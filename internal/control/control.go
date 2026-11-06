// Package control is the REST control plane (PLAN.md M2): profiles, rules,
// endpoints, blocklists, API tokens and the audit log.
//
// Auth: Authorization: Bearer <api token>. Roles (ordered):
//
//	viewer   — read everything
//	operator — viewer + change profiles, rules, endpoints, blocklists
//	admin    — operator + mint tokens, read the audit log
package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

type principal struct {
	name string
	role string
}

type ctxKey struct{}

var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

// Server holds the dependencies of the control API.
type Server struct {
	db     *sql.DB
	reload func() // asks the resolver to recompile its snapshot
}

// Handler returns the API mux. reload is called after every successful write
// so changes take effect without a restart.
func Handler(db *sql.DB, reload func()) http.Handler {
	s := &Server{db: db, reload: reload}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.Handle("GET /api/v1/profiles", s.require("viewer", s.listProfiles))
	mux.Handle("POST /api/v1/profiles", s.require("operator", s.createProfile))
	mux.Handle("GET /api/v1/profiles/{id}/rules", s.require("viewer", s.listRules))
	mux.Handle("POST /api/v1/profiles/{id}/rules", s.require("operator", s.createRule))
	mux.Handle("DELETE /api/v1/rules/{id}", s.require("operator", s.deleteRule))

	mux.Handle("GET /api/v1/endpoints", s.require("viewer", s.listEndpoints))
	mux.Handle("POST /api/v1/endpoints", s.require("operator", s.createEndpoint))
	mux.Handle("DELETE /api/v1/endpoints/{id}", s.require("operator", s.deleteEndpoint))

	mux.Handle("GET /api/v1/blocklists", s.require("viewer", s.listBlocklists))
	mux.Handle("POST /api/v1/blocklists", s.require("operator", s.createBlocklist))
	mux.Handle("DELETE /api/v1/blocklists/{id}", s.require("operator", s.deleteBlocklist))

	mux.Handle("GET /api/v1/audit", s.require("admin", s.listAudit))
	mux.Handle("POST /api/v1/tokens", s.require("admin", s.createToken))

	return mux
}

// require authenticates the bearer token and enforces a minimum role.
func (s *Server) require(minRole string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain, ok := bearer(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		name, role, found, err := store.LookupToken(s.db, plain)
		if err != nil {
			log.Printf("control: token lookup: %v", err)
			writeErr(w, http.StatusInternalServerError, "auth unavailable")
			return
		}
		if !found {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if roleRank[role] < roleRank[minRole] {
			writeErr(w, http.StatusForbidden, "role "+role+" cannot perform this action (needs "+minRole+")")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, principal{name, role})))
	})
}

func actor(r *http.Request) string {
	if p, ok := r.Context().Value(ctxKey{}).(principal); ok {
		return p.name
	}
	return ""
}

// mutated runs after a successful write: audit it and reload the resolver.
func (s *Server) mutated(r *http.Request, action, target string) {
	if err := store.InsertAudit(s.db, actor(r), action, target); err != nil {
		log.Printf("control: audit write failed for %s %s: %v", action, target, err)
	}
	if s.reload != nil {
		go s.reload()
	}
}

// --- profiles ---

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListProfiles(s.db)
	respond(w, out, err)
}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	id, err := store.AddProfile(s.db, in.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutated(r, "profile.create", in.Name)
	writeJSON(w, http.StatusCreated, store.Profile{ID: id, Name: in.Name})
}

// --- rules ---

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := store.ListRules(s.db, id)
	respond(w, out, err)
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	profileID, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Kind    string `json:"kind"`
		Matcher string `json:"matcher"`
		Pattern string `json:"pattern"`
		Answer  string `json:"answer"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, err := store.AddRule(s.db, profileID, in.Kind, in.Matcher, in.Pattern, in.Answer)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutated(r, "rule.create", in.Kind+" "+in.Matcher+" "+in.Pattern)
	writeJSON(w, http.StatusCreated, store.Rule{
		ID: id, ProfileID: profileID, Kind: in.Kind, Matcher: in.Matcher,
		Pattern: in.Pattern, Answer: in.Answer,
	})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.deleteOne(w, r, "rule.delete", "rule", id, store.DeleteRule)
}

// --- endpoints ---

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListEndpoints(s.db)
	respond(w, out, err)
}

// createEndpoint returns the endpoint plus its token. The token is an
// identifier for future DoT/DoH enrollment; it is not a secret.
func (s *Server) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string   `json:"name"`
		ProfileID int64    `json:"profile_id"`
		CIDRs     []string `json:"cidrs"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, token, err := store.AddEndpoint(s.db, in.Name, in.ProfileID, strings.Join(in.CIDRs, ","))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutated(r, "endpoint.create", in.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"endpoint": store.Endpoint{ID: id, ProfileID: in.ProfileID, Name: in.Name, CIDRs: in.CIDRs},
		"token":    token,
	})
}

func (s *Server) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.deleteOne(w, r, "endpoint.delete", "endpoint", id, store.DeleteEndpoint)
}

// --- blocklists ---

func (s *Server) listBlocklists(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListBlocklists(s.db)
	respond(w, out, err)
}

func (s *Server) createBlocklist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL    string `json:"url"`
		Format string `json:"format"`
	}
	if !decode(w, r, &in) {
		return
	}
	if u, err := url.Parse(in.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		writeErr(w, http.StatusBadRequest, "url must be an absolute http(s) URL")
		return
	}
	if in.Format == "" {
		in.Format = "hosts"
	}
	if err := store.AddBlocklistSource(s.db, in.URL, in.Format); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutated(r, "blocklist.create", in.URL)
	writeJSON(w, http.StatusCreated, map[string]string{"url": in.URL, "format": in.Format})
}

func (s *Server) deleteBlocklist(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.deleteOne(w, r, "blocklist.delete", "blocklist", id, store.DeleteBlocklist)
}

// --- admin ---

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := store.ListAudit(s.db, limit)
	respond(w, out, err)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	plain, err := store.CreateToken(s.db, in.Name, in.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutated(r, "token.create", in.Name+" ("+in.Role+")")
	// Shown exactly once: only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name, "role": in.Role, "token": plain})
}

// --- helpers ---

func (s *Server) deleteOne(w http.ResponseWriter, r *http.Request, action, kind string, id int64, del func(*sql.DB, int64) error) {
	if err := del(s.db, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, kind+" not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mutated(r, action, strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return strings.TrimSpace(h[len(p):]), true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "id must be a positive integer")
		return 0, false
	}
	return id, true
}

// decode reads a strict JSON body (unknown fields rejected, 64 KiB max).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		log.Printf("control: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
