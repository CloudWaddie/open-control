// Package control is the REST control plane (PLAN.md M2): profiles, rules,
// endpoints, blocklists, API tokens and the audit log.
//
// Auth: Authorization: Bearer <api token>. A token belongs to one org, and
// every request is scoped to that org. Roles (ordered):
//
//	viewer   — read everything in the org
//	operator — viewer + change profiles, rules, endpoints, blocklists
//	admin    — operator + mint and revoke tokens, read the audit log
//
// Every write runs in one transaction together with its audit row, so a change
// and its record commit or roll back as a unit. The resolver reloads after commit.
package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/egress"
	"github.com/cloudwaddie/opencontrol/internal/store"
	"github.com/cloudwaddie/opencontrol/internal/web"
)

type principal struct {
	id   int64
	org  int64
	name string
	role string
}

type ctxKey struct{}

var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

// Server holds the dependencies of the control API.
type Server struct {
	db      *sql.DB
	reload  func()           // asks the resolver to recompile its snapshot
	checker *egress.Checker // probes exit nodes on demand; nil disables /check
}

// Handler returns the API mux plus the embedded UI. reload is called after
// every committed write so changes take effect without a restart. checker may
// be nil, in which case the on-demand exit check endpoint reports 501.
func Handler(db *sql.DB, reload func(), checker *egress.Checker) http.Handler {
	s := &Server{db: db, reload: reload, checker: checker}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /api/v1/whoami", s.require("viewer", s.whoami))

	mux.Handle("GET /api/v1/profiles", s.require("viewer", s.listProfiles))
	mux.Handle("POST /api/v1/profiles", s.require("operator", s.createProfile))
	mux.Handle("GET /api/v1/profiles/{id}/rules", s.require("viewer", s.listRules))
	mux.Handle("POST /api/v1/profiles/{id}/rules", s.require("operator", s.createRule))
	mux.Handle("DELETE /api/v1/rules/{id}", s.require("operator", s.deleteRule))

	mux.Handle("GET /api/v1/endpoints", s.require("viewer", s.listEndpoints))
	mux.Handle("POST /api/v1/endpoints", s.require("operator", s.createEndpoint))
	mux.Handle("DELETE /api/v1/endpoints/{id}", s.require("operator", s.deleteEndpoint))
	mux.Handle("POST /api/v1/endpoints/{id}/rotate", s.require("operator", s.rotateEndpoint))

	mux.Handle("GET /api/v1/blocklists", s.require("viewer", s.listBlocklists))
	mux.Handle("POST /api/v1/blocklists", s.require("operator", s.createBlocklist))
	mux.Handle("DELETE /api/v1/blocklists/{id}", s.require("operator", s.deleteBlocklist))

	mux.Handle("GET /api/v1/logs", s.require("viewer", s.listLogs))
	mux.Handle("GET /api/v1/stats", s.require("viewer", s.stats))

	mux.Handle("GET /api/v1/exits", s.require("viewer", s.listExits))
	mux.Handle("POST /api/v1/exits", s.require("operator", s.createExit))
	mux.Handle("DELETE /api/v1/exits/{id}", s.require("operator", s.deleteExit))
	mux.Handle("POST /api/v1/exits/{id}/check", s.require("operator", s.checkExit))

	mux.Handle("GET /api/v1/audit", s.require("admin", s.listAudit))
	mux.Handle("GET /api/v1/tokens", s.require("admin", s.listTokens))
	mux.Handle("POST /api/v1/tokens", s.require("admin", s.createToken))
	mux.Handle("DELETE /api/v1/tokens/{id}", s.require("admin", s.revokeToken))

	// Everything else is the web UI (see internal/web).
	mux.Handle("/", web.Handler())

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
		t, found, err := store.LookupToken(s.db, plain)
		if err != nil {
			log.Printf("control: token lookup: %v", err)
			writeErr(w, http.StatusInternalServerError, "auth unavailable")
			return
		}
		if !found {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if roleRank[t.Role] < roleRank[minRole] {
			writeErr(w, http.StatusForbidden, "role "+t.Role+" cannot perform this action (needs "+minRole+")")
			return
		}
		p := principal{id: t.ID, org: t.OrgID, name: t.Name, role: t.Role}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func principalOf(r *http.Request) principal {
	p, _ := r.Context().Value(ctxKey{}).(principal)
	return p
}

// result is what a successful mutation returns to the client.
type result struct {
	target string // audit target
	status int
	body   any // nil for 204
}

// mutate runs fn inside a transaction, records the audit row in the same
// transaction, commits, and only then reloads the resolver. Errors from fn map
// to 404 when the row is missing (or belongs to another org) and 400 otherwise.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, action string, fn func(tx *sql.Tx, org int64) (result, error)) {
	p := principalOf(r)
	tx, err := s.db.Begin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	res, err := fn(tx, p.org)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := store.InsertAudit(tx, p.org, p.name, action, res.target); err != nil {
		log.Printf("control: audit insert failed, change rolled back: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("control: commit failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if s.reload != nil {
		go s.reload()
	}
	if res.body == nil {
		w.WriteHeader(res.status)
		return
	}
	writeJSON(w, res.status, res.body)
}

// --- identity ---

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	writeJSON(w, http.StatusOK, map[string]string{"name": p.name, "role": p.role})
}

// --- profiles ---

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListProfiles(s.db, principalOf(r).org)
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
	s.mutate(w, r, "profile.create", func(tx *sql.Tx, org int64) (result, error) {
		id, err := store.AddProfile(tx, org, in.Name)
		if err != nil {
			return result{}, err
		}
		return result{target: in.Name, status: http.StatusCreated, body: store.Profile{ID: id, Name: in.Name}}, nil
	})
}

// --- rules ---

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := store.ListRules(s.db, principalOf(r).org, id)
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
		ExitID  int64  `json:"exit_id"` // redirect rules: the exit to send matches to
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Kind == "redirect" {
		in.Answer = strconv.FormatInt(in.ExitID, 10)
	}
	s.mutate(w, r, "rule.create", func(tx *sql.Tx, org int64) (result, error) {
		id, err := store.AddRule(tx, org, profileID, in.Kind, in.Matcher, in.Pattern, in.Answer)
		if err != nil {
			return result{}, err
		}
		return result{
			target: in.Kind + " " + in.Matcher + " " + in.Pattern,
			status: http.StatusCreated,
			body: store.Rule{
				ID: id, ProfileID: profileID, Kind: in.Kind, Matcher: in.Matcher,
				Pattern: in.Pattern, Answer: in.Answer,
			},
		}, nil
	})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "rule.delete", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.DeleteRule(tx, org, id); err != nil {
			return result{}, err
		}
		return result{target: "rule " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
	})
}

// --- endpoints ---

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListEndpoints(s.db, principalOf(r).org)
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
	s.mutate(w, r, "endpoint.create", func(tx *sql.Tx, org int64) (result, error) {
		id, token, err := store.AddEndpoint(tx, org, in.Name, in.ProfileID, strings.Join(in.CIDRs, ","))
		if err != nil {
			return result{}, err
		}
		return result{
			target: in.Name,
			status: http.StatusCreated,
			body: map[string]any{
				"endpoint": store.Endpoint{ID: id, ProfileID: in.ProfileID, Name: in.Name, CIDRs: in.CIDRs},
				"token":    token,
			},
		}, nil
	})
}

func (s *Server) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "endpoint.delete", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.DeleteEndpoint(tx, org, id); err != nil {
			return result{}, err
		}
		return result{target: "endpoint " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
	})
}

// rotateEndpoint issues a new endpoint token. The old one stops working at once.
func (s *Server) rotateEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "endpoint.rotate", func(tx *sql.Tx, org int64) (result, error) {
		token, err := store.RotateEndpointToken(tx, org, id)
		if err != nil {
			return result{}, err
		}
		// Shown exactly once: only its hash is stored.
		return result{
			target: "endpoint " + strconv.FormatInt(id, 10),
			status: http.StatusOK,
			body:   map[string]any{"id": id, "token": token},
		}, nil
	})
}

// --- blocklists ---

func (s *Server) listBlocklists(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListBlocklists(s.db, principalOf(r).org)
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
	s.mutate(w, r, "blocklist.create", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.AddBlocklistSource(tx, org, in.URL, in.Format); err != nil {
			return result{}, err
		}
		return result{target: in.URL, status: http.StatusCreated, body: map[string]string{"url": in.URL, "format": in.Format}}, nil
	})
}

func (s *Server) deleteBlocklist(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "blocklist.delete", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.DeleteBlocklist(tx, org, id); err != nil {
			return result{}, err
		}
		return result{target: "blocklist " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
	})
}

// --- exit nodes (M5) ---

func (s *Server) listExits(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListExitNodes(s.db, principalOf(r).org)
	respond(w, out, err)
}

func (s *Server) createExit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Address  string `json:"address"`
		AnswerIP string `json:"answer_ip"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mutate(w, r, "exit.create", func(tx *sql.Tx, org int64) (result, error) {
		id, err := store.AddExitNode(tx, org, in.Name, in.Kind, in.Address, in.AnswerIP)
		if err != nil {
			return result{}, err
		}
		return result{
			target: in.Name + " (" + in.Kind + ")",
			status: http.StatusCreated,
			body: store.ExitNode{ID: id, Name: in.Name, Kind: in.Kind, Address: in.Address,
				AnswerIP: in.AnswerIP, Health: "unknown"},
		}, nil
	})
}

// deleteExit also removes the redirect rules that pointed at the exit, and
// reports how many were removed.
func (s *Server) deleteExit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "exit.delete", func(tx *sql.Tx, org int64) (result, error) {
		removed, err := store.DeleteExitNode(tx, org, id)
		if err != nil {
			return result{}, err
		}
		return result{
			target: fmt.Sprintf("exit %d (%d redirect rules removed)", id, removed),
			status: http.StatusOK,
			body:   map[string]any{"deleted": id, "removed_rules": removed},
		}, nil
	})
}

// checkExit probes an exit right now instead of waiting for the next round.
func (s *Server) checkExit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.checker == nil {
		writeErr(w, http.StatusNotImplemented, "exit checks are not enabled")
		return
	}
	org := principalOf(r).org
	ex, err := store.GetExitNode(s.db, org, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "exit not found")
		return
	}
	health, err := s.checker.CheckRecord(store.ExitRecord{ExitNode: ex, Org: org})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ex.Health = health
	writeJSON(w, http.StatusOK, ex)
}

// --- query log (M4) ---

var logActions = map[string]bool{"block": true, "forward": true, "rewrite": true, "redirect": true, "refused": true, "error": true}

// listLogs returns the org's newest decisions. ?after=<id> returns only newer
// rows, which is how the UI tails the log.
func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.LogFilter
	if v := q.Get("after"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 0 {
			writeErr(w, http.StatusBadRequest, "after must be a non-negative integer")
			return
		}
		f.AfterID = id
	}
	if v := q.Get("action"); v != "" {
		if !logActions[v] {
			writeErr(w, http.StatusBadRequest, "action must be one of block|forward|rewrite|refused|error")
			return
		}
		f.Action = v
	}
	f.Client = q.Get("client")
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}
	out, err := store.ListQueryLogs(s.db, principalOf(r).org, f)
	respond(w, out, err)
}

var statsWindows = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("window")
	if name == "" {
		name = "1h"
	}
	window, ok := statsWindows[name]
	if !ok {
		writeErr(w, http.StatusBadRequest, "window must be 1h, 24h or 7d")
		return
	}
	out, err := store.QueryStats(s.db, principalOf(r).org, window, time.Now())
	if err == nil {
		out.Window = name
	}
	respond(w, out, err)
}

// --- admin ---

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := store.ListAudit(s.db, principalOf(r).org, limit)
	respond(w, out, err)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListTokens(s.db, principalOf(r).org)
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
	s.mutate(w, r, "token.create", func(tx *sql.Tx, org int64) (result, error) {
		plain, err := store.CreateToken(tx, org, in.Name, in.Role)
		if err != nil {
			return result{}, err
		}
		// Shown exactly once: only its hash is stored.
		return result{
			target: in.Name + " (" + in.Role + ")",
			status: http.StatusCreated,
			body:   map[string]string{"name": in.Name, "role": in.Role, "token": plain},
		}, nil
	})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if principalOf(r).id == id {
		// Prevents an admin locking themselves out in the middle of a session.
		writeErr(w, http.StatusConflict, "cannot revoke the token you are using")
		return
	}
	s.mutate(w, r, "token.revoke", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.RevokeToken(tx, org, id); err != nil {
			return result{}, err
		}
		return result{target: "token " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
	})
}

// --- helpers ---

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
