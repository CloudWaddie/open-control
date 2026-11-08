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
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/cloudwaddie/opencontrol/internal/catalog"
	"github.com/cloudwaddie/opencontrol/internal/egress"
	"github.com/cloudwaddie/opencontrol/internal/policy"
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
	db       *sql.DB
	reload   func()                  // asks the resolver to recompile its snapshot
	checker  *egress.Checker         // probes exit nodes on demand; nil disables /check
	dataDir  string                  // where list and registry downloads are cached
	setup    Setup                   // public addresses shown on the setup page
	snapshot func() *policy.Snapshot // the resolver's live compiled state, for the domain test
}

// Setup describes how devices reach this server. Empty Host means the
// operator has not configured a public name.
type Setup struct {
	Host    string `json:"host"`
	DoHPort int    `json:"doh_port"`
	DoTPort int    `json:"dot_port"`
	DoH     bool   `json:"doh"` // a DoH listener is configured
	DoT     bool   `json:"dot"`
}

// SetSetup records the public addresses for the setup page.
func SetSetup(h http.Handler, s Setup) {
	if srv, ok := h.(*handler); ok {
		srv.s.setup = s
	}
}

// handler keeps a reference to the server behind the middleware.
type handler struct {
	http.Handler
	s *Server
}

// Handler returns the API mux plus the embedded UI. reload is called after
// every committed write so changes take effect without a restart. checker may
// be nil, in which case the on-demand exit check endpoint reports 501.
// SetSnapshotSource hands the control plane the resolver's live snapshot so
// the domain test can replay exactly what the resolver would decide.
func SetSnapshotSource(h http.Handler, f func() *policy.Snapshot) {
	if srv, ok := h.(*handler); ok {
		srv.s.snapshot = f
	}
}

func Handler(db *sql.DB, reload func(), checker *egress.Checker, dataDir string) http.Handler {
	s := &Server{db: db, reload: reload, checker: checker, dataDir: dataDir}
	mux := http.NewServeMux()

	// Liveness + readiness: the database must answer. Unauthenticated, so
	// container health checks and load balancers can use it.
	health := func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
	mux.HandleFunc("GET /api/v1/health", health)
	mux.HandleFunc("GET /healthz", health)
	mux.Handle("GET /api/v1/whoami", s.require("viewer", s.whoami))
	mux.Handle("POST /api/v1/auth/login", http.HandlerFunc(s.login))

	mux.Handle("GET /api/v1/users", s.require("admin", s.listUsers))
	mux.Handle("POST /api/v1/users", s.require("admin", s.createUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.require("admin", s.patchUser))
	mux.Handle("DELETE /api/v1/users/{id}", s.require("admin", s.deleteUser))

	mux.Handle("GET /api/v1/profiles", s.require("viewer", s.listProfiles))
	mux.Handle("POST /api/v1/profiles", s.require("operator", s.createProfile))
	mux.Handle("GET /api/v1/profiles/{id}/rules", s.require("viewer", s.listRules))
	mux.Handle("POST /api/v1/profiles/{id}/rules", s.require("operator", s.createRule))
	mux.Handle("DELETE /api/v1/rules/{id}", s.require("operator", s.deleteRule))
	mux.Handle("GET /api/v1/profiles/{id}/filters", s.require("viewer", s.listFilters))
	mux.Handle("PUT /api/v1/profiles/{id}/filters", s.require("operator", s.setFilter))
	mux.Handle("GET /api/v1/profiles/{id}/options", s.require("viewer", s.getOptions))
	mux.Handle("PUT /api/v1/profiles/{id}/options", s.require("operator", s.setOptions))
	mux.Handle("GET /api/v1/profiles/{id}/test", s.require("viewer", s.testDomain))
	mux.Handle("PUT /api/v1/profiles/{id}/default", s.require("operator", s.setDefaultProfile))
	mux.Handle("PATCH /api/v1/endpoints/{id}", s.require("operator", s.patchEndpoint))
	mux.Handle("GET /api/v1/setup", s.require("viewer", s.getSetup))

	mux.Handle("GET /api/v1/catalog/filters", s.require("viewer", s.catalogFilters))
	mux.Handle("GET /api/v1/catalog/services", s.require("viewer", s.catalogServices))

	mux.Handle("GET /api/v1/endpoints", s.require("viewer", s.listEndpoints))
	mux.Handle("POST /api/v1/endpoints", s.require("operator", s.createEndpoint))
	mux.Handle("DELETE /api/v1/endpoints/{id}", s.require("operator", s.deleteEndpoint))
	mux.Handle("POST /api/v1/endpoints/{id}/rotate", s.require("operator", s.rotateEndpoint))
	mux.Handle("GET /api/v1/endpoints/{id}/token", s.require("viewer", s.endpointToken))

	mux.Handle("GET /api/v1/blocklists", s.require("viewer", s.listBlocklists))
	mux.Handle("POST /api/v1/blocklists", s.require("operator", s.createBlocklist))
	mux.Handle("DELETE /api/v1/blocklists/{id}", s.require("operator", s.deleteBlocklist))

	mux.Handle("GET /api/v1/logs", s.require("viewer", s.listLogs))
	mux.Handle("GET /api/v1/stats", s.require("viewer", s.stats))

	mux.Handle("GET /api/v1/exits", s.require("viewer", s.listExits))
	mux.Handle("POST /api/v1/exits", s.require("operator", s.createExit))
	mux.Handle("DELETE /api/v1/exits/{id}", s.require("operator", s.deleteExit))
	mux.Handle("POST /api/v1/exits/{id}/check", s.require("operator", s.checkExit))
	mux.Handle("PATCH /api/v1/exits/{id}", s.require("operator", s.patchExit))
	mux.Handle("GET /api/v1/exits/{id}/secrets", s.require("operator", s.exitSecrets))

	mux.Handle("GET /api/v1/audit", s.require("admin", s.listAudit))
	mux.Handle("GET /api/v1/tokens", s.require("admin", s.listTokens))
	mux.Handle("POST /api/v1/tokens", s.require("admin", s.createToken))
	mux.Handle("DELETE /api/v1/tokens/{id}", s.require("admin", s.revokeToken))

	// Everything else is the web UI (see internal/web).
	mux.Handle("/", web.Handler())

	return &handler{Handler: securityHeaders(mux), s: s}
}

// securityHeaders applies browser hardening to every response. The UI loads
// only its own scripts; inline style attributes are allowed because the
// component library positions popovers with them.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
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
		var locked *store.LockedError
		if errors.As(err, &locked) {
			writeErr(w, http.StatusLocked, err.Error())
			return
		}
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

// whoami identifies the signed-in principal. Sessions minted by dashboard
// sign-in carry a "login: <user>" token name; the UI sees the user's name.
func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	writeJSON(w, http.StatusOK, map[string]string{
		"name": strings.TrimPrefix(p.name, "login: "),
		"role": p.role,
	})
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
		id, epID, token, err := store.AddProfileWithEndpoint(tx, org, in.Name)
		if err != nil {
			return result{}, err
		}
		// The profile's own encrypted endpoint; its token is shown once.
		return result{target: in.Name, status: http.StatusCreated, body: map[string]any{
			"id": id, "name": in.Name,
			"endpoint": store.Endpoint{ID: epID, ProfileID: id, Name: in.Name, CIDRs: []string{}},
			"token":    token,
		}}, nil
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

// --- filters, services, lists ---

func (s *Server) listFilters(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := store.ListProfileFilters(s.db, principalOf(r).org, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	respond(w, out, err)
}

// setFilter turns a filter category, service or custom list on, off
// (state "off"), or changes its level, state or exit.
func (s *Server) setFilter(w http.ResponseWriter, r *http.Request) {
	profileID, ok := pathID(w, r)
	if !ok {
		return
	}
	var in store.ProfileFilter
	if !decode(w, r, &in) {
		return
	}
	s.mutate(w, r, "filter.set", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.SetProfileFilter(tx, org, profileID, in); err != nil {
			return result{}, err
		}
		target := fmt.Sprintf("profile %d: %s %s → %s", profileID, in.Kind, in.Ref, in.State)
		if in.Level != "" {
			target += " (" + in.Level + ")"
		}
		return result{target: target, status: http.StatusOK, body: in}, nil
	})
}

func (s *Server) catalogFilters(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, catalog.Filters)
}

// catalogServices returns the app registry. The first call after install
// downloads it; if that fails the UI shows the error.
func (s *Server) catalogServices(w http.ResponseWriter, r *http.Request) {
	list, err := catalog.Services(catalog.CacheDir(s.dataDir), policy.FetchMissing)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "services list unavailable: "+err.Error())
		return
	}
	groups := make([]map[string]string, 0, len(catalog.Groups))
	for _, g := range catalog.Groups {
		groups = append(groups, map[string]string{"id": g.ID, "name": g.Name})
	}
	w.Header().Set("Cache-Control", "private, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups, "services": list})
}

// --- profile options ---

// testDomain answers "what would the resolver do with this name?", using the
// same EvaluateQuery the resolver runs and the answer shape the profile's
// options would produce — without forwarding anything.
func (s *Server) testDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s == nil || s.snapshot == nil {
		writeErr(w, http.StatusServiceUnavailable, "resolver state is not available in this build")
		return
	}
	snap := s.snapshot()
	if snap == nil {
		writeErr(w, http.StatusServiceUnavailable, "resolver state is not loaded yet")
		return
	}
	prof := snap.Profile(id)
	if prof == nil {
		writeErr(w, http.StatusNotFound, "profile does not exist in the loaded resolver state")
		return
	}
	qname := strings.TrimSpace(r.URL.Query().Get("qname"))
	if qname == "" {
		writeErr(w, http.StatusBadRequest, "qname is required")
		return
	}
	qname = strings.TrimSuffix(qname, ".")
	if _, valid := dns.IsDomainName(qname); !valid {
		writeErr(w, http.StatusBadRequest, "qname is not a valid domain name")
		return
	}
	qname += "."

	qtypeName := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("qtype")))
	if qtypeName == "" {
		qtypeName = "A"
	}
	qtype, known := dns.StringToType[qtypeName]
	if !known {
		writeErr(w, http.StatusBadRequest, "unknown record type "+qtypeName)
		return
	}

	opts := prof.Options
	d := snap.EvaluateQuery(prof, qname, qtype, time.Now())
	if d.Reason == "paused" {
		d.Action = policy.ActionForward // a paused profile lets everything through
	}
	out := TestResult{
		Qname:  strings.TrimSuffix(qname, "."),
		Qtype:  qtypeName,
		Action: actionName(d.Action),
		Reason: d.Reason,
		Target: d.Target,
	}
	if ex := d.ExitName; ex != "" {
		out.ExitName, out.ExitHealthy = ex, d.ExitHealthy
	}
	switch d.Action {
	case policy.ActionBlock:
		out.Answer, out.AnswerStyle = describeBlock(prof.Options, qtype, qtypeName)
	case policy.ActionRewrite:
		out.Answer = describeRewrite(d.Target, qtype, qtypeName)
	case policy.ActionRedirect:
		out.Answer = describeRedirect(d.Target, prof.Options, qtype, qtypeName)
	default:
		out.Answer = "Normal answer from " + describeUpstream(opts)
		out.AnswerStyle = "forward"
	}
	writeJSON(w, http.StatusOK, out)
}

// actionName is the lowercase action word the query log uses.
func actionName(a policy.Action) string {
	switch a {
	case policy.ActionBlock:
		return "block"
	case policy.ActionRewrite:
		return "rewrite"
	case policy.ActionRedirect:
		return "redirect"
	default:
		return "forward"
	}
}

// TestResult is one domain-test lookup: the decision plus, in Control D
// fashion, the exact reply the client would receive.
type TestResult struct {
	Qname       string `json:"qname"`
	Qtype       string `json:"qtype"`
	Action      string `json:"action"` // block | rewrite | redirect | forward
	Reason      string `json:"reason"` // rule/list/service id that decided it
	Target      string `json:"target,omitempty"`
	ExitName    string `json:"exit_name,omitempty"`
	ExitHealthy bool   `json:"exit_healthy,omitempty"`
	Answer      string `json:"answer"`
	AnswerStyle string `json:"answer_style,omitempty"` // nxdomain | zero | nodata | refused | custom | forward | rewrite | redirect
}

func describeBlock(o policy.Options, qtype uint16, name string) (string, string) {
	switch o.BlockResponse {
	case "refused":
		return "REFUSED", "refused"
	case "nodata":
		return "NODATA — empty answer", "nodata"
	case "zero":
		switch qtype {
		case dns.TypeA:
			return "0.0.0.0", "zero"
		case dns.TypeAAAA:
			return "::", "zero"
		}
		return "NODATA — empty answer (no " + name + " carries 0.0.0.0)", "zero"
	case "custom":
		switch qtype {
		case dns.TypeA:
			if o.BlockIPv4 != "" {
				return o.BlockIPv4, "custom"
			}
		case dns.TypeAAAA:
			if o.BlockIPv6 != "" {
				return o.BlockIPv6, "custom"
			}
		}
		return "NODATA — empty answer (no " + name + " address configured)", "custom"
	default:
		return "NXDOMAIN", "nxdomain"
	}
}

func describeRewrite(target string, qtype uint16, name string) string {
	if ip := net.ParseIP(target); ip != nil {
		ip4 := ip.To4()
		switch {
		case ip4 != nil && qtype == dns.TypeA:
			return ip4.String()
		case ip4 == nil && ip.To16() != nil && qtype == dns.TypeAAAA:
			return ip.String()
		}
		return "NODATA — rewrite target has no " + name + " address"
	}
	if qtype == dns.TypeCNAME || qtype == dns.TypeA || qtype == dns.TypeAAAA {
		return "CNAME " + target
	}
	return "CNAME " + target
}

func describeRedirect(target string, opts policy.Options, qtype uint16, name string) string {
	switch qtype {
	case dns.TypeA:
		return target + " (exit answer)"
	case dns.TypeAAAA:
		if opts.CompatMode {
			return "AAAA under the exit (compat mode synthesis)"
		}
		return "NODATA — no IPv6 answer, so IPv6 clients cannot bypass the exit"
	}
	return "NODATA for " + name
}

func describeUpstream(o policy.Options) string {
	if u, err := o.Upstreams(); err == nil && len(u) > 0 {
		return strings.Join(u, ", ")
	}
	return "this server's upstreams"
}

func (s *Server) getOptions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	o, err := store.GetProfileOptions(s.db, principalOf(r).org, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	respond(w, o, err)
}

// setOptions replaces a profile's options. Unlocking a locked profile needs
// an admin; locking or changing settings needs an operator.
func (s *Server) setOptions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in policy.Options
	if !decode(w, r, &in) {
		return
	}
	p := principalOf(r)
	if cur, err := store.GetProfileOptions(s.db, p.org, id); err == nil && cur.Locked && !in.Locked && roleRank[p.role] < roleRank["admin"] {
		writeErr(w, http.StatusForbidden, "only an admin can unlock a profile")
		return
	}
	s.mutate(w, r, "profile.options", func(tx *sql.Tx, org int64) (result, error) {
		out, err := store.SetProfileOptions(tx, org, id, in)
		if err != nil {
			return result{}, err
		}
		return result{target: fmt.Sprintf("profile %d", id), status: http.StatusOK, body: out}, nil
	})
}

func (s *Server) setDefaultProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "profile.default", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.SetDefaultProfile(tx, org, id); err != nil {
			return result{}, err
		}
		return result{target: fmt.Sprintf("profile %d", id), status: http.StatusNoContent}, nil
	})
}

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.setup)
}

// --- endpoints ---

// patchEndpoint moves an endpoint to another profile.
func (s *Server) patchEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		ProfileID int64 `json:"profile_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mutate(w, r, "endpoint.move", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.SetEndpointProfile(tx, org, id, in.ProfileID); err != nil {
			return result{}, err
		}
		return result{target: fmt.Sprintf("endpoint %d → profile %d", id, in.ProfileID), status: http.StatusOK,
			body: map[string]int64{"id": id, "profile_id": in.ProfileID}}, nil
	})
}

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
		// The new token is also viewable later via the endpoints page.
		return result{
			target: "endpoint " + strconv.FormatInt(id, 10),
			status: http.StatusOK,
			body:   map[string]any{"id": id, "token": token},
		}, nil
	})
}

// endpointToken reveals an endpoint's current DoH/DoT token. Endpoint tokens
// are device identifiers, so they can be viewed again by anyone with dashboard
// access; API token secrets stay one-time.
func (s *Server) endpointToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	token, err := store.GetEndpointToken(s.db, principalOf(r).org, id)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "token": token})
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusConflict, "This endpoint has no viewable token. Rotate it to issue one.")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

// --- blocklists ---

func (s *Server) listBlocklists(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListBlocklists(s.db, principalOf(r).org)
	respond(w, out, err)
}

func (s *Server) createBlocklist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL       string `json:"url"`
		Format    string `json:"format"`
		ProfileID int64  `json:"profile_id"` // enable on this profile only; 0 = every profile
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
		id, err := store.AddBlocklistSource(tx, org, in.URL, in.Format, in.ProfileID)
		if err != nil {
			return result{}, err
		}
		return result{target: in.URL, status: http.StatusCreated, body: store.Blocklist{ID: id, URL: in.URL, Format: in.Format}}, nil
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
	spec, name, err := exitFromBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutate(w, r, "exit.create", func(tx *sql.Tx, org int64) (result, error) {
		id, err := store.AddExitNode(tx, org, name, spec)
		if err != nil {
			return result{}, err
		}
		created, err := store.GetExitNode(tx, org, id)
		if err != nil {
			return result{}, err
		}
		return result{target: name + " (" + spec.Kind + ")", status: http.StatusCreated, body: created}, nil
	})
}

// exitFromBody decodes create/update input, expanding a pasted wg-quick
// config into the WireGuard fields when given.
func exitFromBody(r *http.Request) (store.ExitSpec, string, error) {
	var in struct {
		Name       string `json:"name"`
		Kind       string `json:"kind"`
		Address    string `json:"address"`
		AnswerIP   string `json:"answer_ip"`
		AnswerIPv6 string `json:"answer_ipv6"`
		Username   string `json:"username"`
		Password   string `json:"password"`

		// WireGuard fields, or the full wg-quick config instead of them.
		WGPrivateKey string `json:"wg_private_key"`
		WGPeerKey    string `json:"wg_peer_key"`
		WGPreshared  string `json:"wg_preshared_key"`
		WGAllowedIPs string `json:"wg_allowed_ips"`
		Config       string `json:"config"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return store.ExitSpec{}, "", fmt.Errorf("reading body: %w", err)
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return store.ExitSpec{}, "", fmt.Errorf("invalid JSON body: %w", err)
	}
	if strings.TrimSpace(in.Name) == "" {
		return store.ExitSpec{}, "", fmt.Errorf("name is required")
	}
	spec := store.ExitSpec{
		Kind:        in.Kind,
		Address:     strings.TrimSpace(in.Address),
		AnswerIP:    in.AnswerIP,
		AnswerIP6:   in.AnswerIPv6,
		Username:    in.Username,
		Password:    in.Password,
		WGPrivate:   in.WGPrivateKey,
		WGPeer:      in.WGPeerKey,
		WGPreshared: in.WGPreshared,
		WGAllowed:   in.WGAllowedIPs,
	}
	if cfg := strings.TrimSpace(in.Config); cfg != "" {
		wg, err := store.ParseWGConfig(cfg)
		if err != nil {
			return store.ExitSpec{}, "", fmt.Errorf("config: %w", err)
		}
		wg.AnswerIP, wg.AnswerIP6, wg.Username = spec.AnswerIP, spec.AnswerIP6, spec.Username
		spec = wg
	}
	return spec, strings.TrimSpace(in.Name), nil
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
	ex.Password = "" // not for the client
	writeJSON(w, http.StatusOK, ex)
}

// patchExit updates an exit's kind/address/credentials; fields left empty keep
// their current value.
func (s *Server) patchExit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	spec, _, err := exitFromBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mutate(w, r, "exit.update", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.SetExitNode(tx, org, id, spec); err != nil {
			return result{}, err
		}
		return result{target: "exit " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
	})
}

// exitSecrets returns the stored credentials so the edit dialog can show them.
func (s *Server) exitSecrets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := store.GetExitSecrets(s.db, principalOf(r).org, id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "exit not found")
		return
	}
	respond(w, out, err)
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
		// The plaintext is shown once and cannot be recovered later.
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

// --- users (dashboard accounts) ---

// login verifies a username/password sign-in and returns a session bearer
// token. API tokens authenticate scripts; accounts authenticate people.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := store.AuthenticateUser(s.db, in.Username, in.Password)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if err != nil {
		log.Printf("control: login: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	plain, err := store.CreateSession(s.db, u)
	if err != nil {
		log.Printf("control: session: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": plain, "name": u.Name, "role": u.Role})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	out, err := store.ListUsers(s.db, principalOf(r).org)
	respond(w, out, err)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mutate(w, r, "user.create", func(tx *sql.Tx, org int64) (result, error) {
		u, err := store.CreateUser(tx, org, in.Name, in.Password, in.Role)
		if err != nil {
			return result{}, err
		}
		return result{target: u.Name + " (" + u.Role + ")", status: http.StatusCreated, body: u}, nil
	})
}

// patchUser changes a user's password and/or role (an admin reset).
func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Password *string `json:"password,omitempty"`
		Role     string  `json:"role,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Password == nil && in.Role == "" {
		writeErr(w, http.StatusBadRequest, "nothing to change")
		return
	}
	s.mutate(w, r, "user.update", func(tx *sql.Tx, org int64) (result, error) {
		if in.Password != nil {
			if err := store.SetUserPassword(tx, org, id, *in.Password); err != nil {
				return result{}, err
			}
		}
		if in.Role != "" {
			if err := store.SetUserRole(tx, org, id, in.Role); err != nil {
				return result{}, err
			}
		}
		return result{target: "user " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
	})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, "user.delete", func(tx *sql.Tx, org int64) (result, error) {
		if err := store.DeleteUser(tx, org, id, principalOf(r).name); err != nil {
			return result{}, err
		}
		return result{target: "user " + strconv.FormatInt(id, 10), status: http.StatusNoContent}, nil
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
