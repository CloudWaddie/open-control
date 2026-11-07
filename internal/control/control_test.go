package control

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

type fixture struct {
	t          *testing.T
	h          http.Handler
	db         *sql.DB
	reloads    chan struct{}
	admin      string
	operator   string
	viewer     string
	otherOrg   int64
	otherAdmin string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedDefaults(db); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, db: db, reloads: make(chan struct{}, 32)}
	f.h = Handler(db, func() { f.reloads <- struct{}{} }, nil, t.TempDir())
	org, err := store.DefaultOrgID(db)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(org int64, name, role string) string {
		tok, err := store.CreateToken(db, org, name, role)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	f.admin = mint(org, "root", "admin")
	f.operator = mint(org, "ops", "operator")
	f.viewer = mint(org, "dash", "viewer")

	// A second tenant with its own admin, for isolation tests.
	other, err := store.CreateOrg(db, "other-tenant")
	if err != nil {
		t.Fatal(err)
	}
	f.otherOrg = other
	f.otherAdmin = mint(other, "tenant-root", "admin")
	return f
}

// do sends a request and returns status and decoded body (if any).
func (f *fixture) do(method, path, token, body string) (int, map[string]any, []byte) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m, rec.Body.Bytes()
}

func (f *fixture) waitReload() {
	f.t.Helper()
	select {
	case <-f.reloads:
	case <-time.After(2 * time.Second):
		f.t.Fatal("expected a snapshot reload after a write")
	}
}

func TestAuthRequired(t *testing.T) {
	f := newFixture(t)
	if code, _, _ := f.do("GET", "/api/v1/profiles", "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", code)
	}
	if code, _, _ := f.do("GET", "/api/v1/profiles", "oc_nope", ""); code != http.StatusUnauthorized {
		t.Errorf("bad token: got %d, want 401", code)
	}
	if code, _, _ := f.do("GET", "/api/v1/health", "", ""); code != http.StatusOK {
		t.Errorf("health should be open: got %d", code)
	}
}

func TestRolesEnforced(t *testing.T) {
	f := newFixture(t)
	rule := `{"kind":"block","matcher":"domain","pattern":"ads.example"}`

	if code, _, _ := f.do("GET", "/api/v1/profiles", f.viewer, ""); code != http.StatusOK {
		t.Errorf("viewer read: got %d", code)
	}
	if code, _, _ := f.do("POST", "/api/v1/profiles/1/rules", f.viewer, rule); code != http.StatusForbidden {
		t.Errorf("viewer write: got %d, want 403", code)
	}
	if code, _, _ := f.do("GET", "/api/v1/audit", f.operator, ""); code != http.StatusForbidden {
		t.Errorf("operator audit read: got %d, want 403", code)
	}
	if code, _, _ := f.do("POST", "/api/v1/tokens", f.operator, `{"name":"x","role":"viewer"}`); code != http.StatusForbidden {
		t.Errorf("operator minting tokens: got %d, want 403", code)
	}
}

func TestRuleLifecycleAndAudit(t *testing.T) {
	f := newFixture(t)

	code, body, _ := f.do("POST", "/api/v1/profiles/1/rules", f.operator,
		`{"kind":"block","matcher":"wildcard","pattern":"evil.example"}`)
	if code != http.StatusCreated {
		t.Fatalf("create rule: %d %v", code, body)
	}
	f.waitReload()
	id := body["id"].(float64)

	if code, _, raw := f.do("GET", "/api/v1/profiles/1/rules", f.viewer, ""); code != 200 || !strings.Contains(string(raw), "evil.example") {
		t.Fatalf("list rules: %d %s", code, raw)
	}

	_, _, raw := f.do("GET", "/api/v1/audit", f.admin, "")
	if !strings.Contains(string(raw), `"rule.create"`) || !strings.Contains(string(raw), `"ops"`) {
		t.Fatalf("audit should record rule.create by ops, got %s", raw)
	}

	if code, _, _ := f.do("DELETE", "/api/v1/rules/"+itoa(int64(id)), f.operator, ""); code != http.StatusNoContent {
		t.Fatalf("delete rule: %d", code)
	}
	f.waitReload()
	if code, _, _ := f.do("DELETE", "/api/v1/rules/"+itoa(int64(id)), f.operator, ""); code != http.StatusNotFound {
		t.Errorf("delete again: got %d, want 404", code)
	}
}

func TestValidation(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"bad rule kind", "POST", "/api/v1/profiles/1/rules", `{"kind":"nuke","matcher":"domain","pattern":"x.example"}`, 400},
		{"rewrite without answer", "POST", "/api/v1/profiles/1/rules", `{"kind":"rewrite","matcher":"domain","pattern":"x.example"}`, 400},
		{"unknown JSON field", "POST", "/api/v1/profiles/1/rules", `{"kind":"block","matcher":"domain","pattern":"x.example","bogus":1}`, 400},
		{"bad profile id", "POST", "/api/v1/profiles/abc/rules", `{}`, 400},
		{"endpoint without CIDRs is encrypted-only", "POST", "/api/v1/endpoints", `{"name":"e","profile_id":1,"cidrs":[]}`, 201},
		{"endpoint bad CIDR", "POST", "/api/v1/endpoints", `{"name":"e","profile_id":1,"cidrs":["not-a-cidr"]}`, 400},
		{"blocklist not a URL", "POST", "/api/v1/blocklists", `{"url":"file:///etc/passwd"}`, 400},
		{"token unknown role", "POST", "/api/v1/tokens", `{"name":"t","role":"god"}`, 400},
	}
	for _, c := range cases {
		token := f.operator
		if strings.Contains(c.path, "tokens") {
			token = f.admin
		}
		if code, _, raw := f.do(c.method, c.path, token, c.body); code != c.want {
			t.Errorf("%s: got %d (%s), want %d", c.name, code, raw, c.want)
		}
	}
}

func TestEndpointCreateReturnsToken(t *testing.T) {
	f := newFixture(t)
	code, body, raw := f.do("POST", "/api/v1/endpoints", f.operator,
		`{"name":"kids","profile_id":1,"cidrs":["10.9.0.0/16"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create endpoint: %d %s", code, raw)
	}
	if body["token"] == nil || body["token"] == "" {
		t.Fatalf("expected endpoint token in response: %s", raw)
	}
	f.waitReload()
	_, _, list := f.do("GET", "/api/v1/endpoints", f.viewer, "")
	if !strings.Contains(string(list), "10.9.0.0/16") {
		t.Errorf("endpoint not listed: %s", list)
	}
}

// A change must not survive without its audit row: if the audit insert fails,
// the rule write rolls back too.
func TestWriteRollsBackWhenAuditFails(t *testing.T) {
	f := newFixture(t)
	if _, err := f.db.Exec(`DROP TABLE audit_logs`); err != nil {
		t.Fatal(err)
	}
	code, _, raw := f.do("POST", "/api/v1/profiles/1/rules", f.operator,
		`{"kind":"block","matcher":"domain","pattern":"ghost.example"}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when audit fails, got %d (%s)", code, raw)
	}
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM profile_rules WHERE pattern = 'ghost.example'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("rule was committed without its audit row")
	}
}

func TestTokenRevocation(t *testing.T) {
	f := newFixture(t)
	// A viewer token can be revoked by an admin; then it is refused.
	code, _, raw := f.do("GET", "/api/v1/tokens", f.admin, "")
	if code != 200 {
		t.Fatalf("list tokens: %d", code)
	}
	if strings.Contains(string(raw), "token_hash") {
		t.Error("token listing must not expose hashes")
	}
	var viewerID int64
	if err := f.db.QueryRow(`SELECT id FROM api_tokens WHERE name = 'dash'`).Scan(&viewerID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.do("DELETE", "/api/v1/tokens/"+itoa(viewerID), f.admin, ""); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _ := f.do("GET", "/api/v1/profiles", f.viewer, ""); code != http.StatusUnauthorized {
		t.Errorf("revoked token still accepted: %d", code)
	}
}

func TestCannotRevokeOwnToken(t *testing.T) {
	f := newFixture(t)
	var adminID int64
	if err := f.db.QueryRow(`SELECT id FROM api_tokens WHERE name = 'root'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.do("DELETE", "/api/v1/tokens/"+itoa(adminID), f.admin, ""); code != http.StatusConflict {
		t.Errorf("self-revoke: got %d, want 409", code)
	}
}

// Tenant isolation: a token from org B must not read, reference, change or
// revoke anything in org A. Refusals look like "not found", never "forbidden",
// so one tenant cannot probe another's ids.
func TestTenantIsolation(t *testing.T) {
	f := newFixture(t)
	// Org A (default) creates a profile rule; capture its id.
	code, body, raw := f.do("POST", "/api/v1/profiles/1/rules", f.operator,
		`{"kind":"block","matcher":"domain","pattern":"a-secret.example"}`)
	if code != http.StatusCreated {
		t.Fatalf("setup: %d %s", code, raw)
	}
	ruleID := itoa(int64(body["id"].(float64)))
	f.waitReload()

	other := f.otherAdmin

	// Reads: B sees none of A's profiles, rules, endpoints, tokens or audit.
	if _, _, raw := f.do("GET", "/api/v1/profiles", other, ""); strings.Contains(string(raw), `"default"`) {
		t.Errorf("tenant B lists A's profiles: %s", raw)
	}
	if _, _, raw := f.do("GET", "/api/v1/profiles/1/rules", other, ""); strings.Contains(string(raw), "a-secret") {
		t.Errorf("tenant B reads A's rules: %s", raw)
	}
	if _, _, raw := f.do("GET", "/api/v1/audit", other, ""); strings.Contains(string(raw), "rule.create") {
		t.Errorf("tenant B reads A's audit log: %s", raw)
	}
	if _, _, raw := f.do("GET", "/api/v1/tokens", other, ""); strings.Contains(string(raw), `"root"`) {
		t.Errorf("tenant B lists A's tokens: %s", raw)
	}

	// Writes that name A's objects are refused as not found.
	if code, _, _ := f.do("POST", "/api/v1/profiles/1/rules", other,
		`{"kind":"allow","matcher":"domain","pattern":"x.example"}`); code != http.StatusNotFound {
		t.Errorf("B adds a rule to A's profile: %d, want 404", code)
	}
	if code, _, _ := f.do("DELETE", "/api/v1/rules/"+ruleID, other, ""); code != http.StatusNotFound {
		t.Errorf("B deletes A's rule: %d, want 404", code)
	}
	if code, _, _ := f.do("POST", "/api/v1/endpoints", other,
		`{"name":"sneaky","profile_id":1,"cidrs":["0.0.0.0/0"]}`); code != http.StatusNotFound {
		t.Errorf("B binds an endpoint to A's profile: %d, want 404", code)
	}
	if code, _, _ := f.do("DELETE", "/api/v1/tokens/"+itoa(f.tokenID(t, "ops")), other, ""); code != http.StatusNotFound {
		t.Errorf("B revokes A's token: %d, want 404", code)
	}

	// A's rule survived and A's operator still works.
	if code, _, _ := f.do("GET", "/api/v1/profiles/1/rules", f.operator, ""); code != 200 {
		t.Errorf("A's operator broken by B's attempts: %d", code)
	}
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM profile_rules WHERE pattern = 'a-secret.example'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("A's rule altered by tenant B: count=%d err=%v", n, err)
	}

	// B's own objects work normally.
	if code, _, raw := f.do("POST", "/api/v1/profiles", other, `{"name":"tenant-b-profile"}`); code != http.StatusCreated {
		t.Fatalf("B creates its own profile: %d %s", code, raw)
	}
	if code, _, _ := f.do("GET", "/api/v1/profiles", other, ""); code != 200 {
		t.Errorf("B lists its own profiles: %d", code)
	}
}

// tokenID looks up a token's id by name.
func (f *fixture) tokenID(t *testing.T, name string) int64 {
	t.Helper()
	var id int64
	if err := f.db.QueryRow(`SELECT id FROM api_tokens WHERE name = ?`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRotateEndpointToken(t *testing.T) {
	f := newFixture(t)
	code, body, raw := f.do("POST", "/api/v1/endpoints", f.operator,
		`{"name":"phone","profile_id":1,"cidrs":["10.0.0.0/8"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	id := itoa(int64(body["endpoint"].(map[string]any)["id"].(float64)))
	old := body["token"].(string)

	if code, _, _ := f.do("POST", "/api/v1/endpoints/"+id+"/rotate", f.viewer, ""); code != http.StatusForbidden {
		t.Errorf("viewer rotate: %d, want 403", code)
	}
	if code, _, _ := f.do("POST", "/api/v1/endpoints/"+id+"/rotate", f.otherAdmin, ""); code != http.StatusNotFound {
		t.Errorf("other tenant rotate: %d, want 404", code)
	}
	code, rot, raw := f.do("POST", "/api/v1/endpoints/"+id+"/rotate", f.operator, "")
	if code != http.StatusOK || rot["token"] == nil || rot["token"] == old {
		t.Fatalf("rotate: %d %s", code, raw)
	}
	if strings.Contains(string(raw), "token_hash") {
		t.Error("rotation response exposes the stored hash")
	}
}

// Query log and stats are tenant-scoped and validate their parameters.
func TestLogsAndStatsAreTenantScoped(t *testing.T) {
	f := newFixture(t)
	defOrg, _ := store.DefaultOrgID(f.db)
	now := time.Now().Unix()
	if err := store.InsertQueryLogs(f.db, []store.QueryLog{
		{Org: defOrg, Client: "10.0.0.1", QName: "default-only.example", QType: "A", Action: "block", Ts: now},
		{Org: f.otherOrg, Client: "192.0.2.1", QName: "other-only.example", QType: "A", Action: "block", Ts: now},
	}); err != nil {
		t.Fatal(err)
	}

	_, _, raw := f.do("GET", "/api/v1/logs", f.viewer, "")
	if !strings.Contains(string(raw), "default-only.example") || strings.Contains(string(raw), "other-only.example") {
		t.Errorf("default org logs wrong: %s", raw)
	}
	_, _, raw = f.do("GET", "/api/v1/logs", f.otherAdmin, "")
	if !strings.Contains(string(raw), "other-only.example") || strings.Contains(string(raw), "default-only.example") {
		t.Errorf("tenant B logs wrong: %s", raw)
	}

	code, st, raw := f.do("GET", "/api/v1/stats?window=1h", f.viewer, "")
	if code != 200 || st["total"].(float64) != 1 || st["blocked"].(float64) != 1 {
		t.Errorf("default org stats: %d %s", code, raw)
	}
	if _, _, raw := f.do("GET", "/api/v1/stats", f.otherAdmin, ""); !strings.Contains(string(raw), `"total":1`) {
		t.Errorf("tenant B stats: %s", raw)
	}

	for _, p := range []string{"/api/v1/logs?action=nuke", "/api/v1/logs?limit=0", "/api/v1/logs?after=-1", "/api/v1/stats?window=5y"} {
		if code, _, _ := f.do("GET", p, f.viewer, ""); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", p, code)
		}
	}
	if code, _, _ := f.do("GET", "/api/v1/logs", "", ""); code != http.StatusUnauthorized {
		t.Errorf("logs without token: %d, want 401", code)
	}
}

// Exit nodes: tenant-scoped, usable in redirect rules only within their org,
// and deleting one removes the rules that pointed at it.
func TestExitsAreTenantScoped(t *testing.T) {
	f := newFixture(t)
	code, body, raw := f.do("POST", "/api/v1/exits", f.operator,
		`{"name":"vps","kind":"socks5","address":"vps.example:1080","answer_ip":"10.77.0.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("create exit: %d %s", code, raw)
	}
	exitID := body["id"].(float64)

	// Visible to its own org, invisible to the other.
	if _, _, raw := f.do("GET", "/api/v1/exits", f.viewer, ""); !strings.Contains(string(raw), "vps.example:1080") {
		t.Errorf("own org cannot list its exit: %s", raw)
	}
	if _, _, raw := f.do("GET", "/api/v1/exits", f.otherAdmin, ""); strings.Contains(string(raw), "vps.example") {
		t.Errorf("other tenant lists the exit: %s", raw)
	}

	// The other tenant cannot route its profile through this exit.
	code, _, raw = f.do("POST", "/api/v1/profiles/1/rules", f.otherAdmin,
		`{"kind":"redirect","matcher":"domain","pattern":"x.example","exit_id":`+itoa(int64(exitID))+`}`)
	if code != http.StatusNotFound {
		t.Errorf("cross-org redirect rule: %d %s, want 404", code, raw)
	}

	// Same org: a redirect rule works and is listed with its exit id.
	if code, _, raw := f.do("POST", "/api/v1/profiles/1/rules", f.operator,
		`{"kind":"redirect","matcher":"wildcard","pattern":"netflix.example","exit_id":`+itoa(int64(exitID))+`}`); code != http.StatusCreated {
		t.Fatalf("own redirect rule: %d %s", code, raw)
	}

	// Deleting the exit removes its redirect rule and says how many.
	code, body, raw = f.do("DELETE", "/api/v1/exits/"+itoa(int64(exitID)), f.operator, "")
	if code != http.StatusOK || body["removed_rules"].(float64) != 1 {
		t.Errorf("delete exit: %d %s, want 200 with removed_rules=1", code, raw)
	}
	if _, _, raw := f.do("GET", "/api/v1/profiles/1/rules", f.operator, ""); strings.Contains(string(raw), "netflix.example") {
		t.Error("redirect rule survived its exit's deletion")
	}
}

func TestExitValidationAndCheck(t *testing.T) {
	f := newFixture(t)
	if code, _, _ := f.do("POST", "/api/v1/exits", f.operator,
		`{"name":"x","kind":"socks5","address":"no-port","answer_ip":"10.77.0.1"}`); code != http.StatusBadRequest {
		t.Errorf("bad address: %d, want 400", code)
	}
	if code, _, _ := f.do("POST", "/api/v1/exits", f.viewer, `{}`); code != http.StatusForbidden {
		t.Errorf("viewer creating exit: %d, want 403", code)
	}
	// Without a checker the on-demand check says so, rather than pretending.
	code, body, _ := f.do("POST", "/api/v1/exits", f.operator,
		`{"name":"vps","kind":"socks5","address":"vps.example:1080","answer_ip":"10.77.0.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("setup exit: %d", code)
	}
	id := itoa(int64(body["id"].(float64)))
	if code, _, _ := f.do("POST", "/api/v1/exits/"+id+"/check", f.operator, ""); code != http.StatusNotImplemented {
		t.Errorf("check with no checker: %d, want 501", code)
	}
}

func TestWhoami(t *testing.T) {
	f := newFixture(t)
	code, body, _ := f.do("GET", "/api/v1/whoami", f.operator, "")
	if code != 200 || body["name"] != "ops" || body["role"] != "operator" {
		t.Fatalf("whoami: %d %v", code, body)
	}
	if code, _, _ := f.do("GET", "/api/v1/whoami", "", ""); code != 401 {
		t.Errorf("whoami without token: %d, want 401", code)
	}
}

func TestUIServedFromSameMux(t *testing.T) {
	f := newFixture(t)
	code, _, raw := f.do("GET", "/audit", "", "")
	if code != 200 || !strings.Contains(string(raw), `id="root"`) {
		t.Errorf("UI route: %d", code)
	}
}

func TestMintedTokenWorks(t *testing.T) {
	f := newFixture(t)
	code, body, raw := f.do("POST", "/api/v1/tokens", f.admin, `{"name":"ci","role":"viewer"}`)
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, raw)
	}
	plain := body["token"].(string)
	if code, _, _ := f.do("GET", "/api/v1/profiles", plain, ""); code != 200 {
		t.Errorf("minted viewer token rejected: %d", code)
	}
	// Storage must hold the hash, never the plaintext: the row is found by the
	// hash of the token, and the plaintext appears nowhere in the table.
	var stored string
	if err := f.db.QueryRow(`SELECT token_hash FROM api_tokens WHERE name = 'ci'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != store.HashToken(plain) {
		t.Errorf("stored value %q is not the token's hash", stored)
	}
	if strings.Contains(stored, plain) {
		t.Error("plaintext token leaked into storage")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
