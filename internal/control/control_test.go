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
	t        *testing.T
	h        http.Handler
	db       *sql.DB
	reloads  chan struct{}
	admin    string
	operator string
	viewer   string
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
	f.h = Handler(db, func() { f.reloads <- struct{}{} })
	mint := func(name, role string) string {
		tok, err := store.CreateToken(db, name, role)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	f.admin = mint("root", "admin")
	f.operator = mint("ops", "operator")
	f.viewer = mint("dash", "viewer")
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
		{"endpoint without CIDRs", "POST", "/api/v1/endpoints", `{"name":"e","profile_id":1,"cidrs":[]}`, 400},
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
