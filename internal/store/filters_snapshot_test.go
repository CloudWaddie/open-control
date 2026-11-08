package store

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudwaddie/opencontrol/internal/catalog"
	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// End to end through the snapshot: a custom list, a service block, a service
// allow that beats the list, a service redirect, and the precedence between them.
func TestSnapshotAppliesListsAndServices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "# test list\n0.0.0.0 ads.example\n0.0.0.0 cdn.allowed-app.example\n||tracker.example^")
	}))
	defer srv.Close()

	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SeedDefaults(db); err != nil {
		t.Fatal(err)
	}
	org, _ := DefaultOrgID(db)

	if _, err := AddBlocklistSource(db, org, srv.URL+"/list", "hosts", 0); err != nil {
		t.Fatal(err)
	}
	exitID, err := AddExitNode(db, org, "fra", ExitSpec{Kind: "wireguard", Address: "203.0.113.5:51820", AnswerIP: "10.77.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, catalog.CacheDir(dir))

	for _, f := range []ProfileFilter{
		{Kind: "service", Ref: "blocked_app", State: "block"},
		{Kind: "service", Ref: "allowed_app", State: "allow"},
		{Kind: "service", Ref: "geo_app", State: "redirect", ExitID: exitID},
	} {
		if err := SetProfileFilter(db, org, 1, f); err != nil {
			t.Fatalf("%+v: %v", f, err)
		}
	}

	snap, err := LoadSnapshot(db, dir, policy.FetchMissing)
	if err != nil {
		t.Fatal(err)
	}
	p := snap.DefaultProfile()
	cases := []struct {
		name   string
		action policy.Action
		reason string
	}{
		{"ads.example", policy.ActionBlock, "list:1:ads.example"},
		{"sub.tracker.example", policy.ActionBlock, "list:1:tracker.example"},
		{"www.blocked-app.example", policy.ActionBlock, "service:blocked_app"},
		{"cdn.allowed-app.example", policy.ActionForward, "service:allowed_app:allow"}, // allow beats the list
		{"video.geo-app.example", policy.ActionRedirect, "service:geo_app:redirect"},
		{"ok.example", policy.ActionForward, "default"},
	}
	for _, c := range cases {
		d := snap.Evaluate(p, c.name)
		if d.Action != c.action || d.Reason != c.reason {
			t.Errorf("%s: got %v %q, want %v %q", c.name, d.Action, d.Reason, c.action, c.reason)
		}
	}
	if d := snap.Evaluate(p, "video.geo-app.example"); d.Target != "10.77.0.1" {
		t.Errorf("redirect target %q, want the exit's answer IP", d.Target)
	}

	// The list is now cached: a no-network reload still applies it.
	srv.Close()
	snap, err = LoadSnapshot(db, dir, policy.FetchNone)
	if err != nil {
		t.Fatal(err)
	}
	if d := snap.Evaluate(snap.DefaultProfile(), "ads.example"); d.Action != policy.ActionBlock {
		t.Error("cached list was not applied without network")
	}
}

func writeRegistry(t *testing.T, dir string) {
	t.Helper()
	body := `{"blocked_services":[
		{"id":"blocked_app","name":"Blocked","group":"social_network","icon_svg":"<svg/>","rules":["||blocked-app.example^"]},
		{"id":"allowed_app","name":"Allowed","group":"streaming","icon_svg":"<svg/>","rules":["||allowed-app.example^","/regex/","||x.example^$important"]},
		{"id":"geo_app","name":"Geo","group":"streaming","icon_svg":"<svg/>","rules":["||geo-app.example^"]}
	],"groups":[]}`
	path, _ := filepath.Abs(dir)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy.CachePath(catalog.ServicesURL, path), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	svcs, err := catalog.Services(path, policy.FetchNone)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range svcs {
		if s.ID == "allowed_app" && s.Domains != 1 {
			t.Errorf("regex and modifier rules should be skipped, got %d domains", s.Domains)
		}
	}
}
