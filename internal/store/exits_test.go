package store

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

func exitsDB(t *testing.T) (*sql.DB, int64, int64) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "exits.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SeedDefaults(db); err != nil {
		t.Fatal(err)
	}
	a, _ := DefaultOrgID(db)
	b, err := CreateOrg(db, "other")
	if err != nil {
		t.Fatal(err)
	}
	return db, a, b
}

func TestExitValidation(t *testing.T) {
	db, org, _ := exitsDB(t)
	bad := []struct{ kind, addr, ans string }{
		{"openvpn", "vpn.example:1194", "10.77.0.1"},
		{"socks5", "no-port", "10.77.0.1"},
		{"socks5", "vps.example:1080", "2001:db8::1"},
		{"socks5", "vps.example:1080", "not-an-ip"},
	}
	for _, b := range bad {
		if _, err := AddExitNode(db, org, "x", b.kind, b.addr, b.ans); err == nil {
			t.Errorf("accepted bad exit %+v", b)
		}
	}
	if _, err := AddExitNode(db, org, "vps", "socks5", "vps.example:1080", "10.77.0.1"); err != nil {
		t.Errorf("valid exit refused: %v", err)
	}
}

func TestRedirectRulesStayInTheirOrg(t *testing.T) {
	db, orgA, orgB := exitsDB(t)
	exitB, err := AddExitNode(db, orgB, "b-vps", "socks5", "b.example:1080", "10.88.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Org A's profile cannot point at org B's exit.
	if _, err := AddRule(db, orgA, 1, "redirect", "wildcard", "netflix.test", strconv.FormatInt(exitB, 10)); err == nil {
		t.Fatal("org A redirected to org B's exit")
	}
	exitA, _ := AddExitNode(db, orgA, "a-vps", "socks5", "a.example:1080", "10.77.0.1")
	if _, err := AddRule(db, orgA, 1, "redirect", "wildcard", "netflix.test", strconv.FormatInt(exitA, 10)); err != nil {
		t.Fatalf("own exit refused: %v", err)
	}
}

func TestRedirectReachesSnapshotAndHealthFollows(t *testing.T) {
	db, orgA, _ := exitsDB(t)
	exitA, _ := AddExitNode(db, orgA, "a-vps", "socks5", "a.example:1080", "10.77.0.1")
	if _, err := AddRule(db, orgA, 1, "redirect", "wildcard", "netflix.test", strconv.FormatInt(exitA, 10)); err != nil {
		t.Fatal(err)
	}

	snap, err := LoadSnapshot(db, t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	d := snap.Evaluate(snap.ProfileForEndpoint(1), "www.netflix.test.")
	if d.Action != policy.ActionRedirect || d.Target != "10.77.0.1" || !d.ExitHealthy {
		t.Fatalf("redirect decision %+v", d)
	}

	// Health "down" in the database shows up on the next load.
	if err := SetExitHealth(db, exitA, "down"); err != nil {
		t.Fatal(err)
	}
	snap, _ = LoadSnapshot(db, t.TempDir(), false)
	if d := snap.Evaluate(snap.ProfileForEndpoint(1), "netflix.test."); d.ExitHealthy {
		t.Error("down exit still reported healthy")
	}
}

func TestDeletingAnExitRemovesItsRedirects(t *testing.T) {
	db, orgA, _ := exitsDB(t)
	exitA, _ := AddExitNode(db, orgA, "a-vps", "socks5", "a.example:1080", "10.77.0.1")
	if _, err := AddRule(db, orgA, 1, "redirect", "domain", "netflix.test", strconv.FormatInt(exitA, 10)); err != nil {
		t.Fatal(err)
	}
	removed, err := DeleteExitNode(db, orgA, exitA)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed %d redirect rules, want 1", removed)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM profile_rules WHERE kind = 'redirect'`).Scan(&n)
	if n != 0 {
		t.Error("a redirect rule still points at a deleted exit")
	}
}
