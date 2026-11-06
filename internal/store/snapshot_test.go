package store

import (
	"path/filepath"
	"testing"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// TestSnapshotDecisions drives the same path the resolver uses:
// rules in SQLite → LoadSnapshot → Evaluate for a qname.
func TestSnapshotDecisions(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
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
	rules := [][]string{
		{"block", "domain", "ads.test", ""},
		{"block", "wildcard", "evil.test", ""},
		{"allow", "wildcard", "ok.evil.test", ""},
		{"rewrite", "domain", "router.test", "10.0.0.1"},
		{"block", "tld", "xyz", ""},
	}
	for _, r := range rules {
		if _, err := AddRule(db, 1, r[0], r[1], r[2], r[3]); err != nil {
			t.Fatalf("AddRule %v: %v", r, err)
		}
	}

	snap, err := LoadSnapshot(db, t.TempDir(), false) // no network in tests
	if err != nil {
		t.Fatal(err)
	}
	prof := snap.ProfileForEndpoint(1)
	if prof == nil {
		t.Fatal("profile 1 not loaded")
	}

	cases := []struct {
		qname string
		want  policy.Action
	}{
		{"ads.test.", policy.ActionBlock},
		{"a.b.evil.test.", policy.ActionBlock},
		{"ok.evil.test.", policy.ActionForward},
		{"sub.ads.test.", policy.ActionForward},
		{"router.test.", policy.ActionRewrite},
		{"foo.xyz.", policy.ActionBlock},
		{"example.com.", policy.ActionForward},
	}
	for _, c := range cases {
		d := snap.Evaluate(prof, c.qname)
		if d.Action != c.want {
			t.Errorf("Evaluate(%s) = %s (%s), want %s", c.qname, d.Action, d.Reason, c.want)
		}
	}
}
