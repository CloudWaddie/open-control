package store

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// TestSnapshotDecisions drives the same path the resolver uses:
// rules in SQLite → LoadSnapshot → Evaluate for a qname.
// Two tenants on one resolver: each client gets its own org's profile, and
// rules never cross org lines.
func TestTenantsEnforceSeparately(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tenants.db"))
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
	orgA, _ := DefaultOrgID(db)
	if _, err := AddRule(db, orgA, 1, "block", "domain", "ads.test", ""); err != nil {
		t.Fatal(err)
	}

	orgB, err := CreateOrg(db, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	profB, err := AddProfile(db, orgB, "b-policy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddRule(db, orgB, profB, "block", "domain", "b-only.test", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddEndpoint(db, orgB, "b-laptops", profB, "10.50.0.0/16"); err != nil {
		t.Fatal(err)
	}

	snap, err := LoadSnapshot(db, t.TempDir(), policy.FetchNone)
	if err != nil {
		t.Fatal(err)
	}

	// A client in B's range is matched to B's endpoint (more specific than the
	// default 0.0.0.0/0) and filtered by B's profile only.
	ep := snap.EndpointForClientIP(netip.MustParseAddr("10.50.3.7"))
	if ep == nil || ep.ProfileID != profB {
		t.Fatalf("tenant B client matched endpoint %+v, want profile %d", ep, profB)
	}
	pb := snap.ProfileForEndpoint(ep.ProfileID)
	if d := snap.Evaluate(pb, "b-only.test."); d.Action != policy.ActionBlock {
		t.Errorf("B's own rule not enforced: %s", d.Action)
	}
	if d := snap.Evaluate(pb, "ads.test."); d.Action != policy.ActionForward {
		t.Errorf("A's rule leaked into B's policy: %s (%s)", d.Action, d.Reason)
	}
}

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
	org, err := DefaultOrgID(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if _, err := AddRule(db, org, 1, r[0], r[1], r[2], r[3]); err != nil {
			t.Fatalf("AddRule %v: %v", r, err)
		}
	}

	snap, err := LoadSnapshot(db, t.TempDir(), policy.FetchNone) // no network in tests
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
