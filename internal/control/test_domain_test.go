package control

import (
	"net/http"
	"testing"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// TestDomainTest replays the resolver's decision without forwarding.
func TestDomainTest(t *testing.T) {
	f := newFixture(t)

	// With no snapshot source wired (unit tests do not run a resolver) the
	// endpoint must say so rather than 500.
	code, m, _ := f.do("GET", "/api/v1/profiles/1/test?qname=ads.example", f.admin, "")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("no snapshot source: %d %v", code, m)
	}

	// Wire a hand-built snapshot: profile 1 blocks ads.example, rewrites
	// sk.example to 10.9.9.9.
	p := &policy.Profile{ID: 1, OrgID: 1, Allow: policy.NewDomainSet(), Block: policy.NewDomainSet(),
		Rewrites: map[string]policy.RewriteRecord{"sk.example": {Target: "10.9.9.9"}}}
	p.Block.Add("ads.example", false)
	snap := policy.NewSnapshot(nil, map[int64]*policy.Profile{1: p})
	SetSnapshotSource(f.h, func() *policy.Snapshot { return snap })

	code, m, _ = f.do("GET", "/api/v1/profiles/1/test?qname=ads.example", f.admin, "")
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, m)
	}
	if m["action"] != "block" || m["answer"] != "NXDOMAIN" || m["answer_style"] != "nxdomain" {
		t.Fatalf("blocked lookup: %v", m)
	}
	if m["reason"] == "" {
		t.Fatalf("no reason reported: %v", m)
	}

	code, m, _ = f.do("GET", "/api/v1/profiles/1/test?qname=sk.example", f.admin, "")
	if code != http.StatusOK || m["action"] != "rewrite" || m["answer"] != "10.9.9.9" {
		t.Fatalf("rewrite lookup: %d %v", code, m)
	}

	// Any other name forwards to the server's upstreams.
	code, m, _ = f.do("GET", "/api/v1/profiles/1/test?qname=ok.example", f.admin, "")
	if code != http.StatusOK || m["action"] != "forward" {
		t.Fatalf("forward lookup: %d %v", code, m)
	}

	// qtype shapes the answer: zero style answers 0.0.0.0 / :: per family.
	p.Options.BlockResponse = "zero"
	code, m, _ = f.do("GET", `/api/v1/profiles/1/test?qname=ads.example&qtype=A`, f.admin, "")
	if code != http.StatusOK || m["answer"] != "0.0.0.0" || m["answer_style"] != "zero" {
		t.Fatalf("zero A: %d %v", code, m)
	}
	code, m, _ = f.do("GET", `/api/v1/profiles/1/test?qname=ads.example&qtype=AAAA`, f.admin, "")
	if code != http.StatusOK || m["answer"] != "::" {
		t.Fatalf("zero AAAA: %d %v", code, m)
	}
	// A profile the snapshot does not know about: 404, not a wrong answer.
	code, _, _ = f.do("GET", "/api/v1/profiles/99/test?qname=x.example", f.admin, "")
	if code != http.StatusNotFound {
		t.Fatalf("unknown profile: %d", code)
	}

	// Viewer may ask; an invalid name is rejected before anything else.
	code, _, _ = f.do("GET", "/api/v1/profiles/1/test?qname=x..y", f.viewer, "")
	if code != http.StatusBadRequest {
		t.Fatalf("bad qname: %d", code)
	}
	code, _, _ = f.do("GET", "/api/v1/profiles/1/test", f.viewer, "")
	if code != http.StatusBadRequest {
		t.Fatalf("missing qname: %d", code)
	}
}
