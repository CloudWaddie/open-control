package resolver

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// qA builds an A question; qAAAA an AAAA question, for a name.
func qA(name string) dns.Question {
	return dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func TestBlockReplyStyles(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("blocked.example.", dns.TypeA)
	prof := &policy.Profile{ID: 1, Options: policy.Options{}}

	// Default: NXDOMAIN with the question echoed.
	resp := blockReply(prof, req, qA("blocked.example"))
	if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 {
		t.Fatalf("default block: %s %+v", dns.RcodeToString[resp.Rcode], resp.Answer)
	}

	// zero: 0.0.0.0 with the block TTL.
	prof.Options.BlockResponse = "zero"
	resp = blockReply(prof, req, qA("blocked.example"))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatal("zero style: no zero answer")
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "0.0.0.0" || a.Hdr.Ttl != 10 {
		t.Fatalf("zero answer: %s ttl=%d", a.A.String(), a.Hdr.Ttl)
	}

	// nodata and refused.
	prof.Options.BlockResponse = "nodata"
	if resp = blockReply(prof, req, qA("blocked.example")); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatal("nodata style: wrong rcode")
	}
	prof.Options.BlockResponse = "refused"
	if resp = blockReply(prof, req, qA("blocked.example")); resp.Rcode != dns.RcodeRefused {
		t.Fatal("refused style: wrong rcode")
	}

	// custom: address from the profile, block TTL honored.
	prof.Options.BlockResponse = "custom"
	prof.Options.BlockIPv4 = "10.4.4.4"
	prof.Options.BlockTTL = 33
	resp = blockReply(prof, req, qA("blocked.example"))
	if a := resp.Answer[0].(*dns.A); a.A.String() != "10.4.4.4" || a.Hdr.Ttl != 33 {
		t.Errorf("custom answer: %s ttl=%d", a.A.String(), a.Hdr.Ttl)
	}
	// An AAAA question when only IPv4 was configured: NODATA, not a lie.
	areq := new(dns.Msg)
	areq.SetQuestion("x.example.", dns.TypeAAAA)
	if resp = blockReply(prof, areq, areq.Question[0]); len(resp.Answer) != 0 || resp.Rcode != dns.RcodeSuccess {
		t.Fatal("custom without the v6 address should be NODATA")
	}
}

func TestRedirectReplyCompat(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("netflix.example.", dns.TypeAAAA)

	var zero policy.Options
	// No IPv6 and no compat: empty NOERROR so v6 clients still hit the exit.
	resp := redirectReply(req, req.Question[0], "10.77.0.1", "", zero)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatal("redirect AAAA without compat should be empty NOERROR")
	}

	// Compat mode synthesizes the RFC 6052 form of the exit's IPv4.
	zero.CompatMode = true
	resp = redirectReply(req, req.Question[0], "10.77.0.1", "", zero)
	if len(resp.Answer) != 1 || resp.Rcode != dns.RcodeSuccess {
		t.Fatal("redirect AAAA compat: no synthesized answer")
	}
	aaaa := resp.Answer[0].(*dns.AAAA)
	want := nat64IP(netip.MustParsePrefix("64:ff9b::/96"), net.ParseIP("10.77.0.1"))
	if !aaaa.AAAA.Equal(want) || aaaa.Hdr.Ttl != 60 {
		t.Fatalf("compat answer %s ttl %d", aaaa.AAAA.String(), aaaa.Hdr.Ttl)
	}

	// A real IPv6 answer overrides the synth; the redirect TTL applies.
	zero.RedirectTTL = 7
	resp = redirectReply(req, req.Question[0], "10.77.0.1", "2001:db8::9", zero)
	aaaa = resp.Answer[0].(*dns.AAAA)
	if !aaaa.AAAA.Equal(net.ParseIP("2001:db8::9")) || aaaa.Hdr.Ttl != 7 {
		t.Fatalf("explicit v6 answer %s ttl %d", aaaa.AAAA.String(), aaaa.Hdr.Ttl)
	}
}

func TestStripRebind(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "a.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.168.1.4")},
		&dns.A{Hdr: dns.RR_Header{Name: "b.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("8.8.8.8")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "c.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("fe80::1")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "d.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::1")},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "e.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "f."},
	}
	stripRebind(m)
	if len(m.Answer) != 3 {
		t.Fatalf("kept %d records, want 3 public ones", len(m.Answer))
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok && !a.A.Equal(net.ParseIP("8.8.8.8")) {
			t.Errorf("kept a private A: %s", a.A)
		}
	}
}

func TestSynthAAAAAndFlattening(t *testing.T) {
	req := new(dns.Msg)
	q := dns.Question{Name: "x.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	req.SetQuestion("x.example.", dns.TypeAAAA)

	// DNS64: AAAA question, only an A answer → synthesized rows.
	m := req.Copy()
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("203.0.113.2")}}
	var opts policy.Options
	opts.DNS64 = true
	r := &Resolver{upstreams: []string{"127.0.0.1:1"}} // post-process never forwards here
	oo := upstreamOpts{}
	r.postProcess(m, &q, oo, opts)
	if len(m.Answer) != 2 || hasType(m, dns.TypeAAAA) == false {
		t.Fatalf("dns64 synth: %d records", len(m.Answer))
	}
	synth := m.Answer[1].(*dns.AAAA)
	if !synth.AAAA.Equal(nat64IP(netip.MustParsePrefix("64:ff9b::/96"), net.ParseIP("203.0.113.2"))) {
		t.Fatalf("synth address %s", synth.AAAA)
	}

	// Compat mode does the same; nothing does it when both are off.
	m = req.Copy()
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("203.0.113.2")}}
	opts.CompatMode = true
	r.postProcess(m, &q, oo, opts)
	if !hasType(m, dns.TypeAAAA) {
		t.Fatal("compat mode did not synthesize")
	}
	m = req.Copy()
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("203.0.113.2")}}
	r.postProcess(m, &q, oo, policy.Options{})
	if hasType(m, dns.TypeAAAA) {
		t.Fatal("synthesized without the option set")
	}
}

func TestAttachECS(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("cdn.example.", dns.TypeA)
	req.SetEdns0(ednsSize, false)
	q := &req.Question[0]

	// "client": a /24 slice of the asking address.
	attachECS(req, q, "client", netip.MustParseAddr("203.0.113.77"))
	sub, ok := req.IsEdns0().Option[len(req.IsEdns0().Option)-1].(*dns.EDNS0_SUBNET)
	if !ok || sub.Family != 1 || sub.SourceNetmask != 24 || sub.Address.String() != "203.0.113.0" {
		t.Fatalf("client ECS: %+v", sub)
	}

	// Fixed CIDR: masked, source netmask from the prefix.
	req2 := new(dns.Msg)
	req2.SetQuestion("cdn.example.", dns.TypeA)
	req2.SetEdns0(ednsSize, false)
	attachECS(req2, &req2.Question[0], "198.51.100.0/24", netip.Addr{})
	sub = req2.IsEdns0().Option[0].(*dns.EDNS0_SUBNET)
	if sub.SourceNetmask != 24 || sub.Address.String() != "198.51.100.0" {
		t.Fatalf("fixed ECS: %+v", sub)
	}

	// Family mismatch (AAAA question, IPv4 subnet) sends nothing.
	req3 := new(dns.Msg)
	req3.SetQuestion("x.example.", dns.TypeAAAA)
	req3.SetEdns0(ednsSize, false)
	attachECS(req3, &req3.Question[0], "198.51.100.0/24", netip.Addr{})
	if len(req3.IsEdns0().Option) != 0 {
		t.Fatal("family-mismatched ECS attached")
	}
}

func TestProfileKey(t *testing.T) {
	if profileKey("k\x00a.test", 0) != "k\x00a.test" {
		t.Fatal("nil profile should keep the plain key")
	}
	if !strings.Contains(profileKey("k\x00a.test", 3), "p3") {
		t.Fatal("profile key not namespaced")
	}
}

func TestCapTTLsBypass(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "a.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 9000}, A: net.ParseIP("8.8.8.8")},
		&dns.A{Hdr: dns.RR_Header{Name: "b.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP("8.8.4.4")},
	}
	capTTLs(m, 300)
	if m.Answer[0].Header().Ttl != 300 || m.Answer[1].Header().Ttl != 5 {
		t.Fatalf("capTTLs: %d %d", m.Answer[0].Header().Ttl, m.Answer[1].Header().Ttl)
	}
}

// TestPausedProfileForwards checks the paused branch end to end through
// answer(): a paused profile forwards, i.e. gets the upstream's answer.
func TestPausedProfileForwards(t *testing.T) {
	up := startUpstream(t)
	cfg := config.Default()
	cfg.Upstreams = []string{up}
	r := New(&cfg)
	future := time.Now().Add(time.Hour).Unix()
	p := &policy.Profile{ID: 1, Allow: policy.NewDomainSet(), Block: policy.NewDomainSet(), Options: policy.Options{DisabledUntil: future}}
	r.SetSnapshot(policy.NewSnapshot(nil, map[int64]*policy.Profile{1: p}))
	req := new(dns.Msg)
	req.SetQuestion("ok.test.", dns.TypeA)
	resp := r.answer(req, client{addr: "127.0.0.1:53531"})
	if resp == nil || firstA(resp) != "192.0.2.53" {
		t.Fatalf("paused profile must forward, got %+v", resp)
	}
}
