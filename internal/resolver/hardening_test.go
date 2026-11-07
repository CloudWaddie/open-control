package resolver

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/cloudwaddie/opencontrol/internal/config"
)

func TestLimiterBurstThenRefill(t *testing.T) {
	l := newLimiter(10) // burst 20
	ip := netip.MustParseAddr("192.168.1.9")
	now := time.Unix(1000, 0)
	for i := 0; i < 20; i++ {
		if !l.allow(ip, now) {
			t.Fatalf("query %d inside the burst was limited", i)
		}
	}
	if l.allow(ip, now) {
		t.Fatal("query past the burst was allowed")
	}
	if !l.allow(netip.MustParseAddr("192.168.1.10"), now) {
		t.Fatal("another client shares the first client's bucket")
	}
	if !l.allow(ip, now.Add(200*time.Millisecond)) {
		t.Fatal("bucket did not refill after 200ms at 10 qps")
	}
}

func TestLimiterGroupsIPv6By56(t *testing.T) {
	l := newLimiter(1) // burst 2
	now := time.Unix(1000, 0)
	l.allow(netip.MustParseAddr("2001:db8:0:1::1"), now)
	l.allow(netip.MustParseAddr("2001:db8:0:2::1"), now)
	if l.allow(netip.MustParseAddr("2001:db8:0:3::1"), now) {
		t.Fatal("addresses in one /56 should share a bucket")
	}
	if !l.allow(netip.MustParseAddr("2001:db8:1::1"), now) {
		t.Fatal("a different /56 should have its own bucket")
	}
}

func TestANYGetsMinimalAnswer(t *testing.T) {
	r := newTestResolver(t)
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeANY)
	resp := r.answer(q, client{addr: "10.1.5.5:53"})
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1 HINFO", len(resp.Answer))
	}
	if h, ok := resp.Answer[0].(*dns.HINFO); !ok || h.Cpu != "RFC8482" {
		t.Fatalf("answer %v, want RFC 8482 HINFO", resp.Answer[0])
	}
}

func TestFinalizeTruncatesToClientSize(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("big.test.", dns.TypeTXT)
	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := 0; i < 40; i++ {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "big.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{fmt.Sprintf("%050d", i)},
		})
	}
	out := finalize(req, resp.Copy(), true)
	if !out.Truncated || out.Len() > dns.MinMsgSize {
		t.Fatalf("no-EDNS client: truncated=%v len=%d, want TC and <=512", out.Truncated, out.Len())
	}
	if out := finalize(req, resp.Copy(), false); out.Truncated {
		t.Fatal("TCP replies must not be truncated")
	}

	req.SetEdns0(4096, true)
	out = finalize(req, resp.Copy(), true)
	if out.Len() > ednsSize {
		t.Fatalf("EDNS reply is %d bytes, want <= %d", out.Len(), ednsSize)
	}
	if opt := out.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatal("EDNS client should get an OPT record echoing DO")
	}
}

// A dead first upstream must not cause SERVFAIL when a second one works.
func TestForwardFailsOverToNextUpstream(t *testing.T) {
	good := startUpstream(t)
	dead := deadUDPAddr(t)
	cfg := config.Default()
	cfg.Upstreams = []string{dead, good}
	r := New(&cfg)
	for i := 0; i < 2; i++ { // round-robin start alternates; both orders must work
		q := dns.Question{Name: "ok.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		if resp := r.forward(&q, false); resp == nil || firstA(resp) != "192.0.2.53" {
			t.Fatalf("attempt %d: no answer through the healthy upstream", i)
		}
	}
}

func startUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.53"),
		}}
		_ = w.WriteMsg(resp)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// deadUDPAddr is a local port with nothing listening.
func deadUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}
