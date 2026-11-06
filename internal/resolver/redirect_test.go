package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// fakeUpstream is a real DNS server on loopback that answers every A query
// with 192.0.2.99. The fallback path forwards to it, so the test needs no internet.
func fakeUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.99").To4(),
		})
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	return pc.LocalAddr().String()
}

// newRedirectResolver: the default profile redirects netflix.test (and all
// subdomains) to an exit, and blocks ads.netflix.test, which must win.
func newRedirectResolver(t *testing.T, exitHealthy bool, upstream string) (*Resolver, *captureRecorder) {
	t.Helper()
	exit := &policy.Exit{ID: 7, Name: "vps", AnswerIP: "10.77.0.1", Healthy: exitHealthy}
	p := &policy.Profile{ID: 1, Allow: policy.NewDomainSet(), Block: policy.NewDomainSet(),
		Blocklists: policy.NewDomainSet(), Rewrites: map[string]policy.RewriteRecord{},
		Redirect: policy.NewDomainSet(), RedirectTo: map[string]*policy.Exit{}}
	p.Redirect.Add("netflix.test", true)
	p.RedirectTo["netflix.test"] = exit
	p.Block.Add("ads.netflix.test", false)

	cfg := config.Default()
	cfg.Upstreams = []string{upstream}
	r := New(&cfg)
	r.SetSnapshot(policy.NewSnapshot(nil, map[int64]*policy.Profile{1: p}))
	rec := &captureRecorder{}
	r.SetRecorder(rec)
	return r, rec
}

func TestRedirectAnswersWithExitAddress(t *testing.T) {
	r, rec := newRedirectResolver(t, true, fakeUpstream(t))
	resp := r.answer(query("www.netflix.test"), client{addr: "10.1.5.5:53"})
	if got := firstA(resp); got != "10.77.0.1" {
		t.Fatalf("redirected answer %q, want the exit's address", got)
	}
	if resp.Answer[0].Header().Ttl != 60 {
		t.Errorf("redirect TTL %d, want 60 (short, so an exit change takes effect quickly)", resp.Answer[0].Header().Ttl)
	}
	e := rec.got[len(rec.got)-1]
	if e.Action != "redirect" || e.Reason != "vps" {
		t.Errorf("log entry %+v, want action redirect via vps", e)
	}
}

// IPv6 must not bypass the exit: AAAA for a redirected name gets an empty answer.
func TestRedirectDoesNotLeakIPv6(t *testing.T) {
	r, _ := newRedirectResolver(t, true, fakeUpstream(t))
	q := new(dns.Msg)
	q.SetQuestion("www.netflix.test.", dns.TypeAAAA)
	resp := r.answer(q, client{addr: "10.1.5.5:53"})
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("AAAA for a redirected name: rcode %s answers %d, want empty NOERROR",
			dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}

// A down exit is skipped: the query resolves normally and the log says why.
func TestDownExitFallsBackToForwarding(t *testing.T) {
	r, rec := newRedirectResolver(t, false, fakeUpstream(t))
	resp := r.answer(query("www.netflix.test"), client{addr: "10.1.5.5:53"})
	if got := firstA(resp); got != "192.0.2.99" {
		t.Fatalf("with exit down, answer %q, want the normal upstream answer", got)
	}
	e := rec.got[len(rec.got)-1]
	if e.Action != "forward" || e.Reason != "exit-down:vps" {
		t.Errorf("log entry %+v, want forward with reason exit-down:vps", e)
	}
}

// If the fallback itself fails (upstream unreachable), the log keeps both facts.
func TestFallbackFailureKeepsItsReason(t *testing.T) {
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	dead.Close() // nothing listens here any more
	r, rec := newRedirectResolver(t, false, deadAddr)
	resp := r.answer(query("www.netflix.test"), client{addr: "10.1.5.5:53"})
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode %s, want SERVFAIL when upstream is unreachable", dns.RcodeToString[resp.Rcode])
	}
	e := rec.got[len(rec.got)-1]
	if e.Action != "error" || e.Reason != "exit-down:vps+upstream-failed" {
		t.Errorf("log entry %+v, want error with both reasons", e)
	}
}

// A block always beats a redirect that covers the same name.
func TestBlockBeatsRedirect(t *testing.T) {
	r, _ := newRedirectResolver(t, true, fakeUpstream(t))
	resp := r.answer(query("ads.netflix.test"), client{addr: "10.1.5.5:53"})
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("blocked name under a redirect: rcode %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}
