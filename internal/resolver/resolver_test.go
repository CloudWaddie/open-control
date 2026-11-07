package resolver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/policy"
	"github.com/cloudwaddie/opencontrol/internal/store"
)

const (
	tokA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // endpoint A: blocks ads.test
	tokB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // endpoint B: rewrites ads.test
)

// newTestResolver builds a resolver with two endpoints on two profiles:
//
//	profile 1 (A, and the default): blocks ads.test
//	profile 2 (B): rewrites ads.test to 10.9.9.9
//
// Nothing here forwards upstream, so the tests need no network.
func newTestResolver(t *testing.T) *Resolver {
	t.Helper()
	p1 := &policy.Profile{ID: 1, Allow: policy.NewDomainSet(), Block: policy.NewDomainSet(), Rewrites: map[string]policy.RewriteRecord{}}
	p1.Block.Add("ads.test", false)

	p2 := &policy.Profile{ID: 2, Allow: policy.NewDomainSet(), Block: policy.NewDomainSet(), Rewrites: map[string]policy.RewriteRecord{}}
	p2.Rewrites["ads.test"] = policy.RewriteRecord{Target: "10.9.9.9"}

	cidrA, err := policy.NewCidrSetFromJSON(`["10.1.0.0/16"]`)
	if err != nil {
		t.Fatal(err)
	}
	cidrB, err := policy.NewCidrSetFromJSON(`["10.2.0.0/16"]`)
	if err != nil {
		t.Fatal(err)
	}
	eps := []*policy.Endpoint{
		{ID: 1, Name: "a", ProfileID: 1, Allowed: cidrA, TokenHash: policy.HashSecret(tokA)},
		{ID: 2, Name: "b", ProfileID: 2, Allowed: cidrB, TokenHash: policy.HashSecret(tokB)},
	}
	cfg := config.Default()
	r := New(&cfg)
	r.SetSnapshot(policy.NewSnapshot(eps, map[int64]*policy.Profile{1: p1, 2: p2}))
	return r
}

func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func firstA(m *dns.Msg) string {
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func TestPolicyFollowsEndpointIdentity(t *testing.T) {
	r := newTestResolver(t)
	cases := []struct {
		name     string
		c        client
		wantRcod int
		wantIP   string
		note     string
	}{
		{"token A blocks", client{addr: "203.0.113.5:1", token: tokA}, dns.RcodeNameError, "", "token A → profile 1 → block"},
		{"token B rewrites", client{addr: "203.0.113.5:1", token: tokB}, dns.RcodeSuccess, "10.9.9.9", "token B → profile 2 → rewrite"},
		{"token beats source IP", client{addr: "10.2.5.5:53", token: tokA}, dns.RcodeNameError, "", "B's CIDR but A's token → A's policy"},
		{"IP in A's range", client{addr: "10.1.5.5:53"}, dns.RcodeNameError, "", "source IP matches endpoint A"},
		{"IP in B's range", client{addr: "10.2.5.5:53"}, dns.RcodeSuccess, "10.9.9.9", "source IP matches endpoint B"},
		{"unknown private IP uses default", client{addr: "192.168.7.1:53"}, dns.RcodeNameError, "", "no endpoint, private network → default profile"},
		{"unknown public IP refused", client{addr: "192.0.2.1:53"}, dns.RcodeRefused, "", "no endpoint, public network → refused (not an open resolver)"},
		{"public IP with token", client{addr: "192.0.2.1:53", token: tokB}, dns.RcodeSuccess, "10.9.9.9", "a token works from anywhere"},
	}
	for _, c := range cases {
		resp := r.answer(query("ads.test"), c.c)
		if resp.Rcode != c.wantRcod {
			t.Errorf("%s: rcode %s, want %s", c.note, dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.wantRcod])
		}
		if c.wantIP != "" && firstA(resp) != c.wantIP {
			t.Errorf("%s: answer %q, want %q", c.note, firstA(resp), c.wantIP)
		}
	}
}

func TestUnknownTokenIsRefusedNotDefaulted(t *testing.T) {
	r := newTestResolver(t)
	resp := r.answer(query("ads.test"), client{addr: "10.1.5.5:53", token: strings.Repeat("c", 32)})
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("unknown token: rcode %s, want REFUSED (must not fall back to IP policy)", dns.RcodeToString[resp.Rcode])
	}
}

func TestNonQueryIsNotImplemented(t *testing.T) {
	r := newTestResolver(t)
	m := query("ads.test")
	m.Opcode = dns.OpcodeNotify
	if resp := r.answer(m, client{addr: "10.1.5.5:53"}); resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("notify: rcode %s, want NOTIMP", dns.RcodeToString[resp.Rcode])
	}
}

// --- transports ---

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test"},
		DNSNames:     []string{"dns.test", "*.dns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestDoTTokenFromSNI runs a real DoT listener and queries it with the token
// as the SNI label. The TLS handshake and the DNS answer both have to work.
func TestDoTTokenFromSNI(t *testing.T) {
	r := newTestResolver(t)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", r.handle)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	srv := &dns.Server{Listener: ln, Handler: mux}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	time.Sleep(50 * time.Millisecond)

	ask := func(sni string) *dns.Msg {
		c := &dns.Client{Net: "tcp-tls", Timeout: 5 * time.Second,
			TLSConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true}}
		resp, _, err := c.Exchange(query("ads.test"), raw.Addr().String())
		if err != nil {
			t.Fatalf("DoT exchange (sni %s): %v", sni, err)
		}
		return resp
	}

	if resp := ask(tokA + ".dns.test"); resp.Rcode != dns.RcodeNameError {
		t.Errorf("DoT token A: rcode %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if resp := ask(tokB + ".dns.test"); firstA(resp) != "10.9.9.9" {
		t.Errorf("DoT token B: answer %q, want 10.9.9.9", firstA(resp))
	}
	if resp := ask(strings.Repeat("d", 32) + ".dns.test"); resp.Rcode != dns.RcodeRefused {
		t.Errorf("DoT unknown token: rcode %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

// TestDoHPathToken exercises the RFC 8484 handler over HTTPS: POST and GET,
// the token in the path, and the malformed-request responses.
func TestDoHPathToken(t *testing.T) {
	r := newTestResolver(t)
	hm := http.NewServeMux()
	hm.Handle("/dns-query", r.dohHandler())
	hm.Handle("/dns-query/", r.dohHandler())
	srv := httptest.NewUnstartedServer(hm)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	wire, _ := query("ads.test").Pack()
	// post returns the status and, for 200 responses, the decoded DNS message.
	post := func(path string, body []byte, ctype string) (int, *dns.Msg) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return res.StatusCode, nil
		}
		var out dns.Msg
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(res.Body)
		if err := out.Unpack(b.Bytes()); err != nil {
			t.Fatalf("200 response is not DNS: %v", err)
		}
		return res.StatusCode, &out
	}

	code, m := post("/dns-query/"+tokA, wire, "application/dns-message")
	if code != 200 || m == nil || m.Rcode != dns.RcodeNameError {
		t.Errorf("DoH POST token A: status %d msg %+v, want 200 NXDOMAIN", code, m)
	}

	enc := base64.RawURLEncoding.EncodeToString(wire)
	res, err := client.Get(srv.URL + "/dns-query/" + tokB + "?dns=" + enc)
	if err != nil {
		t.Fatal(err)
	}
	var got dns.Msg
	b := new(bytes.Buffer)
	_, _ = b.ReadFrom(res.Body)
	res.Body.Close()
	if err := got.Unpack(b.Bytes()); err != nil || firstA(&got) != "10.9.9.9" {
		t.Errorf("DoH GET token B: %v answer %q, want 10.9.9.9", err, firstA(&got))
	}

	if code, _ := post("/dns-query/"+strings.Repeat("e", 32), wire, "application/dns-message"); code != 200 {
		t.Errorf("unknown token status %d, want 200 with REFUSED", code)
	}
	if code, _ := post("/dns-query/"+tokA, wire, "text/plain"); code != http.StatusBadRequest {
		t.Errorf("wrong content type: status %d, want 400", code)
	}
	if code, _ := post("/dns-query/"+tokA, []byte("not dns"), "application/dns-message"); code != http.StatusBadRequest {
		t.Errorf("garbage body: status %d, want 400", code)
	}
	if res, _ := client.Get(srv.URL + "/dns-query/" + tokA + "/extra"); res.StatusCode != http.StatusNotFound {
		t.Errorf("extra path segment: status %d, want 404", res.StatusCode)
	}
}

type captureRecorder struct {
	mu  sync.Mutex
	got []store.QueryLog
}

func (c *captureRecorder) Record(e store.QueryLog) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, e)
}

// Every decision is recorded with its action, endpoint and client address.
func TestDecisionsAreRecorded(t *testing.T) {
	r := newTestResolver(t)
	rec := &captureRecorder{}
	r.SetRecorder(rec)

	r.answer(query("ads.test"), client{addr: "203.0.113.5:1", token: tokA})
	r.answer(query("ads.test"), client{addr: "203.0.113.5:1", token: tokB})
	r.answer(query("ads.test"), client{addr: "203.0.113.5:1", token: strings.Repeat("f", 32)})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.got) != 3 {
		t.Fatalf("recorded %d events, want 3", len(rec.got))
	}
	block, rewrite, refused := rec.got[0], rec.got[1], rec.got[2]
	if block.Action != "block" || block.Endpoint != 1 || block.Client != "203.0.113.5" || block.QName != "ads.test" || block.QType != "A" {
		t.Errorf("block event: %+v", block)
	}
	if rewrite.Action != "rewrite" || rewrite.Endpoint != 2 || rewrite.Reason != "10.9.9.9" {
		t.Errorf("rewrite event: %+v", rewrite)
	}
	if refused.Action != "refused" || refused.Org != 0 || refused.Endpoint != 0 {
		t.Errorf("refused event should be unattributed: %+v", refused)
	}
}

// Sanity: the netip import is used by clientIP; keep a direct check too.
func TestClientIPParsing(t *testing.T) {
	if got := clientIP("10.1.2.3:53"); got != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("clientIP = %v", got)
	}
	if got := clientIP("not-an-address"); got.IsValid() {
		t.Errorf("clientIP of garbage = %v, want invalid", got)
	}
}
