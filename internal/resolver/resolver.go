// Package resolver wires miekg/dns into the Open Control serving path:
// UDP/TCP/DoT/DoH listeners, cache, upstream pool, policy hook.
//
// Every transport calls answer(), so the policy decision is identical for all
// of them. Only the way the client's identity is read differs:
//
//	UDP, TCP   → source IP (matched against endpoint CIDRs)
//	DoT        → token in the TLS SNI's first label (e.g. <token>.dns.example.com)
//	DoH        → token in the path (/dns-query/<token>)
//
// A presented token that matches no endpoint is refused. It never falls back to
// the IP-based or default policy.
package resolver

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/cloudwaddie/opencontrol/internal/cache"
	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/policy"
)

type Resolver struct {
	cfg       *config.Config
	cache     *cache.Cache
	sf        singleflight.Group
	upstreams []string
	robin     atomic.Uint64
	snapshot  atomic.Pointer[policy.Snapshot]
	udpClient dns.Client
	tcpClient dns.Client
}

// SetSnapshot hot-swaps the compiled policy state (loaded from the store).
// Safe to call at any time; in-flight queries keep the old snapshot.
func (r *Resolver) SetSnapshot(s *policy.Snapshot) {
	r.snapshot.Store(s)
}

func New(cfg *config.Config) *Resolver {
	return &Resolver{
		cfg:       cfg,
		cache:     cache.New(cfg.Cache.MaxEntries),
		upstreams: cfg.Upstreams,
		udpClient: dns.Client{Net: "udp", Timeout: 3 * time.Second, UDPSize: 4096},
		tcpClient: dns.Client{Net: "tcp", Timeout: 5 * time.Second},
	}
}

// client describes who is asking. token is set by DoT (SNI) or DoH (path) and
// takes precedence over the source address.
type client struct {
	addr  string // remote host:port, for logs and CIDR matching
	token string
}

// answer decides and produces the reply for one query. It never returns nil,
// and a panic inside becomes SERVFAIL rather than a silent drop.
func (r *Resolver) answer(req *dns.Msg, c client) (resp *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("resolver: panic from client %s: %v\n%s", c.addr, rec, debug.Stack())
			resp = refusal(req, dns.RcodeServerFailure)
		}
	}()

	if req == nil || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		return refusal(req, dns.RcodeNotImplemented)
	}
	q := req.Question[0]
	key := cache.MakeKey(req)

	// Policy (M1/M3): identify the endpoint → profile → decision.
	if snap := r.snapshot.Load(); snap != nil {
		var prof *policy.Profile
		if c.token != "" {
			ep := snap.EndpointForToken(c.token)
			if ep == nil {
				log.Printf("resolver: REFUSED %s — unknown endpoint token via %s", q.Name, c.addr)
				return refusal(req, dns.RcodeRefused)
			}
			prof = snap.ProfileForEndpoint(ep.ProfileID)
			if prof == nil {
				return refusal(req, dns.RcodeRefused)
			}
		} else {
			if ep := snap.EndpointForClientIP(clientIP(c.addr)); ep != nil {
				prof = snap.ProfileForEndpoint(ep.ProfileID)
			}
			if prof == nil {
				// No endpoint match: fall back to the default org's first profile
				// so a local query never escapes filtering.
				prof = snap.DefaultProfile()
			}
		}
		if prof != nil {
			d := snap.Evaluate(prof, q.Name)
			switch d.Action {
			case policy.ActionBlock:
				log.Printf("resolver: BLOCK %s (%s) via %s", q.Name, d.Reason, c.addr)
				return refusal(req, dns.RcodeNameError)
			case policy.ActionRewrite:
				log.Printf("resolver: REWRITE %s -> %s via %s", q.Name, d.Target, c.addr)
				return rewriteReply(req, q, d.Target)
			case policy.ActionRedirect:
				// Egress phase (PLAN.md M5): forward until exits exist.
				log.Printf("resolver: REDIRECT %s stubbed (%s), forwarding", q.Name, d.Reason)
			}
		}
	}

	// Cache: serve the response if we still have it.
	if msg := r.cache.Get(key, req.Id); msg != nil {
		return msg
	}

	// Single in-flight upstream fetch per key (PLAN.md M0, recovery).
	v, _, _ := r.sf.Do(key, func() (any, error) {
		return r.forward(&q), nil
	})
	up, _ := v.(*dns.Msg)
	if up == nil {
		return refusal(req, dns.RcodeServerFailure)
	}

	// Cache the upstream answer (TTL already clamped by forward) and serve it.
	if ttl := minTTL(up); ttl > 0 {
		r.cache.Put(key, up, ttl)
	}
	out := up.Copy()
	out.Id = req.Id
	return out
}

// handle serves UDP, TCP and DoT (miekg/dns handler).
func (r *Resolver) handle(w dns.ResponseWriter, req *dns.Msg) {
	c := client{addr: remoteAddr(w), token: tokenFromSNI(w)}
	_ = w.WriteMsg(r.answer(req, c))
}

// ListenAndServe starts every configured listener and blocks until one fails.
func (r *Resolver) ListenAndServe() error {
	var tlsCfg *tls.Config
	if r.cfg.DoTListen != "" || r.cfg.DoHListen != "" {
		if r.cfg.TLSCert == "" || r.cfg.TLSKey == "" {
			return errors.New("DoT/DoH need tls_cert and tls_key")
		}
		cert, err := tls.LoadX509KeyPair(r.cfg.TLSCert, r.cfg.TLSKey)
		if err != nil {
			return err
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", r.handle)

	errc := make(chan error, 4)
	start := func(name, addr string, f func() error) {
		log.Printf("resolver: %s listening on %s", name, addr)
		go func() { errc <- f() }()
	}

	udp := &dns.Server{Addr: r.cfg.Listen, Net: "udp", Handler: mux, UDPSize: 4096}
	tcp := &dns.Server{Addr: r.cfg.Listen, Net: "tcp", Handler: mux}
	start("UDP", r.cfg.Listen, udp.ListenAndServe)
	start("TCP", r.cfg.Listen, tcp.ListenAndServe)

	if r.cfg.DoTListen != "" {
		dot := &dns.Server{Addr: r.cfg.DoTListen, Net: "tcp-tls", TLSConfig: tlsCfg, Handler: mux}
		start("DoT", r.cfg.DoTListen, dot.ListenAndServe)
	}
	if r.cfg.DoHListen != "" {
		hm := http.NewServeMux()
		hm.Handle("/dns-query", r.dohHandler())
		hm.Handle("/dns-query/", r.dohHandler())
		doh := &http.Server{Addr: r.cfg.DoHListen, Handler: hm, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
		start("DoH", r.cfg.DoHListen, func() error { return doh.ListenAndServeTLS("", "") })
	}

	// The first listener to fail stops the process; the caller exits.
	return <-errc
}

// dohHandler implements RFC 8484 GET and POST. The endpoint token, if any, is
// the single path segment after /dns-query.
func (r *Resolver) dohHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, hr *http.Request) {
		rest := strings.TrimPrefix(hr.URL.Path, "/dns-query")
		rest = strings.TrimPrefix(rest, "/")
		if strings.Contains(rest, "/") {
			http.NotFound(w, hr)
			return
		}

		req, err := readDoHQuery(w, hr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := r.answer(req, client{addr: hr.RemoteAddr, token: rest})
		packed, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", strconv.Itoa(len(packed)))
		_, _ = w.Write(packed)
	})
}

// readDoHQuery decodes the DNS message from a GET (?dns=base64url) or POST
// (application/dns-message body) request.
func readDoHQuery(w http.ResponseWriter, hr *http.Request) (*dns.Msg, error) {
	var wire []byte
	switch hr.Method {
	case http.MethodGet:
		enc := strings.TrimRight(hr.URL.Query().Get("dns"), "=")
		if enc == "" {
			return nil, errors.New("missing dns parameter")
		}
		b, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			return nil, errors.New("dns parameter is not base64url")
		}
		wire = b
	case http.MethodPost:
		if hr.Header.Get("Content-Type") != "application/dns-message" {
			return nil, errors.New("content type must be application/dns-message")
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, hr.Body, 4096))
		if err != nil {
			return nil, errors.New("body too large or unreadable")
		}
		wire = b
	default:
		return nil, errors.New("method must be GET or POST")
	}
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		return nil, errors.New("not a DNS message")
	}
	return req, nil
}

// tokenFromSNI reads the endpoint token from a DoT connection's SNI. Only a
// first label with the token shape counts; any other SNI means "no token".
func tokenFromSNI(w dns.ResponseWriter) string {
	cs, ok := w.(dns.ConnectionStater)
	if !ok {
		return ""
	}
	st := cs.ConnectionState()
	if st == nil {
		return ""
	}
	label, _, _ := strings.Cut(strings.ToLower(st.ServerName), ".")
	if len(label) == 32 && isHex(label) {
		return label
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func remoteAddr(w dns.ResponseWriter) string {
	if addr := w.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return "unknown"
}

// forward sends the question to the next upstream, UDP first with TCP fallback
// on truncation. On success the returned message already has TTL clamps applied
// so the cache can immediately reuse the same message.
func (r *Resolver) forward(q *dns.Question) *dns.Msg {

	upstream := r.upstreams[int(r.robin.Add(1))%len(r.upstreams)]

	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{*q}

	resp, _, err := r.udpClient.Exchange(req, upstream)
	if err != nil || resp == nil {
		log.Printf("resolver: udp upstream %s failed: %v", upstream, err)
		return nil
	}
	if resp.Truncated {
		// UDP answer exceeded size; retry over TCP per standard practice.
		resp, _, err = r.tcpClient.Exchange(req, upstream)
		if err != nil || resp == nil {
			log.Printf("resolver: tcp fallback %s failed: %v", upstream, err)
			return nil
		}
	}

	if r.cfg.Cache.MaxTTL > 0 {
		clampTTLs(resp, r.cfg.Cache.MinTTL, r.cfg.Cache.MaxTTL)
	}
	return resp
}

func clampTTLs(msg *dns.Msg, min, max uint32) {
	for _, rr := range append(msg.Answer, append(msg.Ns, msg.Extra...)...) {
		if rr.Header().Ttl < min {
			rr.Header().Ttl = min
		}
		if rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
}

func minTTL(msg *dns.Msg) time.Duration {
	var min uint32 = 1<<32 - 1
	for _, rr := range append(msg.Answer, msg.Ns...) {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	if min == 1<<32-1 {
		return 0
	}
	return time.Duration(min) * time.Second
}

// refusal builds a same-shape error reply for a request.
func refusal(req *dns.Msg, code int) *dns.Msg {
	m := new(dns.Msg)
	if req != nil {
		m.SetReply(req)
	}
	m.Rcode = code
	return m
}

// clientIP extracts the client address (without port) as netip.Addr.
func clientIP(clientAddr string) netip.Addr {
	if ap, err := netip.ParseAddrPort(clientAddr); err == nil {
		return ap.Addr()
	}
	var zero netip.Addr
	return zero
}

// rewriteReply answers a REWRITE decision directly, M1 semantics:
// target parses as IPv4 → A, IPv6 → AAAA, otherwise CNAME.
func rewriteReply(req *dns.Msg, q dns.Question, target string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	ip := net.ParseIP(target)
	switch {
	case ip != nil && ip.To4() != nil && q.Qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   ip.To4(),
		})
	case ip != nil && ip.To4() == nil && ip.To16() != nil && q.Qtype == dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: ip,
		})
	default:
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: dns.Fqdn(strings.TrimSuffix(target, ".")),
		})
	}
	return resp
}

