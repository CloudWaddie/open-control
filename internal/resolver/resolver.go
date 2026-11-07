// Package resolver wires miekg/dns into the Open Control serving path:
// UDP/TCP/DoT/DoH listeners, cache, upstream pool, policy hook, query log.
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
	"context"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/cloudwaddie/opencontrol/internal/cache"
	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/metrics"
	"github.com/cloudwaddie/opencontrol/internal/policy"
	"github.com/cloudwaddie/opencontrol/internal/store"
)

// Recorder receives one entry per decision. qlog.Logger satisfies it; its
// Record must not block.
type Recorder interface {
	Record(store.QueryLog)
}

type Resolver struct {
	cfg       *config.Config
	cache     *cache.Cache
	sf        singleflight.Group
	upstreams []string
	robin     atomic.Uint64
	snapshot  atomic.Pointer[policy.Snapshot]
	recorder  atomic.Pointer[Recorder]
	udpClient dns.Client
	tcpClient dns.Client
	limit     *limiter

	mu      sync.Mutex
	dnsSrvs []*dns.Server
	httpSrv *http.Server
}

var (
	mQueries  = metrics.NewCounter("opencontrol_dns_queries_total", "DNS queries by outcome.", "action")
	mDropped  = metrics.NewCounter("opencontrol_dns_dropped_total", "Queries dropped before policy, by reason.", "reason")
	mCache    = metrics.NewCounter("opencontrol_dns_cache_total", "Cache lookups by result.", "result")
	mUpErrors = metrics.NewCounter("opencontrol_upstream_errors_total", "Failed upstream exchanges by upstream.", "upstream")
	mUpTime   = metrics.NewHistogram("opencontrol_upstream_duration_seconds", "Upstream exchange latency.",
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5})
)

// SetSnapshot hot-swaps the compiled policy state (loaded from the store).
// Safe to call at any time; in-flight queries keep the old snapshot.
func (r *Resolver) SetSnapshot(s *policy.Snapshot) {
	r.snapshot.Store(s)
}

// SetRecorder installs the query-log sink. Without one, decisions are not logged.
func (r *Resolver) SetRecorder(rec Recorder) {
	r.recorder.Store(&rec)
}

func New(cfg *config.Config) *Resolver {
	return &Resolver{
		cfg:       cfg,
		cache:     cache.New(cfg.Cache.MaxEntries),
		upstreams: cfg.Upstreams,
		udpClient: dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: ednsSize},
		tcpClient: dns.Client{Net: "tcp", Timeout: 4 * time.Second},
		limit:     newLimiter(cfg.RateLimitQPS),
	}
}

// client describes who is asking. token is set by DoT (SNI) or DoH (path) and
// takes precedence over the source address.
type client struct {
	addr  string // remote host:port, for logs and CIDR matching
	token string
}

// verdict is what a decision concluded, for the query log.
type verdict struct {
	org      int64 // 0 when the query could not be attributed to an org
	endpoint int64 // 0 when no endpoint matched (default profile)
	action   string
	reason   string
}

// answer decides and produces the reply for one query. It never returns nil,
// and a panic inside becomes SERVFAIL rather than a silent drop.
func (r *Resolver) answer(req *dns.Msg, c client) *dns.Msg {
	var v verdict
	resp := r.decide(req, c, &v)
	mQueries.Inc(v.action)
	if v.reason == "not-allowed" {
		// Unattributed and possibly hostile; counted, not stored.
		return resp
	}
	if rec := r.recorder.Load(); rec != nil && req != nil && len(req.Question) == 1 {
		q := req.Question[0]
		(*rec).Record(store.QueryLog{
			Org:      v.org,
			Endpoint: v.endpoint,
			Ts:       time.Now().Unix(),
			Client:   clientHost(c.addr),
			QName:    strings.ToLower(strings.TrimSuffix(q.Name, ".")),
			QType:    dns.TypeToString[q.Qtype],
			Action:   v.action,
			Reason:   v.reason,
		})
	}
	return resp
}

func (r *Resolver) decide(req *dns.Msg, c client, v *verdict) (resp *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("resolver: panic from client %s: %v\n%s", c.addr, rec, debug.Stack())
			v.action, v.reason = "error", "panic"
			resp = refusal(req, dns.RcodeServerFailure)
		}
	}()

	if req == nil || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		v.action, v.reason = "error", "not-a-query"
		return refusal(req, dns.RcodeNotImplemented)
	}
	q := req.Question[0]
	if q.Qtype == dns.TypeANY {
		// RFC 8482: a minimal answer instead of everything we know, which
		// removes ANY as an amplification vector.
		v.action, v.reason = "forward", "rfc8482"
		return anyReply(req, q)
	}
	key := cache.MakeKey(req)

	// fallback records why a redirect was not applied (exit down), so the
	// forwarded answer's log line says so.
	fallback := ""
	forwardReason := func(s string) string {
		if fallback != "" {
			return fallback
		}
		return s
	}

	// Policy (M1/M3): identify the endpoint → profile → decision.
	if snap := r.snapshot.Load(); snap != nil {
		var prof *policy.Profile
		if c.token != "" {
			ep := snap.EndpointForToken(c.token)
			if ep == nil {
				r.debugf("resolver: REFUSED %s — unknown endpoint token via %s", q.Name, c.addr)
				v.action, v.reason = "refused", "unknown-token"
				return refusal(req, dns.RcodeRefused)
			}
			prof = snap.ProfileForEndpoint(ep.ProfileID)
			if prof == nil {
				v.action, v.reason = "refused", "no-profile"
				return refusal(req, dns.RcodeRefused)
			}
			v.endpoint = ep.ID
		} else {
			ip := clientIP(c.addr)
			ep, bits := snap.MatchClientIP(ip)
			// Only a specific endpoint (narrower than 0.0.0.0/0) or a trusted
			// network may use the resolver without a token. Anyone else is
			// refused, so a public server is not an open resolver.
			if bits <= 0 && !r.cfg.PlainDNSAllowed(ip) {
				v.action, v.reason = "refused", "not-allowed"
				return refusal(req, dns.RcodeRefused)
			}
			if ep != nil {
				prof = snap.ProfileForEndpoint(ep.ProfileID)
				v.endpoint = ep.ID
			}
			if prof == nil {
				// No endpoint match: fall back to the default org's first profile
				// so a local query never escapes filtering.
				prof = snap.DefaultProfile()
				v.endpoint = 0
			}
		}
		if prof != nil {
			v.org = prof.OrgID
			d := snap.Evaluate(prof, q.Name)
			switch d.Action {
			case policy.ActionBlock:
				r.debugf("resolver: BLOCK %s (%s) via %s", q.Name, d.Reason, c.addr)
				v.action, v.reason = "block", d.Reason
				return refusal(req, dns.RcodeNameError)
			case policy.ActionRewrite:
				r.debugf("resolver: REWRITE %s -> %s via %s", q.Name, d.Target, c.addr)
				v.action, v.reason = "rewrite", d.Target
				return rewriteReply(req, q, d.Target)
			case policy.ActionRedirect:
				if d.ExitHealthy {
					r.debugf("resolver: REDIRECT %s → exit %s (%s) via %s", q.Name, d.ExitName, d.Target, c.addr)
					v.action, v.reason = "redirect", d.ExitName
					return redirectReply(req, q, d.Target)
				}
				// The exit is down: resolve normally and say so in the log.
				r.debugf("resolver: REDIRECT %s skipped, exit %s is down; forwarding", q.Name, d.ExitName)
				fallback = "exit-down:" + d.ExitName
			}
		}
	}

	// Cache: serve the response if we still have it.
	if msg := r.cache.Get(key, req.Id); msg != nil {
		mCache.Inc("hit")
		v.action, v.reason = "forward", forwardReason("cache")
		return msg
	}

	mCache.Inc("miss")

	// Single in-flight upstream fetch per key (PLAN.md M0, recovery).
	do := isDO(req)
	res, _, _ := r.sf.Do(key, func() (any, error) {
		return r.forward(&q, do), nil
	})
	up, _ := res.(*dns.Msg)
	if up == nil {
		v.action = "error"
		v.reason = "upstream-failed"
		if fallback != "" {
			v.reason = fallback + "+upstream-failed"
		}
		return refusal(req, dns.RcodeServerFailure)
	}

	// Cache the upstream answer (TTL already clamped by forward) and serve it.
	if ttl := minTTL(up); ttl > 0 {
		r.cache.Put(key, up, ttl)
	}
	v.action, v.reason = "forward", forwardReason("upstream")
	out := up.Copy()
	out.Id = req.Id
	return out
}

// handle serves UDP, TCP and DoT (miekg/dns handler).
func (r *Resolver) handle(w dns.ResponseWriter, req *dns.Msg) {
	c := client{addr: remoteAddr(w), token: tokenFromSNI(w)}
	_, udp := w.RemoteAddr().(*net.UDPAddr)
	if !r.limit.allow(clientIP(c.addr), time.Now()) {
		mDropped.Inc("ratelimited")
		if udp {
			return // silence: replying would still amplify a spoofed source
		}
		_ = w.WriteMsg(refusal(req, dns.RcodeRefused))
		return
	}
	_ = w.WriteMsg(finalize(req, r.answer(req, c), udp))
}

func (r *Resolver) debugf(format string, args ...any) {
	if r.cfg.LogQueries {
		log.Printf(format, args...)
	}
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

	// TCP-based servers get idle limits so slow or idle clients cannot pin
	// connections indefinitely.
	idle := func() time.Duration { return 10 * time.Second }
	udp := &dns.Server{Addr: r.cfg.Listen, Net: "udp", Handler: mux, UDPSize: ednsSize}
	tcp := &dns.Server{Addr: r.cfg.Listen, Net: "tcp", Handler: mux, IdleTimeout: idle,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	r.track(udp, tcp)
	start("UDP", r.cfg.Listen, udp.ListenAndServe)
	start("TCP", r.cfg.Listen, tcp.ListenAndServe)

	if r.cfg.DoTListen != "" {
		dot := &dns.Server{Addr: r.cfg.DoTListen, Net: "tcp-tls", TLSConfig: tlsCfg, Handler: mux,
			IdleTimeout: idle, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		r.track(dot)
		start("DoT", r.cfg.DoTListen, dot.ListenAndServe)
	}
	if r.cfg.DoHListen != "" {
		hm := http.NewServeMux()
		hm.Handle("/dns-query", r.dohHandler())
		hm.Handle("/dns-query/", r.dohHandler())
		doh := &http.Server{Addr: r.cfg.DoHListen, Handler: hm, TLSConfig: tlsCfg,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		r.mu.Lock()
		r.httpSrv = doh
		r.mu.Unlock()
		start("DoH", r.cfg.DoHListen, func() error { return doh.ListenAndServeTLS("", "") })
	}

	// The first listener to fail stops the process; the caller exits.
	return <-errc
}

func (r *Resolver) track(srvs ...*dns.Server) {
	r.mu.Lock()
	r.dnsSrvs = append(r.dnsSrvs, srvs...)
	r.mu.Unlock()
}

// Shutdown stops every listener and waits for in-flight queries, up to ctx.
func (r *Resolver) Shutdown(ctx context.Context) {
	r.mu.Lock()
	srvs, doh := r.dnsSrvs, r.httpSrv
	r.mu.Unlock()
	for _, s := range srvs {
		_ = s.ShutdownContext(ctx)
	}
	if doh != nil {
		_ = doh.Shutdown(ctx)
	}
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
		if !r.limit.allow(clientIP(hr.RemoteAddr), time.Now()) {
			mDropped.Inc("ratelimited")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		resp := finalize(req, r.answer(req, client{addr: hr.RemoteAddr, token: rest}), false)
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

// clientHost is the address without its port, for the query log.
func clientHost(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().String()
	}
	return addr
}

// forward sends the question upstream, UDP first with TCP fallback on
// truncation. A failing upstream is skipped and the next one tried, so one dead
// resolver does not turn into SERVFAILs. On success the returned message already
// has TTL clamps applied so the cache can reuse it directly.
func (r *Resolver) forward(q *dns.Question, do bool) *dns.Msg {
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{*q}
	req.SetEdns0(ednsSize, do)

	n := len(r.upstreams)
	first := int(r.robin.Add(1))
	for i := 0; i < n; i++ {
		upstream := r.upstreams[(first+i)%n]
		start := time.Now()
		resp, _, err := r.udpClient.Exchange(req, upstream)
		if err == nil && resp != nil && resp.Truncated {
			// UDP answer exceeded size; retry over TCP per standard practice.
			resp, _, err = r.tcpClient.Exchange(req, upstream)
		}
		if err != nil || resp == nil || resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			mUpErrors.Inc(upstream)
			log.Printf("resolver: upstream %s failed for %s: %v", upstream, q.Name, upstreamErr(resp, err))
			continue
		}
		mUpTime.Observe(time.Since(start))
		if r.cfg.Cache.MaxTTL > 0 {
			clampTTLs(resp, r.cfg.Cache.MinTTL, r.cfg.Cache.MaxTTL)
		}
		return resp
	}
	return nil
}

func upstreamErr(resp *dns.Msg, err error) any {
	if err != nil {
		return err
	}
	if resp == nil {
		return "no response"
	}
	return dns.RcodeToString[resp.Rcode]
}

// ednsSize is the EDNS buffer size we advertise and accept: the DNS Flag Day
// 2020 value that avoids IP fragmentation.
const ednsSize = 1232

func isDO(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

// finalize shapes a reply for the client that asked: our own OPT record (never
// the upstream's) when the client used EDNS, and truncation to the client's
// buffer size over UDP so oversized answers set TC and the client retries on TCP.
func finalize(req, resp *dns.Msg, udp bool) *dns.Msg {
	if req == nil || resp == nil {
		return resp
	}
	extra := resp.Extra[:0:0]
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	resp.Extra = extra
	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(ednsSize, opt.Do())
		if s := int(opt.UDPSize()); s > size {
			size = s
		}
		if size > ednsSize {
			size = ednsSize
		}
	}
	if udp {
		resp.Truncate(size)
	}
	return resp
}

// anyReply is the RFC 8482 answer to a qtype ANY query: one synthesized HINFO.
func anyReply(req *dns.Msg, q dns.Question) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.HINFO{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 3600},
		Cpu: "RFC8482",
	}}
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

// redirectReply answers a REDIRECT with the exit's address. IPv4 gets an A
// record pointing at the exit's gateway. Every other type gets an empty
// NOERROR, so IPv6 cannot bypass the exit. The short TTL lets a changed exit
// take effect quickly.
func redirectReply(req *dns.Msg, q dns.Question, answerIP string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	ip := net.ParseIP(answerIP).To4()
	if q.Qtype == dns.TypeA && ip != nil {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		})
	}
	return resp
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
