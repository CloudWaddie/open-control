// Package resolver wires miekg/dns into the Open Control serving path:
// UDP/TCP listeners, cache, upstream pool, policy hook.
package resolver

import (
	"log"
	"runtime/debug"
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
	engine    *policy.Engine
	sf        singleflight.Group
	upstreams []string
	robin     atomic.Uint64
	udpClient dns.Client
	tcpClient dns.Client
}

func New(cfg *config.Config) *Resolver {
	return &Resolver{
		cfg:       cfg,
		cache:     cache.New(cfg.Cache.MaxEntries),
		engine:    policy.New(),
		upstreams: cfg.Upstreams,
		udpClient: dns.Client{Net: "udp", Timeout: 3 * time.Second, UDPSize: 4096},
		tcpClient: dns.Client{Net: "tcp", Timeout: 5 * time.Second},
	}
}

// ListenAndServe starts UDP and TCP servers on cfg.Listen and blocks until one
// of them fails exactly once.
func (r *Resolver) ListenAndServe() error {
	errc := make(chan error, 2)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", r.handle)

	udpServer := &dns.Server{Addr: r.cfg.Listen, Net: "udp", Handler: mux, UDPSize: 4096}
	tcpServer := &dns.Server{Addr: r.cfg.Listen, Net: "tcp", Handler: mux}

	go func() {
		log.Printf("resolver: UDP listening on %s", r.cfg.Listen)
		errc <- udpServer.ListenAndServe()
	}()
	go func() {
		log.Printf("resolver: TCP listening on %s", r.cfg.Listen)
		errc <- tcpServer.ListenAndServe()
	}()

	// Block on whichever server exits first with an error.
	return <-errc
}

// Handle is the M0 hot path. Structured so each step maps to a plan phase:
//
//	identify endpoint (M1) -> evaluate policy (M1) -> cache (M0) -> upstream (M0)
func (r *Resolver) handle(w dns.ResponseWriter, req *dns.Msg) {
	clientAddr := "unknown"
	if addr := w.RemoteAddr(); addr != nil {
		clientAddr = addr.String()
	}

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("resolver: panic from client %s: %v\n%s", clientAddr, rec, debug.Stack())
		}
	}()

	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		_ = w.WriteMsg(refusal(req, dns.RcodeNotImplemented))
		return
	}
	q := req.Question[0]
	key := cache.MakeKey(req)

	// Cache: serve the response if we still have it.
	if msg := r.cache.Get(key, req.Id); msg != nil {
		_ = w.WriteMsg(msg)
		return
	}

	// Single in-flight upstream fetch per key, per PLAN.md M0 (recovery).
	v, _, _ := r.sf.Do(key, func() (any, error) {
		return r.forward(&q), nil
	})
	resp, _ := v.(*dns.Msg)
	if resp == nil {
		_ = w.WriteMsg(refusal(req, dns.RcodeServerFailure))
		return
	}

	// We got the upstream answer; cache it (TTL already clamped by forward)
	// and serve.
	ttl := minTTL(resp)
	if ttl > 0 {
		r.cache.Put(key, resp, ttl)
	}
	out := resp.Copy()
	out.Id = req.Id
	_ = w.WriteMsg(out)
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
	m.SetReply(req)
	m.Rcode = code
	return m
}
