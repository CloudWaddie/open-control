// Package cache implements the M0-only resolver cache.
//
// Deliberately minimal (PLAN.md §7): size-capped LRU, TTL floor/ceiling,
// remaining-TTL accounting. No negative caching, no prefetch, no optimistic
// refresh — those arrive only after correctness is proven.
package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// entry is one cached response with its expiry.
type entry struct {
	key      string
	msg      *dns.Msg // TTLs as stored (clamped); adjusted on Get
	expireAt time.Time
}

// Cache is a mutex-protected LRU keyed by (qname, qtype, qclass, DO).
type Cache struct {
	mu    sync.Mutex
	ll    *list.List // front = most recent
	items map[string]*list.Element
	max   int
}

func New(maxEntries int) *Cache {
	if maxEntries <= 0 {
		maxEntries = 65536
	}
	return &Cache{
		ll:    list.New(),
		items: make(map[string]*list.Element, maxEntries),
		max:   maxEntries,
	}
}

// MakeKey builds the cache key from a query message.
func MakeKey(req *dns.Msg) string {
	q := req.Question[0]
	// The DO bit is part of the key in v1 so DNSSEC-aware clients can never be
	// served records computed without it, per decision in PLAN.md M0.
	return q.String() + "|" + isDO(req)
}

func isDO(req *dns.Msg) string {
	for _, extra := range req.Extra {
		if opt, ok := extra.(*dns.OPT); ok && opt.Do() {
			return "1"
		}
	}
	return "0"
}

// Get returns a client-ready copy with TTLs decremented by cache age, or nil
// on miss/expiry.
func (c *Cache) Get(key string, reqID uint16) *dns.Msg {
	c.mu.Lock()
	el, ok := c.items[key]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	c.ll.MoveToFront(el)
	e := el.Value.(*entry)
	remaining := time.Until(e.expireAt)
	c.mu.Unlock()

	if remaining <= 0 {
		c.Delete(key)
		return nil
	}
	msg := e.msg.Copy()
	msg.Id = reqID
	adjustTTLs(msg, uint32(remaining.Seconds()))
	return msg
}

// Put stores a response. TTLs must already be clamped by the caller; the copied
// message loses state specific to one client (Id, RD copy).
func (c *Cache) Put(key string, msg *dns.Msg, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m := msg.Copy()
	m.Id = 0
	e := &entry{key: key, msg: m, expireAt: time.Now().Add(ttl)}
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
	} else {
		if len(c.items) >= c.max {
			oldest := c.ll.Back()
			if oldest != nil {
				c.ll.Remove(oldest)
				delete(c.items, oldest.Value.(*entry).key)
			}
		}
		c.items[key] = c.ll.PushFront(e)
	}
	c.mu.Unlock()
}

// Delete removes a key (used for expired-on-read entries).
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
		delete(c.items, key)
	}
	c.mu.Unlock()
}

func adjustTTLs(msg *dns.Msg, remaining uint32) {
	for _, rr := range append(msg.Answer, append(msg.Ns, msg.Extra...)...) {
		// TTL floor is enforced by the caller at Put time; here we only shrink
		// towards zero as the entry ages.
		if rr.Header().Ttl > remaining {
			rr.Header().Ttl = remaining
		}
	}
}
