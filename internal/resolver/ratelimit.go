package resolver

import (
	"net/netip"
	"sync"
	"time"
)

// limiter is a per-client token bucket. IPv6 clients are grouped by /56, the
// usual size of one subscriber's allocation, so rotating addresses inside it
// does not reset the bucket.
type limiter struct {
	rate  float64 // tokens per second
	burst float64

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(qps int) *limiter {
	if qps <= 0 {
		return nil
	}
	return &limiter{rate: float64(qps), burst: float64(2 * qps), buckets: map[netip.Addr]*bucket{}}
}

// allow reports whether a query from addr fits within its budget. A nil
// limiter allows everything.
func (l *limiter) allow(addr netip.Addr, now time.Time) bool {
	if l == nil || !addr.IsValid() {
		return true
	}
	key := limitKey(addr)

	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > time.Minute {
		// Drop buckets that have refilled completely; they carry no state.
		for k, b := range l.buckets {
			if now.Sub(b.last).Seconds()*l.rate >= l.burst {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func limitKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is6() {
		p, _ := addr.Prefix(56)
		return p.Addr()
	}
	return addr
}
