// Package metrics exposes counters in the Prometheus text format without
// pulling in the Prometheus client library. Only what the resolver and control
// plane need: labelled counters, gauges read at scrape time, and a latency
// histogram.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mu       sync.Mutex
	counters = map[string]*CounterVec{}
	gauges   = map[string]gauge{}
	hists    = map[string]*Histogram{}
	start    = time.Now()
)

// CounterVec is a counter family keyed by one label.
type CounterVec struct {
	name, help, label string
	vals              sync.Map // label value → *atomic.Uint64
}

// NewCounter registers a counter family. label may be "" for a plain counter.
func NewCounter(name, help, label string) *CounterVec {
	c := &CounterVec{name: name, help: help, label: label}
	mu.Lock()
	counters[name] = c
	mu.Unlock()
	return c
}

// Inc adds one to the series for value.
func (c *CounterVec) Inc(value string) { c.Add(value, 1) }

// Add adds n to the series for value.
func (c *CounterVec) Add(value string, n uint64) {
	v, ok := c.vals.Load(value)
	if !ok {
		v, _ = c.vals.LoadOrStore(value, new(atomic.Uint64))
	}
	v.(*atomic.Uint64).Add(n)
}

// Get returns the current value of one series (for tests).
func (c *CounterVec) Get(value string) uint64 {
	if v, ok := c.vals.Load(value); ok {
		return v.(*atomic.Uint64).Load()
	}
	return 0
}

type gauge struct {
	help string
	fn   func() float64
}

// NewGauge registers a gauge whose value is read at scrape time.
func NewGauge(name, help string, fn func() float64) {
	mu.Lock()
	gauges[name] = gauge{help, fn}
	mu.Unlock()
}

// Histogram tracks a latency distribution in seconds.
type Histogram struct {
	name, help string
	bounds     []float64
	buckets    []atomic.Uint64
	count      atomic.Uint64
	sumMicros  atomic.Uint64
}

// NewHistogram registers a histogram with the given upper bounds (seconds).
func NewHistogram(name, help string, bounds []float64) *Histogram {
	h := &Histogram{name: name, help: help, bounds: bounds, buckets: make([]atomic.Uint64, len(bounds))}
	mu.Lock()
	hists[name] = h
	mu.Unlock()
	return h
}

// Observe records one duration.
func (h *Histogram) Observe(d time.Duration) {
	s := d.Seconds()
	for i, b := range h.bounds {
		if s <= b {
			h.buckets[i].Add(1)
		}
	}
	h.count.Add(1)
	h.sumMicros.Add(uint64(d.Microseconds()))
}

func init() {
	NewGauge("opencontrol_uptime_seconds", "Seconds since the process started.", func() float64 {
		return time.Since(start).Seconds()
	})
	NewGauge("opencontrol_goroutines", "Number of goroutines.", func() float64 {
		return float64(runtime.NumGoroutine())
	})
	NewGauge("opencontrol_heap_bytes", "Bytes of allocated heap objects.", func() float64 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc)
	})
}

// Write renders every registered metric.
func Write(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()

	for _, name := range sortedKeys(counters) {
		c := counters[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, c.help, name)
		var labels []string
		c.vals.Range(func(k, _ any) bool { labels = append(labels, k.(string)); return true })
		sort.Strings(labels)
		for _, l := range labels {
			v, _ := c.vals.Load(l)
			if c.label == "" {
				fmt.Fprintf(w, "%s %d\n", name, v.(*atomic.Uint64).Load())
			} else {
				fmt.Fprintf(w, "%s{%s=%q} %d\n", name, c.label, l, v.(*atomic.Uint64).Load())
			}
		}
	}
	for _, name := range sortedKeys(gauges) {
		g := gauges[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", name, g.help, name, name, num(g.fn()))
	}
	for _, name := range sortedKeys(hists) {
		h := hists[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, h.help, name)
		for i, b := range h.bounds {
			fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, num(b), h.buckets[i].Load())
		}
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, h.count.Load())
		fmt.Fprintf(w, "%s_sum %s\n%s_count %d\n", name, num(float64(h.sumMicros.Load())/1e6), name, h.count.Load())
	}
}

// Handler serves /metrics.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		Write(w)
	})
}

func num(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return fmt.Sprintf("%d", int64(f))
	}
	return strings.TrimRight(fmt.Sprintf("%f", f), "0")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
