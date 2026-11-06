package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// Decision and Action live in policy.go (M0); this file holds the compiled
// snapshot: everything the resolver needs per query, swap-able atomically.

// Endpoint is a named resolver identity bound to a profile.
type Endpoint struct {
	ID        int64
	Name      string
	ProfileID int64
	Allowed   *cidrSet // allowed source networks; nil = accept any
}

// Profile is a compiled policy bundle.
type Profile struct {
	ID         int64
	OrgID      int64
	Name       string
	Allow      *domainSet            // custom BYPASS rules
	Block      *domainSet            // custom BLOCK rules
	Blocklists *domainSet            // union of all org blocklist sources
	Rewrites   map[string]RewriteRecord // exact-domain rewrites
}

type RewriteRecord struct {
	Target string // IP or fqdn, parse at answer time
}

// Snapshot is the immutable compiled state served by the resolver.
type Snapshot struct {
	endpoints []*Endpoint
	profiles  map[int64]*Profile
}

// NewSnapshot assembles an immutable snapshot from loaded endpoints/profiles.
func NewSnapshot(endpoints []*Endpoint, profiles map[int64]*Profile) *Snapshot {
	return &Snapshot{endpoints: endpoints, profiles: profiles}
}

func (s *Snapshot) ProfileForEndpoint(id int64) *Profile {
	return s.profiles[id]
}

// DefaultProfile returns the smallest-ID profile — the seeded org default.
// Used when no endpoint rule matches the client IP.
func (s *Snapshot) DefaultProfile() *Profile {
	var best *Profile
	for _, p := range s.profiles {
		if best == nil || p.ID < best.ID {
			best = p
		}
	}
	return best
}

// Summary is a one-line human description of the compiled snapshot.
func (s *Snapshot) Summary() string {
	defaults := 0
	for _, p := range s.profiles {
		defaults += p.Blocklists.Size() + p.Block.Size() + p.Allow.Size() + len(p.Rewrites)
	}
	return fmt.Sprintf("%d endpoint(s), %d profile(s), %d rule entries", len(s.endpoints), len(s.profiles), defaults)
}

// EndpointForClientIP finds the endpoint whose allowlist matches the client
// source (longest-prefix order as loaded). No match → nil.
func (s *Snapshot) EndpointForClientIP(ip netip.Addr) *Endpoint {
	for _, e := range s.endpoints {
		if e.Allowed == nil || e.Allowed.Match(ip) {
			return e
		}
	}
	return nil
}

// cidrSet is a compiled endpoint source allowlist.
type cidrSet struct {
	prefixes []netip.Prefix
}

func NewCidrSet() *cidrSet { return &cidrSet{} }

func NewCidrSetFromJSON(raw string) (*cidrSet, error) {
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, err
	}
	c := NewCidrSet()
	for _, p := range list {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			// bare IP → /32 or /128
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return nil, err
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		c.prefixes = append(c.prefixes, prefix)
	}
	return c, nil
}

func (c *cidrSet) Match(addr netip.Addr) bool {
	for _, p := range c.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
