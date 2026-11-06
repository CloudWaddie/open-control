package policy

import (
	"crypto/sha256"
	"encoding/hex"
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
	OrgID     int64
	ProfileID int64
	Allowed   *cidrSet // allowed source networks; nil = accept any
	TokenHash string   // HashSecret(token); "" = no token (source-IP only)
}

// HashSecret is the storage form of a bearer-style secret (API token, endpoint
// token). The input is high-entropy random, so a fast hash is appropriate.
func HashSecret(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
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
	byToken   map[string]*Endpoint
	profiles  map[int64]*Profile
}

// NewSnapshot assembles an immutable snapshot from loaded endpoints/profiles.
func NewSnapshot(endpoints []*Endpoint, profiles map[int64]*Profile) *Snapshot {
	s := &Snapshot{endpoints: endpoints, profiles: profiles, byToken: map[string]*Endpoint{}}
	for _, e := range endpoints {
		if e.TokenHash != "" {
			s.byToken[e.TokenHash] = e
		}
	}
	return s
}

// EndpointForToken finds the endpoint a presented DoH/DoT token belongs to.
// The token itself identifies the endpoint, so the source-IP allowlist is not
// consulted: encrypted clients roam between networks. Unknown token → nil.
func (s *Snapshot) EndpointForToken(plain string) *Endpoint {
	if plain == "" {
		return nil
	}
	return s.byToken[HashSecret(plain)]
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

// EndpointForClientIP returns the endpoint whose source allowlist matches the
// client with the most specific (longest) prefix, so a /32 endpoint beats a
// broad /0 one regardless of load order. No match → nil.
func (s *Snapshot) EndpointForClientIP(ip netip.Addr) *Endpoint {
	var best *Endpoint
	bestBits := -1
	for _, e := range s.endpoints {
		bits := 0 // nil allowlist = accept any, least specific
		if e.Allowed != nil {
			bits = e.Allowed.MatchBits(ip)
		}
		if bits > bestBits {
			best, bestBits = e, bits
		}
	}
	if bestBits < 0 {
		return nil
	}
	return best
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

// MatchBits returns the longest matching prefix length for addr, or -1 if none
// matches. An empty allowlist therefore matches nothing (fail closed).
func (c *cidrSet) MatchBits(addr netip.Addr) int {
	best := -1
	for _, p := range c.prefixes {
		if p.Contains(addr) && p.Bits() > best {
			best = p.Bits()
		}
	}
	return best
}
