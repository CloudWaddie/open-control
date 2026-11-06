// Package policy implements the rule engine per PLAN.md §1/§2.
//
// This file: domain matching semantics. One structure serves allow, block and
// blocklist lookups. Entries are one of:
//
//	domain    — exact only: matches example.com, not sub.example.com
//	wildcard  — matches example.com AND every sub.example.com
//	.tld      — matches every domain under the TLD (stored as ".xyz")
//
// Lookups cost one map probe per label (typical: 3-4) — no trie needed until
// benchmarks (PLAN.md §7) say otherwise.
package policy

import "strings"

type matchKind uint8

const (
	kindExact    matchKind = 1
	kindWildcard matchKind = 2
)

type domainSet struct {
	m map[string]matchKind
}

// NewDomainSet builds an empty set.
func NewDomainSet() *domainSet { return &domainSet{m: make(map[string]matchKind)} }

// Add inserts a rule. A leading "." marks a TLD rule (always wildcard).
// When the same key is added as exact and wildcard, wildcard wins.
func (s *domainSet) Add(domain string, sub bool) {
	raw := strings.ToLower(strings.TrimSpace(domain))
	kind := kindExact
	if sub {
		kind = kindWildcard
	}
	if strings.HasPrefix(raw, ".") {
		key := "." + strings.Trim(raw, ".")
		if key == "." {
			return
		}
		s.m[key] = kindWildcard
		return
	}
	key := strings.Trim(raw, ".")
	if key == "" {
		return
	}
	if s.m[key] < kind {
		s.m[key] = kind
	}
}

// Size returns the number of stored entries.
func (s *domainSet) Size() int { return len(s.m) }

// Match reports whether qname is covered by the set, and which key matched.
func (s *domainSet) Match(qname string) (bool, string) {
	if s == nil {
		return false, ""
	}
	d := strings.ToLower(strings.TrimSuffix(qname, "."))
	if d == "" {
		return false, ""
	}
	first := true
	for {
		k := s.m[d]
		// The query name itself can match an exact or wildcard entry; parent
		// names can only match wildcard entries.
		if k == kindWildcard || (first && k == kindExact) {
			return true, d
		}
		first = false
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			// Last label: check whole-TLD rules stored as "." + tld.
			if s.m["."+d] == kindWildcard {
				return true, "." + d
			}
			return false, ""
		}
		d = d[idx+1:]
	}
}
