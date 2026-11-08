package policy

import (
	"slices"
	"strings"
)

// Matcher is what a list reference tests names against: the compact HashSet
// for downloaded lists, or a domainSet for small hand-built sets (services).
type Matcher interface {
	Match(qname string) (bool, string)
	Size() int
}

// HashSet is a read-only, memory-compact set of wildcard domain entries:
// a sorted slice of 64-bit FNV-1a hashes, 8 bytes per domain instead of the
// ~60 a map entry costs. Lists hold millions of domains, so this matters.
// With a few million entries and a handful of lookups per query, the chance
// of a hash collision causing a false match is around 1e-12 per query.
//
// Every entry matches the domain and all its subdomains, the way blocklists
// are meant. TLD entries are stored as ".tld".
type HashSet struct {
	h []uint64
}

func newHashSet(hashes []uint64) *HashSet {
	slices.Sort(hashes)
	return &HashSet{h: slices.Compact(hashes)}
}

// Size returns the number of distinct entries.
func (s *HashSet) Size() int {
	if s == nil {
		return 0
	}
	return len(s.h)
}

func (s *HashSet) has(key string) bool {
	_, ok := slices.BinarySearch(s.h, fnv64(key))
	return ok
}

// Match reports whether qname or any parent domain is in the set, and which.
func (s *HashSet) Match(qname string) (bool, string) {
	if s == nil || len(s.h) == 0 {
		return false, ""
	}
	d := strings.ToLower(strings.TrimSuffix(qname, "."))
	for d != "" {
		if s.has(d) {
			return true, d
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			if s.has("." + d) {
				return true, "." + d
			}
			return false, ""
		}
		d = d[i+1:]
	}
	return false, ""
}

func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
