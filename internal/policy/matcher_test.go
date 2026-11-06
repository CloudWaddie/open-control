package policy

import "testing"

func TestDomainSetSemantics(t *testing.T) {
	s := NewDomainSet()
	s.Add("exact.example", false)
	s.Add("wild.example", true)
	s.Add(".xyz", false) // TLD rule; sub flag ignored, always wildcard

	cases := []struct {
		q    string
		want bool
		note string
	}{
		{"exact.example.", true, "exact matches itself"},
		{"sub.exact.example", false, "exact does not cover subdomains"},
		{"wild.example", true, "wildcard matches itself"},
		{"a.b.wild.example", true, "wildcard covers deep subdomains"},
		{"example", false, "parent of exact is not matched"},
		{"foo.xyz", true, "TLD rule matches a domain under it"},
		{"a.b.foo.xyz", true, "TLD rule matches deep names"},
		{"xyz", true, "TLD rule also covers the bare TLD apex"},
		{"unrelated.org", false, "no entry"},
		{"WILD.Example.", true, "case-insensitive"},
	}
	for _, c := range cases {
		got, key := s.Match(c.q)
		if got != c.want {
			t.Errorf("%s: Match(%q) = %v (key %q), want %v", c.note, c.q, got, key, c.want)
		}
	}
}

func TestWildcardBeatsExact(t *testing.T) {
	s := NewDomainSet()
	s.Add("x.example", false)
	s.Add("x.example", true)
	if hit, _ := s.Match("sub.x.example"); !hit {
		t.Fatal("wildcard should win over earlier exact entry")
	}
}
