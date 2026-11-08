package policy

import (
	"strings"
	"testing"
)

func TestHashSetMatching(t *testing.T) {
	s := parseList(strings.NewReader("# comment\n0.0.0.0 ads.example\n||tracker.example^\n*.wild.example\nplain.example\n"), FormatDomains)
	if s.Size() != 4 {
		t.Fatalf("size %d, want 4", s.Size())
	}
	cases := map[string]string{
		"ads.example":      "ads.example",
		"x.y.ads.example.": "ads.example",
		"TRACKER.example":  "tracker.example",
		"a.wild.example":   "wild.example",
		"plain.example":    "plain.example",
		"notads.example":   "",
		"example":          "",
		"ads.example.evil": "",
	}
	for name, want := range cases {
		hit, key := s.Match(name)
		if (want != "") != hit || key != want {
			t.Errorf("%s: got %v %q, want %q", name, hit, key, want)
		}
	}

	tlds := parseList(strings.NewReader("zip\n# x\nmov\n"), FormatTLDs)
	if hit, key := tlds.Match("evil.zip"); !hit || key != ".zip" {
		t.Errorf("tld: %v %q", hit, key)
	}
	if hit, _ := tlds.Match("zip.example"); hit {
		t.Error("tld rule matched a non-final label")
	}
}

func BenchmarkHashSetMatch(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 500000; i++ {
		sb.WriteString("d")
		sb.WriteString(strings.Repeat("x", i%7))
		sb.WriteString(string(rune('a' + i%26)))
		sb.WriteString(".example")
		sb.WriteString(string(rune('0' + i%10)))
		sb.WriteString(".com\n")
	}
	s := parseList(strings.NewReader(sb.String()), FormatDomains)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Match("cdn.static.www.example.org")
	}
}
