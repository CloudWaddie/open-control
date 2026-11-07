package policy

import (
	"strings"
	"testing"
	"time"
)

func TestSafeSearchTargets(t *testing.T) {
	on := Options{SafeSearch: true, YouTube: "strict"}
	cases := map[string]string{
		"www.google.com":       "forcesafesearch.google.com",
		"google.co.uk":         "forcesafesearch.google.com",
		"www.google.com.au":    "forcesafesearch.google.com",
		"www.bing.com":         "strict.bing.com",
		"duckduckgo.com":       "safe.duckduckgo.com",
		"yandex.ru":            "familysearch.yandex.ru",
		"search.brave.com":     "forcesafe.search.brave.com",
		"www.youtube.com":      "restrict.youtube.com",
		"m.youtube.com":        "restrict.youtube.com",
		"mail.google.com":      "",
		"googleapis.com":       "",
		"notgoogle.com":        "",
		"maps.google.com":      "",
		"www.youtube.com.evil": "",
	}
	for name, want := range cases {
		if got := SafeSearchTarget(on, name); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
	if got := SafeSearchTarget(Options{YouTube: "moderate"}, "www.youtube.com"); got != "restrictmoderate.youtube.com" {
		t.Errorf("moderate youtube: %q", got)
	}
	if got := SafeSearchTarget(Options{}, "www.google.com"); got != "" {
		t.Errorf("safe search off still rewrote: %q", got)
	}
}

func TestLooksLikeExfiltration(t *testing.T) {
	bad := []string{
		"aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQgZGF0YQ.x.attacker.com",
		"a." + string(make([]byte, 0)) + "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghij.evil.com",
	}
	for _, d := range bad {
		if !LooksLikeExfiltration(d, 1) {
			t.Errorf("missed %s", d)
		}
	}
	ok := []string{"www.example.com", "d1a2b3c4d5e6f7.cloudfront.net", "r3---sn-ab5l6nzr.googlevideo.com", "_dmarc.example.com"}
	for _, d := range ok {
		if LooksLikeExfiltration(d, 1) {
			t.Errorf("flagged %s", d)
		}
	}
	if !LooksLikeExfiltration("0123456789abcdef0123456789abcdef0123456789.t.example.com", 16) {
		t.Error("long TXT payload label not flagged")
	}
}

func TestEvaluateOptionsOrder(t *testing.T) {
	p := &Profile{
		ID: 1, Allow: NewDomainSet(), Block: NewDomainSet(), Redirect: NewDomainSet(),
		Rewrites: map[string]RewriteRecord{}, RedirectTo: map[string]*Exit{},
		Options: Options{SafeSearch: true, YouTube: "strict", BlockExfil: true},
	}
	yt := NewDomainSet()
	yt.Add("youtube.com", true)
	p.ServiceAllow = []ListRef{{Set: yt, Reason: "service:youtube"}}
	s := NewSnapshot(nil, map[int64]*Profile{1: p})
	now := time.Unix(1_000_000, 0)

	if d := s.EvaluateQuery(p, "www.youtube.com", 1, now); d.Action != ActionRewrite || d.Target != "restrict.youtube.com" {
		t.Errorf("allowed YouTube lost restricted mode: %+v", d)
	}
	exfil := strings.Repeat("ab12", 15) + ".x.attacker.com" // a 60-character label
	if d := s.EvaluateQuery(p, exfil, 1, now); d.Action != ActionBlock || d.Reason != "heuristic:exfiltration" {
		t.Errorf("heuristic: %+v", d)
	}
	p.Options.DisabledUntil = now.Add(time.Minute).Unix()
	if d := s.EvaluateQuery(p, exfil, 1, now); d.Action != ActionForward || d.Reason != "paused" {
		t.Errorf("paused profile still filtered: %+v", d)
	}
	if d := s.EvaluateQuery(p, exfil, 1, now.Add(2*time.Minute)); d.Action != ActionBlock {
		t.Errorf("pause did not expire: %+v", d)
	}
}

func TestOptionsNormalize(t *testing.T) {
	bad := []Options{
		{BlockResponse: "teapot"},
		{BlockResponse: "custom"},
		{BlockResponse: "custom", BlockIPv4: "::1"},
		{BlockTTL: 100000},
		{YouTube: "lax"},
		{Upstream: "not an ip"},
		{ECS: "nope"},
		{DNS64Prefix: "64:ff9b::/64"},
	}
	for _, o := range bad {
		if _, err := o.Normalize(); err == nil {
			t.Errorf("%+v: accepted", o)
		}
	}
	o, err := Options{Upstream: "9.9.9.9, 1.1.1.1:5353", ECS: "203.0.113.77/24", LockMessage: "x"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	ups, _ := o.Upstreams()
	if len(ups) != 2 || ups[0] != "9.9.9.9:53" || o.ECS != "203.0.113.0/24" || o.LockMessage != "" {
		t.Errorf("normalized: %+v %v", o, ups)
	}
}
