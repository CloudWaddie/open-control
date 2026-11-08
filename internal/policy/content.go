package policy

import (
	"math"
	"regexp"
	"strings"
)

// Safe search and YouTube restrictions work the way the providers document:
// the search hostname is answered with a CNAME to the provider's enforced
// "safe" hostname, which the resolver then resolves.

var googleSearch = regexp.MustCompile(`^(www\.)?google\.(com?\.)?[a-z]{2,3}$`)

var safeSearchExact = map[string]string{
	"bing.com":             "strict.bing.com",
	"www.bing.com":         "strict.bing.com",
	"duckduckgo.com":       "safe.duckduckgo.com",
	"www.duckduckgo.com":   "safe.duckduckgo.com",
	"start.duckduckgo.com": "safe.duckduckgo.com",
	"search.brave.com":     "forcesafe.search.brave.com",
	"pixabay.com":          "safesearch.pixabay.com",
	"www.pixabay.com":      "safesearch.pixabay.com",
}

var yandexSearch = regexp.MustCompile(`^(www\.)?yandex\.(ru|com|by|kz|ua|com\.tr)$`)

// youtubeHosts are the names Google lists for DNS-based YouTube restrictions.
var youtubeHosts = map[string]bool{
	"www.youtube.com":          true,
	"m.youtube.com":            true,
	"youtubei.googleapis.com":  true,
	"youtube.googleapis.com":   true,
	"www.youtube-nocookie.com": true,
}

// SafeSearchTarget returns the enforced hostname for name under o, or "".
func SafeSearchTarget(o Options, name string) string {
	if o.YouTube != "" && youtubeHosts[name] {
		if o.YouTube == "strict" {
			return "restrict.youtube.com"
		}
		return "restrictmoderate.youtube.com"
	}
	if !o.SafeSearch {
		return ""
	}
	if t, ok := safeSearchExact[name]; ok {
		return t
	}
	if googleSearch.MatchString(name) {
		return "forcesafesearch.google.com"
	}
	if yandexSearch.MatchString(name) {
		return "familysearch.yandex.ru"
	}
	return ""
}

// registrableLabel is the label a person registers: "example" in
// a.b.example.com, "example" in www.example.co.uk. A rough approximation of
// the public suffix list, good enough for scoring.
func registrableLabel(labels []string) (string, int) {
	n := len(labels)
	if n < 2 {
		return "", -1
	}
	i := n - 2
	if n >= 3 && len(labels[n-1]) == 2 && secondLevel[labels[n-2]] {
		i = n - 3
	}
	return labels[i], i
}

var secondLevel = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true, "edu": true, "ne": true, "or": true}

// LooksLikeExfiltration flags queries shaped like data smuggled through DNS:
// very long names, oversized labels, or long high-entropy subdomains (and
// TXT/NULL lookups of such names, a common payload channel).
func LooksLikeExfiltration(name string, qtype uint16) bool {
	if len(name) > 180 {
		return true
	}
	labels := strings.Split(name, ".")
	_, reg := registrableLabel(labels)
	payloadType := qtype == 16 || qtype == 10 // TXT, NULL
	for i, l := range labels {
		if len(l) > 52 {
			return true
		}
		if i >= reg {
			break // only subdomain labels carry payloads
		}
		if len(l) >= 32 && entropy(l) >= 4.0 {
			return true
		}
		if payloadType && len(l) >= 40 {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
