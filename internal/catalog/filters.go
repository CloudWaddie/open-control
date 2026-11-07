// Package catalog defines the built-in filter categories and loads the app
// services registry. Both point at public, actively maintained sources that
// are downloaded at runtime and refreshed with the other lists; nothing from
// them is vendored into this repository.
package catalog

import "github.com/cloudwaddie/opencontrol/internal/policy"

// Filter is a one-click category ("Ads & trackers", "Adult content"). A filter
// with several levels lets the user pick how aggressive it is; exactly one
// level is active at a time.
type Filter struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Icon        string  `json:"icon"` // icon name the UI maps to a glyph
	Levels      []Level `json:"levels"`
}

type Level struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Note   string            `json:"note,omitempty"`
	URLs   []string          `json:"-"`
	Format policy.ListFormat `json:"-"`
}

const hagezi = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"

func hz(name string) string { return hagezi + name + "-onlydomains.txt" }

// Filters is the built-in category catalog, in display order. Sources:
// HaGeZi DNS blocklists (GPL-3.0, github.com/hagezi/dns-blocklists), OISD
// (oisd.nl) and Phishing Army (phishing.army).
var Filters = []Filter{
	{
		ID: "ads", Name: "Ads & trackers", Icon: "megaphone",
		Description: "Advertising, tracking, analytics and telemetry domains.",
		Levels: []Level{
			{ID: "light", Name: "Light", Note: "Rarely breaks anything", URLs: []string{hz("light")}},
			{ID: "normal", Name: "Normal", Note: "Recommended", URLs: []string{hz("multi")}},
			{ID: "pro", Name: "Pro", Note: "Stricter, occasional breakage", URLs: []string{hz("pro")}},
			{ID: "proplus", Name: "Pro++", Note: "Aggressive, expect breakage", URLs: []string{hz("pro.plus")}},
			{ID: "oisd", Name: "OISD Big", Note: "Alternative maintainer", URLs: []string{"https://big.oisd.nl/domainswild2"}},
		},
	},
	{
		ID: "malware", Name: "Malware & phishing", Icon: "bug",
		Description: "Malware, phishing, scam, cryptojacking and command-and-control domains from threat intelligence feeds.",
		Levels: []Level{
			{ID: "medium", Name: "Standard", Note: "Recommended", URLs: []string{hz("tif.medium"), "https://phishing.army/download/phishing_army_blocklist.txt"}},
			{ID: "full", Name: "Full", Note: "Largest feed, uses more memory", URLs: []string{hz("tif")}},
		},
	},
	{
		ID: "fakes", Name: "Scams & fake shops", Icon: "badge-alert",
		Description: "Fake stores, fake streaming sites, scam and rip-off domains.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("fake")}}},
	},
	{
		ID: "adult", Name: "Adult content", Icon: "eye-off",
		Description: "Pornography and other sexually explicit sites.",
		Levels: []Level{
			{ID: "standard", Name: "Standard", URLs: []string{hz("nsfw")}},
			{ID: "strict", Name: "Strict", Note: "Larger list", URLs: []string{"https://nsfw.oisd.nl/domainswild2"}},
		},
	},
	{
		ID: "gambling", Name: "Gambling", Icon: "dices",
		Description: "Casinos, betting and lottery sites.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("gambling")}}},
	},
	{
		ID: "social", Name: "Social networks", Icon: "users",
		Description: "Social media sites. Use Services to block individual apps instead.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("social")}}},
	},
	{
		ID: "piracy", Name: "Piracy", Icon: "skull",
		Description: "Torrent trackers, illegal streaming and download sites.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("anti.piracy")}}},
	},
	{
		ID: "popups", Name: "Pop-up ads", Icon: "app-window",
		Description: "Pop-up, pop-under and malvertising redirect domains.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("popupads")}}},
	},
	{
		ID: "bypass", Name: "Filter bypass", Icon: "unplug",
		Description: "Public encrypted DNS, VPN and proxy services that devices use to get around filtering.",
		Levels: []Level{
			{ID: "doh", Name: "Encrypted DNS only", URLs: []string{hz("doh")}},
			{ID: "full", Name: "DNS, VPN & proxies", URLs: []string{hz("doh-vpn-proxy-bypass")}},
		},
	},
	{
		ID: "dyndns", Name: "Dynamic DNS", Icon: "refresh-cw",
		Description: "Dynamic DNS providers, often abused to host malware.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("dyndns")}}},
	},
	{
		ID: "shorteners", Name: "URL shorteners", Icon: "link",
		Description: "Link shorteners that hide where a link really goes.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("urlshortener")}}},
	},
	{
		ID: "spamtlds", Name: "Abused TLDs", Icon: "globe-lock",
		Description: "Whole top-level domains dominated by spam and malware (for example .zip, .mov).",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("spam-tlds")}, Format: policy.FormatTLDs}},
	},
}

// FilterByID returns the filter and the requested level (the first level when
// levelID is empty or unknown).
func FilterByID(id, levelID string) (*Filter, *Level) {
	for i := range Filters {
		f := &Filters[i]
		if f.ID != id {
			continue
		}
		for j := range f.Levels {
			if f.Levels[j].ID == levelID {
				return f, &f.Levels[j]
			}
		}
		return f, &f.Levels[0]
	}
	return nil, nil
}

// HasLevel reports whether a filter defines levelID.
func (f *Filter) HasLevel(levelID string) bool {
	for _, l := range f.Levels {
		if l.ID == levelID {
			return true
		}
	}
	return false
}
