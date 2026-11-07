// Package catalog defines the built-in filters and loads the app services
// registry. Every source is a public, actively maintained list downloaded at
// runtime and refreshed with the others; nothing is vendored into this repo.
package catalog

import "github.com/cloudwaddie/opencontrol/internal/policy"

// Filter is a one-click blocklist. Categories ("Ads & Trackers") may offer
// levels; exactly one level is active at a time. Lists are named third-party
// lists offered as-is.
type Filter struct {
	ID          string  `json:"id"`
	Group       string  `json:"group"` // category | list
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Icon        string  `json:"icon"`   // icon name the UI maps to a glyph
	Source      string  `json:"source"` // who maintains the data
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

const (
	nrd        = "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/"
	oneHosts   = "https://raw.githubusercontent.com/badmojr/1Hosts/main/"
	srcHaGeZi  = "HaGeZi DNS Blocklists"
	srcOISD    = "OISD"
	srcPhArmy  = "Phishing Army"
	srcHaGeZiN = "HaGeZi NRD"
)

func one(url string) []Level { return []Level{{ID: "on", Name: "On", URLs: []string{url}}} }

// Filters is the built-in catalog, in display order: categories first, then
// third-party lists.
var Filters = []Filter{
	{
		ID: "ads", Group: "category", Name: "Ads & Trackers", Icon: "eye", Source: srcHaGeZi,
		Description: "Advertising, tracking, analytics and telemetry domains.",
		Levels: []Level{
			{ID: "relaxed", Name: "Relaxed", Note: "Only common ads and trackers. Least likely to break anything.", URLs: []string{hz("light")}},
			{ID: "balanced", Name: "Balanced", Note: "Blocks much more, but keeps common affiliate and email tracking links working.", URLs: []string{hz("multi")}},
			{ID: "strict", Name: "Strict", Note: "Blocks the most, with the highest chance of breaking sites.", URLs: []string{hz("pro.plus")}},
		},
	},
	{
		ID: "malware", Group: "category", Name: "Malware", Icon: "biohazard", Source: srcHaGeZi + " (Threat Intelligence Feeds)",
		Description: "Malware, ransomware, cryptojacking, spyware and command-and-control domains.",
		Levels: []Level{
			{ID: "relaxed", Name: "Relaxed", Note: "Most active threats only.", URLs: []string{hz("tif.mini")}},
			{ID: "balanced", Name: "Balanced", Note: "Recommended.", URLs: []string{hz("tif.medium")}},
			{ID: "strict", Name: "Strict", Note: "Full feed; uses more memory.", URLs: []string{hz("tif")}},
		},
	},
	{
		ID: "phishing", Group: "category", Name: "Phishing", Icon: "fish", Source: srcPhArmy,
		Description: "Sites that impersonate banks, shops and logins to steal credentials.",
		Levels: []Level{
			{ID: "balanced", Name: "Balanced", URLs: []string{"https://phishing.army/download/phishing_army_blocklist.txt"}},
			{ID: "strict", Name: "Strict", Note: "Adds domains with less evidence.", URLs: []string{"https://phishing.army/download/phishing_army_blocklist_extended.txt"}},
		},
	},
	{
		ID: "newdomains", Group: "category", Name: "New Domains", Icon: "sparkles", Source: srcHaGeZiN,
		Description: "Domains registered in the last 7 days. Attackers favour them because they are cheap and throwaway.",
		Levels: []Level{
			{ID: "suspicious", Name: "Suspicious", Note: "Only new domains that look machine-generated.", URLs: []string{nrd + "dga7.txt"}},
			{ID: "all", Name: "All", Note: "Every new domain. Will block some legitimate new sites.", URLs: []string{nrd + "nrd7.txt"}},
		},
	},
	{
		ID: "scams", Group: "category", Name: "Scams & Fakes", Icon: "badge-alert", Source: srcHaGeZi,
		Description: "Fake shops, fake streaming sites, scams and rip-offs.",
		Levels:      one(hz("fake")),
	},
	{
		ID: "adult", Group: "category", Name: "Adult Content", Icon: "eye-off", Source: srcHaGeZi + " / " + srcOISD,
		Description: "Pornography and other sexually explicit sites.",
		Levels: []Level{
			{ID: "balanced", Name: "Balanced", URLs: []string{hz("nsfw")}},
			{ID: "strict", Name: "Strict", Note: "Much larger list.", URLs: []string{"https://nsfw.oisd.nl/domainswild2"}},
		},
	},
	{
		ID: "gambling", Group: "category", Name: "Gambling", Icon: "dices", Source: srcHaGeZi,
		Description: "Casinos, betting and lottery sites.",
		Levels: []Level{
			{ID: "relaxed", Name: "Relaxed", URLs: []string{hz("gambling.mini")}},
			{ID: "balanced", Name: "Balanced", URLs: []string{hz("gambling.medium")}},
			{ID: "strict", Name: "Strict", URLs: []string{hz("gambling")}},
		},
	},
	{
		ID: "social", Group: "category", Name: "Social", Icon: "users", Source: srcHaGeZi,
		Description: "Social networks. To block individual apps, use Services.",
		Levels:      one(hz("social")),
	},
	{
		ID: "piracy", Group: "category", Name: "Torrents & Piracy", Icon: "skull", Source: srcHaGeZi,
		Description: "Torrent trackers and illegal streaming and download sites.",
		Levels:      one(hz("anti.piracy")),
	},
	{
		ID: "vpndns", Group: "category", Name: "VPN & DNS", Icon: "unplug", Source: srcHaGeZi,
		Description: "Encrypted DNS, VPN and proxy services that devices use to get around filtering.",
		Levels: []Level{
			{ID: "dns", Name: "DNS only", Note: "Public encrypted DNS resolvers.", URLs: []string{hz("doh")}},
			{ID: "all", Name: "DNS, VPN & proxies", URLs: []string{hz("doh-vpn-proxy-bypass")}},
		},
	},
	{
		ID: "iot", Group: "category", Name: "IoT Telemetry", Icon: "radio", Source: srcHaGeZi + " (native trackers)",
		Description: "Tracking built into TVs, phones and operating systems: Amazon, Apple, Huawei, LG, Oppo, Roku, Samsung, TikTok, Vivo, Windows and Xiaomi.",
		Levels: []Level{{ID: "on", Name: "On", URLs: []string{
			hz("native.amazon"), hz("native.apple"), hz("native.huawei"), hz("native.lgwebos"),
			hz("native.oppo-realme"), hz("native.roku"), hz("native.samsung"), hz("native.tiktok"),
			hz("native.vivo"), hz("native.winoffice"), hz("native.xiaomi"),
		}}},
	},
	{
		ID: "dyndns", Group: "category", Name: "Dynamic DNS", Icon: "refresh-cw", Source: srcHaGeZi,
		Description: "Dynamic DNS providers, often abused to host phishing and malware.",
		Levels:      one(hz("dyndns")),
	},
	{
		ID: "hosters", Group: "category", Name: "Badware Hosters", Icon: "server-crash", Source: srcHaGeZi,
		Description: "Hosting services that are routinely abused to serve malware.",
		Levels:      one(hz("hoster")),
	},
	{
		ID: "shorteners", Group: "category", Name: "URL Shorteners", Icon: "link", Source: srcHaGeZi,
		Description: "Link shorteners that hide where a link really goes.",
		Levels:      one(hz("urlshortener")),
	},
	{
		ID: "popups", Group: "category", Name: "Pop-up Ads", Icon: "app-window", Source: srcHaGeZi,
		Description: "Pop-up, pop-under and malvertising redirect domains.",
		Levels:      one(hz("popupads")),
	},
	{
		ID: "tlds", Group: "category", Name: "Abused TLDs", Icon: "globe-lock", Source: srcHaGeZi,
		Description: "Whole top-level domains dominated by spam and malware, such as .zip and .mov.",
		Levels:      []Level{{ID: "on", Name: "On", URLs: []string{hz("spam-tlds")}, Format: policy.FormatTLDs}},
	},

	// Third-party lists, offered as their maintainers publish them.
	list("1hosts-lite", "1Hosts Lite", "1Hosts", "Ads and trackers, tuned to avoid breakage.", oneHosts+"Lite/domains.wildcards"),
	list("1hosts-xtra", "1Hosts Xtra", "1Hosts", "Aggressive ads, trackers and annoyances.", oneHosts+"Xtra/domains.wildcards"),
	list("adguard-dns", "AdGuard DNS filter", "AdGuard", "The list behind AdGuard DNS: ads, trackers and malware.", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
	list("hagezi-light", "HaGeZi Light", srcHaGeZi, "Basic protection with minimal breakage.", hz("light")),
	list("hagezi-normal", "HaGeZi Normal", srcHaGeZi, "All-round protection.", hz("multi")),
	list("hagezi-pro", "HaGeZi Pro", srcHaGeZi, "Extended protection.", hz("pro")),
	list("hagezi-proplus", "HaGeZi Pro++", srcHaGeZi, "Maximum protection; expect some breakage.", hz("pro.plus")),
	list("hagezi-ultimate", "HaGeZi Ultimate", srcHaGeZi, "Aggressive protection; expect breakage.", hz("ultimate")),
	list("hagezi-tif", "HaGeZi Threat Intelligence", srcHaGeZi, "Malware, phishing, scams and C2 domains from threat feeds.", hz("tif")),
	list("oisd-small", "OISD Small", srcOISD, "Ads, trackers and malware with near-zero breakage.", "https://small.oisd.nl/domainswild2"),
	list("oisd-big", "OISD Big", srcOISD, "The full OISD blocklist.", "https://big.oisd.nl/domainswild2"),
	list("stevenblack", "StevenBlack Unified", "StevenBlack", "Consolidated hosts file of ads and malware.", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
}

func list(id, name, source, desc, url string) Filter {
	return Filter{ID: id, Group: "list", Name: name, Description: desc, Icon: "shield", Source: source, Levels: one(url)}
}

// DefaultLevel is the level a filter starts at: "balanced" when it has one.
func (f *Filter) DefaultLevel() string {
	for _, l := range f.Levels {
		if l.ID == "balanced" {
			return l.ID
		}
	}
	return f.Levels[0].ID
}

// FilterByID returns the filter and the requested level (the default level
// when levelID is empty or unknown).
func FilterByID(id, levelID string) (*Filter, *Level) {
	for i := range Filters {
		f := &Filters[i]
		if f.ID != id {
			continue
		}
		if levelID == "" {
			levelID = f.DefaultLevel()
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
