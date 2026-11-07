package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// ServicesURL is AdGuard's HostlistsRegistry (GPL-3.0): per-app domain rules
// and icons, maintained upstream. It is downloaded at runtime and cached in the
// data dir like any other list.
const ServicesURL = "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/services.json"

// Service is one app or site that can be blocked, allowed or routed through an exit.
type Service struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	IconSVG string `json:"icon_svg"`
	Domains int    `json:"domains"`
	set     *policy.DomainSet
}

// Groups maps registry group ids to display names, in display order.
var Groups = []struct{ ID, Name string }{
	{"social_network", "Social"},
	{"messenger", "Messaging"},
	{"streaming", "Streaming"},
	{"gaming", "Gaming"},
	{"ai", "AI"},
	{"shopping", "Shopping"},
	{"dating", "Dating"},
	{"gambling", "Gambling"},
	{"software", "Software"},
	{"hosting", "Hosting"},
	{"cdn", "CDN"},
	{"privacy", "Privacy"},
}

type registry struct {
	BlockedServices []struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Group   string   `json:"group"`
		IconSVG string   `json:"icon_svg"`
		Rules   []string `json:"rules"`
	} `json:"blocked_services"`
}

var (
	svcMu      sync.Mutex
	svcPath    string
	svcModTime time.Time
	svcList    []*Service
	svcByID    map[string]*Service
)

// Services returns the registry, downloading it according to mode. The parsed
// result is cached until the file on disk changes.
func Services(dir string, mode policy.FetchMode) ([]*Service, error) {
	path, err := policy.FetchFile(ServicesURL, dir, mode)
	if err != nil {
		return nil, fmt.Errorf("services registry: %w", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	svcMu.Lock()
	defer svcMu.Unlock()
	if svcList != nil && path == svcPath && st.ModTime().Equal(svcModTime) {
		return svcList, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var reg registry
	if err := json.Unmarshal(b, &reg); err != nil {
		return nil, fmt.Errorf("services registry: %w", err)
	}
	list := make([]*Service, 0, len(reg.BlockedServices))
	byID := make(map[string]*Service, len(reg.BlockedServices))
	for _, s := range reg.BlockedServices {
		set := policy.NewDomainSet()
		for _, rule := range s.Rules {
			if d := serviceDomain(rule); d != "" {
				set.Add(d, true)
			}
		}
		if set.Size() == 0 {
			continue // only regex/modifier rules, which DNS matching cannot apply
		}
		svc := &Service{ID: s.ID, Name: s.Name, Group: s.Group, IconSVG: s.IconSVG, Domains: set.Size(), set: set}
		list = append(list, svc)
		byID[s.ID] = svc
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	svcList, svcByID, svcPath, svcModTime = list, byID, path, st.ModTime()
	return list, nil
}

// ServiceSet returns the compiled domains of one service, or nil if the
// registry is not loaded or does not know id.
func ServiceSet(dir, id string) (*Service, *policy.DomainSet) {
	if _, err := Services(dir, policy.FetchNone); err != nil {
		return nil, nil
	}
	svcMu.Lock()
	defer svcMu.Unlock()
	s := svcByID[id]
	if s == nil {
		return nil, nil
	}
	return s, s.set
}

// serviceDomain reads the domain out of an AdGuard rule. Only plain
// "||domain^" rules are used; regex and modifier rules are skipped.
func serviceDomain(rule string) string {
	rule = strings.TrimSpace(rule)
	if !strings.HasPrefix(rule, "||") {
		return ""
	}
	rule = strings.TrimPrefix(rule, "||")
	end := strings.IndexAny(rule, "^$")
	if end < 0 {
		return ""
	}
	if rest := rule[end:]; rest != "^" {
		return "" // modifiers such as $important or $dnsrewrite change meaning
	}
	d := strings.ToLower(strings.TrimPrefix(rule[:end], "*."))
	if !strings.Contains(d, ".") || strings.ContainsAny(d, "*/|") {
		return ""
	}
	return d
}

// CacheDir is where lists and the registry are cached under the data dir.
func CacheDir(dataDir string) string { return filepath.Join(dataDir, "blocklists") }
