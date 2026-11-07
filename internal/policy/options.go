package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Options are a profile's resolver settings. They are stored as JSON on the
// profile; a zero value means "default" for every field.
type Options struct {
	// Answers
	BlockResponse string `json:"block_response,omitempty"` // nxdomain (default) | zero | nodata | refused | custom
	BlockIPv4     string `json:"block_ipv4,omitempty"`     // custom block answer
	BlockIPv6     string `json:"block_ipv6,omitempty"`
	BlockTTL      uint32 `json:"block_ttl,omitempty"`    // default 10 s
	RedirectTTL   uint32 `json:"redirect_ttl,omitempty"` // default 60 s
	BypassTTL     uint32 `json:"bypass_ttl,omitempty"`   // cap for allowed answers; 0 = upstream TTL

	// Content controls
	SafeSearch bool   `json:"safe_search,omitempty"`
	YouTube    string `json:"youtube,omitempty"` // "" | moderate | strict

	// Security
	RebindProtection bool `json:"rebind_protection,omitempty"`
	BlockExfil       bool `json:"block_exfil,omitempty"`

	// Resolution
	Upstream      string `json:"upstream,omitempty"` // "" (server default) | preset id | comma list of host:port
	DisableDNSSEC bool   `json:"disable_dnssec,omitempty"`
	ECS           string `json:"ecs,omitempty"` // "" (off) | client | a CIDR to send instead
	CompatMode    bool   `json:"compat_mode,omitempty"`
	DNS64         bool   `json:"dns64,omitempty"`
	DNS64Prefix   string `json:"dns64_prefix,omitempty"` // default 64:ff9b::/96
	CNAMEFlatten  bool   `json:"cname_flatten,omitempty"`
	DisabledUntil int64  `json:"disabled_until,omitempty"` // unix seconds; filtering paused until then
	Locked        bool   `json:"locked,omitempty"`
	LockMessage   string `json:"lock_message,omitempty"`
}

// Upstream presets offered in the UI. Plain DNS to well-known public resolvers.
var UpstreamPresets = map[string][]string{
	"cloudflare": {"1.1.1.1:53", "1.0.0.1:53"},
	"quad9":      {"9.9.9.9:53", "149.112.112.112:53"},
	"google":     {"8.8.8.8:53", "8.8.4.4:53"},
	"adguard":    {"94.140.14.140:53", "94.140.14.141:53"}, // AdGuard's unfiltered resolvers
}

// Normalize fills defaults and validates. It returns a copy safe to store.
func (o Options) Normalize() (Options, error) {
	switch o.BlockResponse {
	case "", "nxdomain", "zero", "nodata", "refused":
		o.BlockIPv4, o.BlockIPv6 = "", ""
	case "custom":
		if o.BlockIPv4 == "" && o.BlockIPv6 == "" {
			return o, fmt.Errorf("custom block response needs an IPv4 or IPv6 address")
		}
		if o.BlockIPv4 != "" {
			a, err := netip.ParseAddr(o.BlockIPv4)
			if err != nil || !a.Is4() {
				return o, fmt.Errorf("block_ipv4 must be an IPv4 address")
			}
		}
		if o.BlockIPv6 != "" {
			a, err := netip.ParseAddr(o.BlockIPv6)
			if err != nil || !a.Is6() || a.Is4In6() {
				return o, fmt.Errorf("block_ipv6 must be an IPv6 address")
			}
		}
	default:
		return o, fmt.Errorf("block_response must be nxdomain, zero, nodata, refused or custom")
	}
	for name, ttl := range map[string]uint32{"block_ttl": o.BlockTTL, "redirect_ttl": o.RedirectTTL, "bypass_ttl": o.BypassTTL} {
		if ttl > 86400 {
			return o, fmt.Errorf("%s must be at most 86400 seconds", name)
		}
	}
	switch o.YouTube {
	case "", "moderate", "strict":
	default:
		return o, fmt.Errorf("youtube must be moderate or strict")
	}
	if _, err := o.Upstreams(); err != nil {
		return o, err
	}
	if o.ECS != "" && o.ECS != "client" {
		p, err := netip.ParsePrefix(o.ECS)
		if err != nil {
			return o, fmt.Errorf("ecs must be \"client\" or a CIDR like 203.0.113.0/24")
		}
		o.ECS = p.Masked().String()
	}
	if o.DNS64Prefix != "" {
		p, err := netip.ParsePrefix(o.DNS64Prefix)
		if err != nil || !p.Addr().Is6() || p.Bits() != 96 {
			return o, fmt.Errorf("dns64_prefix must be an IPv6 /96, e.g. 64:ff9b::/96")
		}
		o.DNS64Prefix = p.Masked().String()
	}
	o.LockMessage = strings.TrimSpace(o.LockMessage)
	if len(o.LockMessage) > 200 {
		return o, fmt.Errorf("lock message is too long (200 characters max)")
	}
	if !o.Locked {
		o.LockMessage = ""
	}
	return o, nil
}

// Upstreams returns the resolvers this profile forwards to, or nil for the
// server default.
func (o Options) Upstreams() ([]string, error) {
	if o.Upstream == "" {
		return nil, nil
	}
	if p, ok := UpstreamPresets[o.Upstream]; ok {
		return p, nil
	}
	var out []string
	for _, s := range strings.Split(o.Upstream, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap.String())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.AddrPortFrom(a, 53).String())
			continue
		}
		return nil, fmt.Errorf("upstream %q: use a preset or IP[:port] addresses", s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("upstream list is empty")
	}
	return out, nil
}

// Paused reports whether filtering is temporarily disabled at now.
func (o Options) Paused(now time.Time) bool {
	return o.DisabledUntil > now.Unix()
}

func (o Options) TTLBlock() uint32 {
	if o.BlockTTL == 0 {
		return 10
	}
	return o.BlockTTL
}

func (o Options) TTLRedirect() uint32 {
	if o.RedirectTTL == 0 {
		return 60
	}
	return o.RedirectTTL
}

func (o Options) Prefix64() netip.Prefix {
	if o.DNS64Prefix != "" {
		if p, err := netip.ParsePrefix(o.DNS64Prefix); err == nil {
			return p
		}
	}
	return netip.MustParsePrefix("64:ff9b::/96")
}
