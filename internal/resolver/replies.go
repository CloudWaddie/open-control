package resolver

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// replies.go — synthesized answers and per-profile answer shaping. The
// decision path in resolver.go picks one of these helpers; everything the
// profile's Options control (block styles, TTLs, compat, DNS64, rebind, ECS)
// is applied here so the serving path stays linear.

// upstreamOpts carries everything an upstream round trip needs from the
// caller's profile: which resolvers to use, whether EDNS DNSSEC OK is set,
// and what ECS to attach.
type upstreamOpts struct {
	ups    []string   // nil → server default upstreams
	do     bool       // EDNS DNSSEC OK bit for the upstream request
	ecs    string     // "" | "client" | fixed CIDR
	client netip.Addr // the asking client, for ecs == "client"
}

// newRequest builds an upstream query for one question.
func newRequest(q *dns.Question, o upstreamOpts) *dns.Msg {
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{*q}
	req.SetEdns0(ednsSize, o.do)
	attachECS(req, q, o.ecs, o.client)
	return req
}

// attachECS adds an EDNS client subnet option when the profile asks for it:
// "client" sends the asking client's address trimmed to /24 (IPv4) or /56
// (IPv6) — enough for CDN locality, vague enough not to identify them — and
// anything else is a fixed CIDR sent on every query. A subnet whose family
// does not match the question is dropped: sending an IPv4 client subnet with
// an AAAA lookup is not what anyone wants.
func attachECS(req *dns.Msg, q *dns.Question, ecs string, client netip.Addr) {
	if ecs == "" {
		return
	}
	var addr netip.Addr
	var bits int
	switch ecs {
	case "client":
		if !client.IsValid() {
			return
		}
		addr = client.Unmap()
		bits = 24
		if addr.Is6() {
			bits = 56
		}
	default:
		p, err := netip.ParsePrefix(ecs)
		if err != nil {
			return
		}
		addr, bits = p.Addr(), p.Bits()
	}
	if (q.Qtype == dns.TypeAAAA) != addr.Is6() {
		return
	}
	opt := req.IsEdns0()
	if opt == nil {
		return
	}
	sub := new(dns.EDNS0_SUBNET)
	sub.Code = dns.EDNS0SUBNET
	sub.Family = 1 // IPv4
	if addr.Is6() {
		sub.Family = 2
	}
	sub.SourceNetmask = uint8(bits)
	// Zero the bits past the prefix length: the wire format has no room for
	// them, and upstreams expect the address already masked.
	sub.Address = netip.PrefixFrom(addr, bits).Masked().Addr().AsSlice()
	opt.Option = append(opt.Option, sub)
}

// blockReply answers a BLOCK decision using the profile's block response
// style (Control D's "Block response" setting): nxdomain by default, or
// 0.0.0.0/::, an empty NOERROR, REFUSED, or custom addresses.
//
// The styles that cannot express an answer for the asked record type (e.g.
// "zero" for a TXT lookup) answer NOERROR without records: NOERROR keeps
// resolvers from retrying other names and says "this name is intercepted".
func blockReply(prof *policy.Profile, req *dns.Msg, q dns.Question) *dns.Msg {
	o := prof.Options
	switch o.BlockResponse {
	case "refused":
		return refusal(req, dns.RcodeRefused)
	case "nodata":
		return emptyReply(req)
	case "zero":
		resp := emptyReply(req)
		ttl := o.TTLBlock()
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.IPv4zero.To4(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: net.IPv6zero,
			})
		}
		return resp
	case "custom":
		switch q.Qtype {
		case dns.TypeA:
			if o.BlockIPv4 != "" {
				if ip := net.ParseIP(o.BlockIPv4).To4(); ip != nil {
					resp := emptyReply(req)
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: o.TTLBlock()},
						A:   ip,
					})
					return resp
				}
			}
		case dns.TypeAAAA:
			if o.BlockIPv6 != "" {
				if ip := net.ParseIP(o.BlockIPv6); ip != nil && ip.To4() == nil {
					resp := emptyReply(req)
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: o.TTLBlock()},
						AAAA: ip,
					})
					return resp
				}
			}
		}
		// Asked type cannot carry the custom address: NODATA mirrors
		// upstreams answering a name they have no record for.
		return emptyReply(req)
	default: // "", "nxdomain"
		return refusal(req, dns.RcodeNameError)
	}
}

// emptyReply is NOERROR with no answer — a NODATA response in its own right.
func emptyReply(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	return resp
}

// redirectReply answers a REDIRECT with the exit's address: A gets the exit's
// IPv4; AAAA gets its IPv6, or — under compat mode with no IPv6 set — the
// NAT64 form of the IPv4 so IPv6-prefering clients still land on the exit.
// Everything else gets an empty NOERROR. The TTL is the profile's redirect
// TTL (short by default) so a changed exit takes effect quickly.
func redirectReply(req *dns.Msg, q dns.Question, answerIP, answerIP6 string, opts policy.Options) *dns.Msg {
	resp := emptyReply(req)
	ttl := opts.TTLRedirect()
	switch q.Qtype {
	case dns.TypeA:
		if ip := net.ParseIP(answerIP).To4(); ip != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip,
			})
		}
	case dns.TypeAAAA:
		switch {
		case answerIP6 != "":
			if ip := net.ParseIP(answerIP6); ip != nil && ip.To4() == nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			}
		case opts.CompatMode && answerIP != "":
			if v4 := net.ParseIP(answerIP).To4(); v4 != nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: nat64IP(opts.Prefix64(), v4),
				})
			}
		}
	}
	return resp
}

// nat64IP widens an IPv4 address into an IPv6 address under a /96 prefix,
// RFC 6052.
func nat64IP(prefix netip.Prefix, v4 net.IP) net.IP {
	pb := prefix.Addr().As16()
	out := make(net.IP, 16)
	copy(out[:12], pb[:12])
	copy(out[12:], v4.To4())
	return out
}

// hasType reports whether the answer holds at least one record of qtype.
func hasType(m *dns.Msg, qtype uint16) bool {
	if m == nil {
		return false
	}
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// postProcess applies per-profile transforms to an upstream answer, in the
// order a recursive resolver would: TTL caps, rebind stripping, flattening,
// then synthesis. It edits msg in place; the caller passes a copy of the
// singleflight result so another profile's view never sees these changes.
func (r *Resolver) postProcess(msg *dns.Msg, q *dns.Question, o upstreamOpts, opts policy.Options) {
	if opts.BypassTTL > 0 {
		capTTLs(msg, opts.BypassTTL)
	}
	if opts.RebindProtection {
		stripRebind(msg)
	}
	if opts.CNAMEFlatten && !hasType(msg, q.Qtype) {
		r.flattenCNAME(msg, q, o)
	}
	if (opts.DNS64 || opts.CompatMode) && q.Qtype == dns.TypeAAAA && hasType(msg, dns.TypeA) && !hasType(msg, dns.TypeAAAA) {
		synthAAAA(msg, opts.Prefix64())
	}
}

// profileKey namespaces a cache/singleflight key per profile so answers
// forwarded or processed differently per profile never cross.
func profileKey(key string, id int64) string {
	if id == 0 {
		return key
	}
	return key + "\x00p" + strconv.FormatInt(id, 10)
}

// stripRebind removes answers that point at private address space — the
// classic rebinding defense. A public name resolving to 10.x or 192.168.x is
// almost always an attacker moving their victim's browser onto their own
// network. Keeps nothing: CNAMEs stay, address records go.
func stripRebind(m *dns.Msg) {
	out := make([]dns.RR, 0, len(m.Answer))
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.A); ok && isBogon(netip.AddrFrom4([4]byte(t.A.To4()))) {
			continue
		}
		if t, ok := rr.(*dns.AAAA); ok && isBogon(netip.AddrFrom16([16]byte(t.AAAA.To16()))) {
			continue
		}
		out = append(out, rr)
	}
	m.Answer = out
}

// isBogon reports whether ip is local or private network space after
// unmapping IPv4-in-IPv6.
func isBogon(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// capTTLs lowers any TTL above cap without touching short ones — the
// bypass_ttl ceiling for allowed answers.
func capTTLs(m *dns.Msg, max uint32) {
	for _, rr := range m.Answer {
		if rr.Header().Ttl > max {
			rr.Header().Ttl = max
		}
	}
}

// synthAAAA implements DNS64 / compat-mode AAAA synthesis: an AAAA query
// whose answer only has A records gets one AAAA per A, built under the
// profile's /96 prefix. Owner names are copied from the A records so CNAME
// chains keep pointing correctly.
func synthAAAA(m *dns.Msg, prefix netip.Prefix) {
	var extra []dns.RR
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.A); ok {
			extra = append(extra, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: t.Hdr.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: t.Hdr.Ttl},
				AAAA: nat64IP(prefix, t.A),
			})
		}
	}
	m.Answer = append(m.Answer, extra...)
}

// flattenCNAME walks CNAME chains in the answer, resolving each unseen target
// through the same upstreams (up to 8 hops) and splicing the final records
// in. With flattening on, the client gets the plain address records and never
// the CNAMEs. A hop that fails upstream leaves the answer exactly as the
// upstream sent it — flattening must never make an answer worse, only flatter.
func (r *Resolver) flattenCNAME(m *dns.Msg, q *dns.Question, o upstreamOpts) {
	ups := o.ups
	if len(ups) == 0 {
		ups = r.upstreams
	}
	seen := map[string]bool{strings.ToLower(strings.TrimSuffix(q.Name, ".")): true}
	orig := m.Answer
	var flats []dns.RR
	for hop := 0; hop < 8; hop++ {
		var targets []string
		for _, rr := range orig {
			if c, ok := rr.(*dns.CNAME); ok {
				key := strings.ToLower(strings.TrimSuffix(c.Target, "."))
				if !seen[key] {
					seen[key] = true
					targets = append(targets, c.Target)
				}
			}
		}
		if len(targets) == 0 && flats == nil {
			return // no CNAMEs beyond the original question: nothing to do
		}
		if len(targets) == 0 {
			break
		}
		for _, t := range targets {
			nq := &dns.Question{Name: dns.Fqdn(t), Qtype: q.Qtype, Qclass: dns.ClassINET}
			resp := r.exchange(newRequest(nq, o), nq, ups)
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				return // chain unresolved: keep the upstream's own answer
			}
			for _, rr := range resp.Answer {
				if _, isCNAME := rr.(*dns.CNAME); isCNAME {
					continue // collected on the next hop instead
				}
				flats = append(flats, rr)
			}
		}
	}
	if len(flats) > 0 {
		m.Answer = flats
	}
}
