package policy

import "strings"

// Evaluate applies PLAN.md §1's evaluation order for one query against a
// profile:
//
//	rewrites → custom allow → blocklists + custom block → redirect → forward
//
// Blocks always precede redirects, so a redirect can never un-block a name.
// The resolver calls this exactly once per client query.
func (s *Snapshot) Evaluate(p *Profile, qname string) Decision {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))

	// 1. Local rewrites / split-DNS entries (exact domains only in M1).
	if rw, ok := p.Rewrites[name]; ok {
		return Decision{Action: ActionRewrite, Reason: "rewrite", Target: rw.Target}
	}

	// 2. Custom allow rules (BYPASS) short-circuit everything block-related.
	if hit, key := p.Allow.Match(name); hit {
		return Decision{Action: ActionForward, Reason: "custom:allow:" + key}
	}

	// 3+4. Blocklists (subscribed sources) and custom block rules. Reason
	// strings distinguish them; the wire behavior is identical (NXDOMAIN).
	if hit, key := p.Blocklists.Match(name); hit {
		return Decision{Action: ActionBlock, Reason: "blocklist:" + key}
	}
	if hit, key := p.Block.Match(name); hit {
		return Decision{Action: ActionBlock, Reason: "custom:block:" + key}
	}

	// 5. Redirect rules: answer with the exit node's address. The resolver
	// falls back to forwarding if that exit is down.
	if hit, key := p.Redirect.Match(name); hit {
		if ex := p.RedirectTo[key]; ex != nil {
			return Decision{
				Action:      ActionRedirect,
				Reason:      "redirect:" + key,
				Target:      ex.AnswerIP,
				ExitID:      ex.ID,
				ExitName:    ex.Name,
				ExitHealthy: ex.Healthy,
			}
		}
	}

	// 6. Default: forward upstream.
	return Decision{Action: ActionForward, Reason: "default"}
}
