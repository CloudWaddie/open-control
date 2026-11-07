package policy

import "strings"

// Evaluate applies the evaluation order for one query against a profile:
//
//	rewrites → custom allow → custom block → service allow → service block
//	→ filter categories and lists → custom redirect → service redirect → forward
//
// Explicit rules beat services, services beat lists, and anything that blocks
// beats anything that redirects, so a redirect can never un-block a name. An
// allowed service bypasses the lists, which is how a user un-breaks one app
// without turning a whole category off. The resolver calls this exactly once
// per client query.
func (s *Snapshot) Evaluate(p *Profile, qname string) Decision {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))

	// 1. Local rewrites / split-DNS entries (exact domains only).
	if rw, ok := p.Rewrites[name]; ok {
		return Decision{Action: ActionRewrite, Reason: "rewrite", Target: rw.Target}
	}

	// 2-3. Custom rules.
	if hit, key := p.Allow.Match(name); hit {
		return Decision{Action: ActionForward, Reason: "custom:allow:" + key}
	}
	if hit, key := p.Block.Match(name); hit {
		return Decision{Action: ActionBlock, Reason: "custom:block:" + key}
	}

	// 4-5. Services.
	for _, l := range p.ServiceAllow {
		if hit, _ := l.Set.Match(name); hit {
			return Decision{Action: ActionForward, Reason: l.Reason + ":allow"}
		}
	}
	for _, l := range p.ServiceBlock {
		if hit, _ := l.Set.Match(name); hit {
			return Decision{Action: ActionBlock, Reason: l.Reason}
		}
	}

	// 6. Filter categories and subscribed lists.
	for _, l := range p.Lists {
		if hit, key := l.Set.Match(name); hit {
			return Decision{Action: ActionBlock, Reason: l.Reason + ":" + key}
		}
	}

	// 7-8. Redirects: answer with the exit node's address. The resolver falls
	// back to forwarding if that exit is down.
	if hit, key := p.Redirect.Match(name); hit {
		if ex := p.RedirectTo[key]; ex != nil {
			return redirect("redirect:"+key, ex)
		}
	}
	for _, r := range p.ServiceRedirect {
		if hit, _ := r.Set.Match(name); hit && r.Exit != nil {
			return redirect(r.Reason+":redirect", r.Exit)
		}
	}

	// 9. Default: forward upstream.
	return Decision{Action: ActionForward, Reason: "default"}
}

func redirect(reason string, ex *Exit) Decision {
	return Decision{
		Action:      ActionRedirect,
		Reason:      reason,
		Target:      ex.AnswerIP,
		ExitID:      ex.ID,
		ExitName:    ex.Name,
		ExitHealthy: ex.Healthy,
	}
}
