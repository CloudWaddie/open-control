// Package policy holds the rule engine.
//
// Design contract (PLAN.md §2/§5): the engine returns an abstract Action — the
// resolver never blocks on its own. REDIRECT is a stub until the egress phase,
// but the evaluation flow and this signature are final from day one.
package policy

// Action is what the policy engine decides for a query.
type Action int

const (
	ActionForward  Action = iota // pass to the profile's upstream
	ActionBlock                  // answer NXDOMAIN / noonexistent
	ActionRewrite                // answer from a rewrite rule
	ActionRedirect               // route via egress node (later phase)
)

func (a Action) String() string {
	switch a {
	case ActionBlock:
		return "BLOCK"
	case ActionRewrite:
		return "REWRITE"
	case ActionRedirect:
		return "REDIRECT"
	default:
		return "FORWARD"
	}
}

// Decision is the outcome of evaluating a query against a profile.
type Decision struct {
	Action      Action
	Reason      string // machine-readable cause, e.g. "custom:block:tracker.example", "blocklist:ads.example"
	Target      string // rewrite target, or the exit node's answer IP for REDIRECT
	ExitID      int64  // REDIRECT: the exit node chosen
	ExitName    string // REDIRECT: its name, for logs
	ExitHealthy bool   // REDIRECT: false means the resolver should fall back to forwarding
}

// Engine is the M0 stub: everything forwards, no lists loaded yet.
type Engine struct{}

func New() *Engine { return &Engine{} }

// Evaluate will take (profileID, qname, qtype, clientIP) in M1. The stub keeps
// the call site shape stable so wiring changes then are minimal.
func (e *Engine) Evaluate() Decision {
	return Decision{Action: ActionForward, Reason: "mvp"}
}
