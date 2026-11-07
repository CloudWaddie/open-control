package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/catalog"
	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// queries.go — org-scoped writes and the resolver snapshot loader.
//
// Every write takes the org explicitly and checks ownership in the same SQL
// statement (INSERT … SELECT … WHERE EXISTS, or DELETE … WHERE org matches), so
// one org can never reference or change another org's rows.

// SeedDefaults creates the first org with a default profile and endpoint so
// the resolver has something to enforce on first run.
func SeedDefaults(db DBTX) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM orgs`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	orgID, err := CreateOrg(db, "default")
	if err != nil {
		return err
	}

	res, err := db.Exec(`INSERT INTO profiles (org_id, name, options) VALUES (?, 'default', '{}')`, orgID)
	if err != nil {
		return err
	}
	profileID, _ := res.LastInsertId()

	// The seeded endpoint is reached by source IP; it also gets a token (now
	// viewable on the endpoints page) so devices can use encrypted DNS against
	// the default profile out of the box.
	secret, err := NewSecret()
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO endpoints (org_id, profile_id, token, token_plain, name, allowed_source_ips) VALUES (?, ?, ?, ?, 'default', '["0.0.0.0/0"]')`,
		orgID, profileID, HashToken(secret), secret)
	if err != nil {
		return err
	}
	log.Printf("store: seeded default org/profile/endpoint (profile_id=%d)", profileID)
	return nil
}

// CreateOrg adds a tenant and returns its id.
func CreateOrg(db DBTX, name string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("org name is required")
	}
	res, err := db.Exec(`INSERT INTO orgs (name) VALUES (?)`, name)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// OrgIDByName resolves an org name to its id.
func OrgIDByName(db DBTX, name string) (int64, error) {
	var id int64
	err := db.QueryRow(`SELECT id FROM orgs WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("org %q: %w", name, ErrNotFound)
	}
	return id, err
}

// DefaultOrgID returns the first org (the seeded one). The CLI operates on it.
func DefaultOrgID(db DBTX) (int64, error) {
	var id int64
	if err := db.QueryRow(`SELECT id FROM orgs ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// LoadSnapshot compiles everything the resolver needs into an immutable
// policy.Snapshot: endpoints, profiles, custom rules and blocklist sources.
// Blocklist contents are read through the ETag file cache; a DB row marks the
// last successful fetch.
//
// mode says when lists go to the network: FetchNone at boot (never wait on a
// remote host), FetchMissing after a settings change (download newly enabled
// lists), FetchAll on the periodic refresh.
func LoadSnapshot(db DBTX, dataDir string, mode policy.FetchMode) (*policy.Snapshot, error) {
	blDir := catalog.CacheDir(dataDir)

	// Profiles
	profs := map[int64]*policy.Profile{}
	rows, err := db.Query(`SELECT id, org_id, name, options FROM profiles`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p policy.Profile
		var opts string
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &opts); err != nil {
			rows.Close()
			return nil, err
		}
		p.Options = parseOptions(opts)
		p.Upstreams, _ = p.Options.Upstreams()
		p.Allow = policy.NewDomainSet()
		p.Block = policy.NewDomainSet()
		p.Rewrites = map[string]policy.RewriteRecord{}
		p.Redirect = policy.NewDomainSet()
		p.RedirectTo = map[string]*policy.Exit{}
		profs[p.ID] = &p
	}
	rows.Close()

	// Exit nodes, by id. Health "down" marks an exit as unusable; anything else
	// is usable (see exits.go).
	exits := map[int64]*policy.Exit{}
	rows, err = db.Query(`SELECT id, name, answer_ip, answer_ipv6, health FROM exit_nodes`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e policy.Exit
		var health string
		if err := rows.Scan(&e.ID, &e.Name, &e.AnswerIP, &e.AnswerIPv6, &health); err != nil {
			rows.Close()
			return nil, err
		}
		e.Healthy = health != "down"
		exits[e.ID] = &e
	}
	rows.Close()

	// Custom rules per profile.
	rows, err = db.Query(`SELECT profile_id, kind, matcher, pattern, answer FROM profile_rules`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var profileID int64
		var kind, matcher, pattern, answer string
		if err := rows.Scan(&profileID, &kind, &matcher, &pattern, &answer); err != nil {
			rows.Close()
			return nil, err
		}
		p, ok := profs[profileID]
		if !ok {
			continue
		}
		// matcher: domain (exact) | wildcard (domain + subdomains) | tld (".xyz")
		sub := matcher != "domain"
		switch kind {
		case "allow":
			p.Allow.Add(pattern, sub)
		case "block":
			p.Block.Add(pattern, sub)
		case "rewrite":
			p.Rewrites[normDomain(pattern)] = policy.RewriteRecord{Target: answer}
		case "redirect":
			exitID, _ := strconv.ParseInt(answer, 10, 64)
			if ex := exits[exitID]; ex != nil {
				p.Redirect.Add(pattern, sub)
				p.RedirectTo[ruleKey(matcher, pattern)] = ex
			}
		}
	}
	rows.Close()

	if err := loadProfileFilters(db, blDir, mode, profs, exits); err != nil {
		return nil, err
	}

	// Endpoints (with source allowlists).
	var eps []*policy.Endpoint
	rows, err = db.Query(`SELECT id, name, profile_id, allowed_source_ips, token, org_id FROM endpoints`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e policy.Endpoint
		var allowed string
		if err := rows.Scan(&e.ID, &e.Name, &e.ProfileID, &allowed, &e.TokenHash, &e.OrgID); err != nil {
			rows.Close()
			return nil, err
		}
		// Fail closed: an unparsable allowlist must never become "accept any".
		cs, err := policy.NewCidrSetFromJSON(allowed)
		if err != nil {
			log.Printf("policy: endpoint %s skipped: bad allowed_source_ips %q: %v", e.Name, allowed, err)
			continue
		}
		e.Allowed = cs
		eps = append(eps, &e)
	}
	rows.Close()

	snap := policy.NewSnapshot(eps, profs)
	// Clients that match no endpoint use the first org's default profile.
	var def sql.NullInt64
	if err := db.QueryRow(`SELECT default_profile_id FROM orgs ORDER BY id LIMIT 1`).Scan(&def); err == nil && def.Valid {
		snap.SetDefault(def.Int64)
	}
	return snap, nil
}

// AddRule inserts a rule into one of org's profiles. pattern is the domain (or
// ".tld"); answer is only used by rewrite rules.
func AddRule(db DBTX, org, profileID int64, kind, matcher, pattern, answer string) (int64, error) {
	switch kind {
	case "block", "allow", "rewrite", "redirect":
	default:
		return 0, fmt.Errorf("unknown rule kind %q", kind)
	}
	switch matcher {
	case "domain", "wildcard", "tld":
	default:
		return 0, fmt.Errorf("unknown matcher %q", matcher)
	}
	if matcher == "tld" {
		pattern = "." + strings.Trim(pattern, ".")
	}
	if pattern == "" || pattern == "." {
		return 0, fmt.Errorf("empty pattern")
	}
	if kind == "rewrite" && (matcher != "domain" || answer == "") {
		return 0, fmt.Errorf("rewrite needs an exact domain and an answer (IP or name)")
	}
	if err := checkUnlocked(db, profileID); err != nil {
		return 0, err
	}
	if kind == "redirect" {
		// For redirect rules, answer holds the exit node id. It must be one of
		// org's exits, checked in the same statement as the profile check.
		exitID, err := strconv.ParseInt(answer, 10, 64)
		if err != nil || exitID <= 0 {
			return 0, fmt.Errorf("redirect needs an exit node id")
		}
		res, err := db.Exec(`INSERT INTO profile_rules (profile_id, kind, matcher, pattern, answer)
			SELECT ?, 'redirect', ?, ?, ? WHERE EXISTS (SELECT 1 FROM profiles WHERE id = ? AND org_id = ?)
			AND EXISTS (SELECT 1 FROM exit_nodes WHERE id = ? AND org_id = ?)`,
			profileID, matcher, pattern, answer, profileID, org, exitID, org)
		if err != nil {
			return 0, err
		}
		return insertedOrNotFound(res, "profile or exit node")
	}
	res, err := db.Exec(`INSERT INTO profile_rules (profile_id, kind, matcher, pattern, answer)
		SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM profiles WHERE id = ? AND org_id = ?)`,
		profileID, kind, matcher, pattern, answer, profileID, org)
	if err != nil {
		return 0, err
	}
	return insertedOrNotFound(res, "profile")
}

// AddProfile creates a profile in org and returns its id.
func AddProfile(db DBTX, org int64, name string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("profile name is required")
	}
	res, err := db.Exec(`INSERT INTO profiles (org_id, name) VALUES (?, ?)`, org, name)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	_, err = db.Exec(`UPDATE orgs SET default_profile_id = ? WHERE id = ? AND default_profile_id IS NULL`, id, org)
	return id, err
}

// AddProfileWithEndpoint creates a profile plus an encrypted-only endpoint of
// the same name, so every profile has its own DoH/DoT address. The endpoint
// token is returned once.
func AddProfileWithEndpoint(db DBTX, org int64, name string) (int64, int64, string, error) {
	id, err := AddProfile(db, org, name)
	if err != nil {
		return 0, 0, "", err
	}
	epID, token, err := AddEndpoint(db, org, name, id, "")
	if err != nil {
		return 0, 0, "", err
	}
	return id, epID, token, nil
}

// AddEndpoint creates an endpoint in org bound to one of org's profiles,
// admitting clients whose source address falls in cidrs (comma-separated IPs
// or prefixes). Returns the endpoint's id and its generated token.
func AddEndpoint(db DBTX, org int64, name string, profileID int64, cidrs string) (int64, string, error) {
	var list []string
	for _, c := range strings.Split(cidrs, ",") {
		if c = strings.TrimSpace(c); c != "" {
			list = append(list, c)
		}
	}
	// No CIDRs means an encrypted-only endpoint: reachable by its DoH/DoT
	// token, never by source address (an empty allowlist matches nothing).
	if list == nil {
		list = []string{}
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return 0, "", err
	}
	if _, err := policy.NewCidrSetFromJSON(string(raw)); err != nil {
		return 0, "", fmt.Errorf("bad CIDR list %q: %w", cidrs, err)
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return 0, "", err
	}
	token := hex.EncodeToString(buf)
	// The token is stored twice: hashed for lookup, plaintext for the pages
	// that show it again (endpoint tokens are device identifiers, not
	// credentials).
	res, err := db.Exec(`INSERT INTO endpoints (org_id, profile_id, token, token_plain, name, allowed_source_ips)
		SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM profiles WHERE id = ? AND org_id = ?)`,
		org, profileID, HashToken(token), token, name, string(raw), profileID, org)
	if err != nil {
		return 0, "", err
	}
	id, err := insertedOrNotFound(res, "profile")
	if err != nil {
		return 0, "", err
	}
	return id, token, nil
}

// AddBlocklistSource subscribes org to a list and turns it on for one profile
// (profileID > 0) or for every profile in the org (0). Re-subscribing is a
// no-op apart from enabling it. Returns the list's id.
func AddBlocklistSource(db DBTX, org int64, url, format string, profileID int64) (int64, error) {
	if profileID > 0 {
		if err := profileInOrg(db, org, profileID); err != nil {
			return 0, err
		}
	}
	switch format {
	case "hosts", "dnsmasq", "adguard":
	default:
		return 0, fmt.Errorf("unknown format %q (hosts|dnsmasq|adguard)", format)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO blocklist_sources (org_id, url, format) VALUES (?, ?, ?)`, org, url, format); err != nil {
		return 0, err
	}
	var id int64
	if err := db.QueryRow(`SELECT id FROM blocklist_sources WHERE org_id = ? AND url = ?`, org, url).Scan(&id); err != nil {
		return 0, err
	}
	_, err := db.Exec(`INSERT OR IGNORE INTO profile_filters (profile_id, kind, ref, state)
		SELECT id, 'list', ?, 'block' FROM profiles WHERE org_id = ? AND (? = 0 OR id = ?)`,
		strconv.FormatInt(id, 10), org, profileID, profileID)
	return id, err
}

// insertedOrNotFound maps a zero-row INSERT…SELECT (the ownership check failed)
// to ErrNotFound, and otherwise returns the new row id.
func insertedOrNotFound(res interface {
	RowsAffected() (int64, error)
	LastInsertId() (int64, error)
}, what string) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("%s not found in this org: %w", what, ErrNotFound)
	}
	return res.LastInsertId()
}

func normDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

// loadProfileFilters attaches enabled filter categories, services and custom
// lists to each profile. Compiled lists are shared between profiles. A list
// that cannot be loaded is skipped with a log line; the rest still apply.
func loadProfileFilters(db DBTX, blDir string, mode policy.FetchMode, profs map[int64]*policy.Profile, exits map[int64]*policy.Exit) error {
	type row struct {
		profile          int64
		kind, ref, state string
		level            string
		exit             int64
	}
	// Read everything and close the cursor before touching the network or
	// writing: the pool has one connection, so an open cursor would deadlock.
	var rowsOut []row
	rows, err := db.Query(`SELECT profile_id, kind, ref, state, level, COALESCE(exit_id, 0) FROM profile_filters`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.profile, &r.kind, &r.ref, &r.state, &r.level, &r.exit); err != nil {
			rows.Close()
			return err
		}
		rowsOut = append(rowsOut, r)
	}
	rows.Close()

	lists := map[string]string{} // blocklist id → url
	rows, err = db.Query(`SELECT id, url FROM blocklist_sources`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var url string
		if err := rows.Scan(&id, &url); err != nil {
			rows.Close()
			return err
		}
		lists[strconv.FormatInt(id, 10)] = url
	}
	rows.Close()

	servicesLoaded := false
	loaded := map[string]*policy.HashSet{}
	load := func(url string, format policy.ListFormat) *policy.HashSet {
		if format == "" {
			format = policy.FormatDomains
		}
		if set, ok := loaded[url]; ok {
			return set // fetch and compile each source once per load, however many profiles use it
		}
		set, err := policy.LoadList(url, blDir, format, mode)
		loaded[url] = set
		if err != nil {
			log.Printf("policy: list %s: %v (skipped)", url, err)
			return nil
		}
		return set
	}

	for _, r := range rowsOut {
		p := profs[r.profile]
		if p == nil {
			continue
		}
		switch r.kind {
		case "filter":
			_, lvl := catalog.FilterByID(r.ref, r.level)
			if lvl == nil {
				continue
			}
			for _, url := range lvl.URLs {
				if set := load(url, lvl.Format); set != nil {
					p.Lists = append(p.Lists, policy.ListRef{Set: set, Reason: "filter:" + r.ref})
				}
			}
		case "list":
			url, ok := lists[r.ref]
			if !ok {
				continue
			}
			if set := load(url, policy.FormatDomains); set != nil {
				p.Lists = append(p.Lists, policy.ListRef{Set: set, Reason: "list:" + r.ref})
			}
		case "service":
			if !servicesLoaded {
				if _, err := catalog.Services(blDir, mode); err != nil {
					log.Printf("policy: %v (services skipped)", err)
				}
				servicesLoaded = true
			}
			_, set := catalog.ServiceSet(blDir, r.ref)
			if set == nil {
				continue
			}
			ref := policy.ListRef{Set: set, Reason: "service:" + r.ref}
			switch r.state {
			case "allow":
				p.ServiceAllow = append(p.ServiceAllow, ref)
			case "block":
				p.ServiceBlock = append(p.ServiceBlock, ref)
			case "redirect":
				if ex := exits[r.exit]; ex != nil {
					p.ServiceRedirect = append(p.ServiceRedirect, policy.ServiceRoute{Set: set, Reason: ref.Reason, Exit: ex})
				}
			}
		}
	}

	// Record when each custom list was last downloaded, for the UI.
	for id, url := range lists {
		if t := policy.ListFetchedAt(url, blDir); !t.IsZero() {
			if _, err := db.Exec(`UPDATE blocklist_sources SET last_synced = ? WHERE id = ?`,
				t.UTC().Format(time.DateTime), id); err != nil {
				log.Printf("policy: record sync time for %s: %v", url, err)
			}
		}
	}
	return nil
}
