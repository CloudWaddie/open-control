package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

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

	_, err = db.Exec(`INSERT INTO endpoints (org_id, profile_id, token, name, allowed_source_ips) VALUES (?, ?, 'default', 'default', '["0.0.0.0/0"]')`,
		orgID, profileID)
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
// fetch=false reads blocklists from the on-disk cache only (no network), so
// startup never waits on a remote host. fetch=true refreshes them first.
func LoadSnapshot(db DBTX, dataDir string, fetch bool) (*policy.Snapshot, error) {
	blDir := dataDir + "/blocklists"

	// Profiles
	profs := map[int64]*policy.Profile{}
	rows, err := db.Query(`SELECT id, org_id, name FROM profiles`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p policy.Profile
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name); err != nil {
			rows.Close()
			return nil, err
		}
		p.Allow = policy.NewDomainSet()
		p.Block = policy.NewDomainSet()
		p.Blocklists = policy.NewDomainSet()
		p.Rewrites = map[string]policy.RewriteRecord{}
		profs[p.ID] = &p
	}
	rows.Close()

	// Read every source and CLOSE the cursor before doing anything else: the DB
	// pool has one connection, so writing while a cursor is open deadlocks.
	type source struct {
		id, orgID int64
		url       string
	}
	var sources []source
	rows, err = db.Query(`SELECT id, org_id, url FROM blocklist_sources`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s source
		if err := rows.Scan(&s.id, &s.orgID, &s.url); err != nil {
			rows.Close()
			return nil, err
		}
		sources = append(sources, s)
	}
	rows.Close()

	// Each org's lists go only into that org's profiles.
	for _, s := range sources {
		var domains []string
		var err error
		if fetch {
			domains, err = policy.FetchBlocklist(s.url, blDir)
			if err == nil {
				if _, uerr := db.Exec(`UPDATE blocklist_sources SET last_synced = datetime('now') WHERE id = ?`, s.id); uerr != nil {
					log.Printf("policy: record sync time for %s: %v", s.url, uerr)
				}
			}
		} else {
			domains, err = policy.CachedBlocklist(s.url, blDir)
		}
		if err != nil {
			log.Printf("policy: blocklist %s: %v (skipped)", s.url, err)
			continue
		}
		for _, p := range profs {
			if p.OrgID == s.orgID {
				for _, d := range domains {
					p.Blocklists.Add(d, true) // lists block subdomains implicitly
				}
			}
		}
	}

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
			// Egress phase stub — accepted in schema, not compiled yet.
		}
	}
	rows.Close()

	// Endpoints (with source allowlists).
	var eps []*policy.Endpoint
	rows, err = db.Query(`SELECT id, name, profile_id, allowed_source_ips FROM endpoints`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e policy.Endpoint
		var allowed string
		if err := rows.Scan(&e.ID, &e.Name, &e.ProfileID, &allowed); err != nil {
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

	return policy.NewSnapshot(eps, profs), nil
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
	return res.LastInsertId()
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
	if len(list) == 0 {
		return 0, "", fmt.Errorf("endpoint needs at least one CIDR (fail closed otherwise)")
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
	res, err := db.Exec(`INSERT INTO endpoints (org_id, profile_id, token, name, allowed_source_ips)
		SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM profiles WHERE id = ? AND org_id = ?)`,
		org, profileID, token, name, string(raw), profileID, org)
	if err != nil {
		return 0, "", err
	}
	id, err := insertedOrNotFound(res, "profile")
	if err != nil {
		return 0, "", err
	}
	return id, token, nil
}

// AddBlocklistSource subscribes org to a list. Re-subscribing is a no-op.
func AddBlocklistSource(db DBTX, org int64, url, format string) error {
	switch format {
	case "hosts", "dnsmasq", "adguard":
	default:
		return fmt.Errorf("unknown format %q (hosts|dnsmasq|adguard)", format)
	}
	_, err := db.Exec(`INSERT OR IGNORE INTO blocklist_sources (org_id, url, format) VALUES (?, ?, ?)`, org, url, format)
	return err
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
