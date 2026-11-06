package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// queries.go — data access used by the resolver snapshot loader and the admin
// CLI. The control-plane API (M2) will re-use these through its own layer.

// SeedDefaults creates org/profile/endpoint rows on first run so the resolver
// has something to enforce immediately.
func SeedDefaults(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM orgs`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	res, err := db.Exec(`INSERT INTO orgs (name) VALUES ('default')`)
	if err != nil {
		return err
	}
	orgID, _ := res.LastInsertId()

	res, err = db.Exec(`INSERT INTO profiles (org_id, name, options) VALUES (?, 'default', '{}')`, orgID)
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

// DefaultOrgID returns the seeded org (first row).
func DefaultOrgID(db *sql.DB) (int64, error) {
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
func LoadSnapshot(db *sql.DB, dataDir string) (*policy.Snapshot, error) {
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

	// Blocklist sources, per org: fetch (cache-aware) and union into that
	// org's compiled domain set.
	rows, err = db.Query(`SELECT id, org_id, url, format FROM blocklist_sources`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, orgID int64
		var url, format string
		if err := rows.Scan(&id, &orgID, &url, &format); err != nil {
			rows.Close()
			return nil, err
		}
		domains, err := policy.FetchBlocklist(url, blDir)
		if err != nil {
			log.Printf("policy: blocklist %s: %v (skipped)", url, err)
			continue
		}
		for _, p := range profs {
			if p.OrgID == orgID {
				for _, d := range domains {
					p.Blocklists.Add(d, true) // lists block subdomains implicitly
				}
			}
		}
		if _, err := db.Exec(`UPDATE blocklist_sources SET last_synced = datetime('now'), etag = substr(hex(randomblob(8)), 1, 16) WHERE id = ?`, id); err != nil {
			return nil, err
		}
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

// AddRule inserts a custom rule row (admin CLI for M1; M2 gets the API+UI).
// pattern is the domain (or ".tld"); answer is only used by rewrite rules.
func AddRule(db *sql.DB, profileID int64, kind, matcher, pattern, answer string) error {
	switch kind {
	case "block", "allow", "rewrite", "redirect":
	default:
		return fmt.Errorf("unknown rule kind %q", kind)
	}
	switch matcher {
	case "domain", "wildcard", "tld":
	default:
		return fmt.Errorf("unknown matcher %q", matcher)
	}
	if matcher == "tld" {
		pattern = "." + strings.Trim(pattern, ".")
	}
	if pattern == "" || pattern == "." {
		return fmt.Errorf("empty pattern")
	}
	if kind == "rewrite" && (matcher != "domain" || answer == "") {
		return fmt.Errorf("rewrite needs an exact domain and an answer (IP or name)")
	}
	_, err := db.Exec(`INSERT INTO profile_rules (profile_id, kind, matcher, pattern, answer) VALUES (?, ?, ?, ?, ?)`,
		profileID, kind, matcher, pattern, answer)
	return err
}

// AddProfile creates a profile on the default org and returns its id.
func AddProfile(db *sql.DB, name string) (int64, error) {
	orgID, err := DefaultOrgID(db)
	if err != nil {
		return 0, fmt.Errorf("no org: %w", err)
	}
	res, err := db.Exec(`INSERT INTO profiles (org_id, name) VALUES (?, ?)`, orgID, name)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AddEndpoint creates an endpoint bound to profileID, admitting clients whose
// source address falls in cidrs (comma-separated IPs or prefixes). Returns the
// endpoint's id and its generated token.
func AddEndpoint(db *sql.DB, name string, profileID int64, cidrs string) (int64, string, error) {
	orgID, err := DefaultOrgID(db)
	if err != nil {
		return 0, "", fmt.Errorf("no org: %w", err)
	}
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
	res, err := db.Exec(`INSERT INTO endpoints (org_id, profile_id, token, name, allowed_source_ips) VALUES (?, ?, ?, ?, ?)`,
		orgID, profileID, token, name, string(raw))
	if err != nil {
		return 0, "", err
	}
	id, _ := res.LastInsertId()
	return id, token, nil
}

// AddBlocklistSource registers a blocklist subscription on the default org.
func AddBlocklistSource(db *sql.DB, url, format string) error {
	orgID, err := DefaultOrgID(db)
	if err != nil {
		return fmt.Errorf("no org: %w", err)
	}
	switch format {
	case "hosts", "dnsmasq", "adguard":
	default:
		return fmt.Errorf("unknown format %q (hosts|dnsmasq|adguard)", format)
	}
	_, err = db.Exec(`INSERT OR IGNORE INTO blocklist_sources (org_id, url, format) VALUES (?, ?, ?)`, orgID, url, format)
	return err
}

func normDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}
