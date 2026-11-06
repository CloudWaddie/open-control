package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// api.go — data access for the control-plane REST API (PLAN.md M2).
// Everything is scoped to the default org for now; multi-org scoping is M2b.

type Profile struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type Rule struct {
	ID        int64  `json:"id"`
	ProfileID int64  `json:"profile_id"`
	Kind      string `json:"kind"`
	Matcher   string `json:"matcher"`
	Pattern   string `json:"pattern"`
	Answer    string `json:"answer,omitempty"`
}

type Endpoint struct {
	ID        int64    `json:"id"`
	ProfileID int64    `json:"profile_id"`
	Name      string   `json:"name"`
	CIDRs     []string `json:"cidrs"`
}

type Blocklist struct {
	ID         int64  `json:"id"`
	URL        string `json:"url"`
	Format     string `json:"format"`
	LastSynced string `json:"last_synced,omitempty"`
}

type AuditEntry struct {
	ID     int64  `json:"id"`
	Ts     int64  `json:"ts"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// ErrNotFound is returned when a delete targets a missing row.
var ErrNotFound = errors.New("not found")

func ListProfiles(db *sql.DB) ([]Profile, error) {
	rows, err := db.Query(`SELECT id, name FROM profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		var p Profile
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func ListRules(db *sql.DB, profileID int64) ([]Rule, error) {
	rows, err := db.Query(`SELECT id, profile_id, kind, matcher, pattern, answer FROM profile_rules WHERE profile_id = ? ORDER BY id`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.ProfileID, &r.Kind, &r.Matcher, &r.Pattern, &r.Answer); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func DeleteRule(db *sql.DB, id int64) error {
	return deleteRow(db, `DELETE FROM profile_rules WHERE id = ?`, id)
}

func ListEndpoints(db *sql.DB) ([]Endpoint, error) {
	rows, err := db.Query(`SELECT id, profile_id, name, allowed_source_ips FROM endpoints ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		var raw string
		if err := rows.Scan(&e.ID, &e.ProfileID, &e.Name, &raw); err != nil {
			return nil, err
		}
		e.CIDRs = parseCIDRList(raw)
		out = append(out, e)
	}
	return out, rows.Err()
}

func DeleteEndpoint(db *sql.DB, id int64) error {
	return deleteRow(db, `DELETE FROM endpoints WHERE id = ?`, id)
}

func ListBlocklists(db *sql.DB) ([]Blocklist, error) {
	rows, err := db.Query(`SELECT id, url, format, COALESCE(last_synced, '') FROM blocklist_sources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Blocklist{}
	for rows.Next() {
		var b Blocklist
		if err := rows.Scan(&b.ID, &b.URL, &b.Format, &b.LastSynced); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func DeleteBlocklist(db *sql.DB, id int64) error {
	return deleteRow(db, `DELETE FROM blocklist_sources WHERE id = ?`, id)
}

// ListAudit returns the newest audit entries first.
func ListAudit(db *sql.DB, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.Query(`SELECT id, ts, actor, action, target FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.Ts, &a.Actor, &a.Action, &a.Target); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// InsertAudit records an admin action. Every mutating API call writes one.
func InsertAudit(db *sql.DB, actor, action, target string) error {
	orgID, err := DefaultOrgID(db)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO audit_logs (org_id, ts, actor, action, target) VALUES (?, ?, ?, ?, ?)`,
		orgID, time.Now().Unix(), actor, action, target)
	return err
}

// HashToken is the storage form of an API token. Tokens are high-entropy
// random strings, so a fast hash is appropriate; the plaintext is never stored.
func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// CreateToken mints a random API token with a role. The plaintext is returned
// once and cannot be recovered afterwards.
func CreateToken(db *sql.DB, name, role string) (string, error) {
	switch role {
	case "admin", "operator", "viewer":
	default:
		return "", fmt.Errorf("unknown role %q (admin|operator|viewer)", role)
	}
	orgID, err := DefaultOrgID(db)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	plain := "oc_" + hex.EncodeToString(buf)
	if _, err := db.Exec(`INSERT INTO api_tokens (org_id, name, role, token_hash) VALUES (?, ?, ?, ?)`,
		orgID, name, role, HashToken(plain)); err != nil {
		return "", err
	}
	return plain, nil
}

// LookupToken resolves a presented token to its name and role.
func LookupToken(db *sql.DB, plain string) (name, role string, ok bool, err error) {
	err = db.QueryRow(`SELECT name, role FROM api_tokens WHERE token_hash = ?`, HashToken(plain)).Scan(&name, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return name, role, true, nil
}

func deleteRow(db *sql.DB, query string, id int64) error {
	res, err := db.Exec(query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func parseCIDRList(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}
