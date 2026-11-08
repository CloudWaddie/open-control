package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// api.go — org-scoped data access for the control-plane REST API (PLAN.md M2).
// Every read filters by org; every delete matches org in the WHERE clause, so
// a row from another org is indistinguishable from a missing one (404).

// DBTX is satisfied by *sql.DB and *sql.Tx. Mutations take a DBTX so a change
// and its audit row can commit or roll back together.
type DBTX interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// ErrNotFound is returned when a row is missing or belongs to another org.
var ErrNotFound = errors.New("not found")

type Profile struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Default bool   `json:"default"`
	Locked  bool   `json:"locked"`
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
	// Token is the endpoint's DoH/DoT resolver ID. It is a device
	// identifier, not a credential, so it is listed again any time
	// (migration 0008 keeps the plaintext alongside the auth hash).
	Token string `json:"token,omitempty"`
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

// Token is an API credential. OrgID scopes everything it can reach; the hash
// is never serialized.
type Token struct {
	ID        int64  `json:"id"`
	OrgID     int64  `json:"-"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

func ListProfiles(db DBTX, org int64) ([]Profile, error) {
	rows, err := db.Query(`SELECT p.id, p.name, p.options, COALESCE(o.default_profile_id = p.id, 0)
		FROM profiles p JOIN orgs o ON o.id = p.org_id WHERE p.org_id = ? ORDER BY p.id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		var p Profile
		var opts string
		if err := rows.Scan(&p.ID, &p.Name, &opts, &p.Default); err != nil {
			return nil, err
		}
		p.Locked = parseOptions(opts).Locked
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListRules returns rules of one profile, but only if the profile is in org.
func ListRules(db DBTX, org, profileID int64) ([]Rule, error) {
	rows, err := db.Query(`SELECT r.id, r.profile_id, r.kind, r.matcher, r.pattern, r.answer
		FROM profile_rules r JOIN profiles p ON p.id = r.profile_id
		WHERE r.profile_id = ? AND p.org_id = ? ORDER BY r.id`, profileID, org)
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

func DeleteRule(db DBTX, org, id int64) error {
	var profileID int64
	if err := db.QueryRow(`SELECT profile_id FROM profile_rules WHERE id = ?`, id).Scan(&profileID); err == nil {
		if err := checkUnlocked(db, profileID); err != nil {
			return err
		}
	}
	return deleteRow(db, `DELETE FROM profile_rules WHERE id = ?
		AND profile_id IN (SELECT id FROM profiles WHERE org_id = ?)`, id, org)
}

func ListEndpoints(db DBTX, org int64) ([]Endpoint, error) {
	rows, err := db.Query(`SELECT id, profile_id, name, allowed_source_ips, token_plain FROM endpoints WHERE org_id = ? ORDER BY id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		var raw, token string
		if err := rows.Scan(&e.ID, &e.ProfileID, &e.Name, &raw, &token); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &e.CIDRs)
		e.Token = token
		out = append(out, e)
	}
	return out, rows.Err()
}

func DeleteEndpoint(db DBTX, org, id int64) error {
	return deleteRow(db, `DELETE FROM endpoints WHERE id = ? AND org_id = ?`, id, org)
}

func ListBlocklists(db DBTX, org int64) ([]Blocklist, error) {
	rows, err := db.Query(`SELECT id, url, format, COALESCE(last_synced, '') FROM blocklist_sources WHERE org_id = ? ORDER BY id`, org)
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

func DeleteBlocklist(db DBTX, org, id int64) error {
	if err := deleteRow(db, `DELETE FROM blocklist_sources WHERE id = ? AND org_id = ?`, id, org); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM profile_filters WHERE kind = 'list' AND ref = ?
		AND profile_id IN (SELECT id FROM profiles WHERE org_id = ?)`, strconv.FormatInt(id, 10), org)
	return err
}

// ListAudit returns the org's newest audit entries first.
func ListAudit(db DBTX, org int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.Query(`SELECT id, ts, actor, action, target FROM audit_logs
		WHERE org_id = ? ORDER BY id DESC LIMIT ?`, org, limit)
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

// InsertAudit records an action for org. Every mutating API call writes one.
func InsertAudit(db DBTX, org int64, actor, action, target string) error {
	_, err := db.Exec(`INSERT INTO audit_logs (org_id, ts, actor, action, target) VALUES (?, ?, ?, ?, ?)`,
		org, time.Now().Unix(), actor, action, target)
	return err
}

// HashToken is the storage form of an API token. Tokens are high-entropy
// random strings, so a fast hash is appropriate; the plaintext is never stored.
func HashToken(plain string) string {
	return policy.HashSecret(plain)
}

// NewSecret returns a random 128-bit hex string for endpoint tokens.
func NewSecret() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// RotateEndpointToken replaces an endpoint's token. The old token stops working
// immediately; the new one is returned and, like every endpoint token, can be
// viewed again on the endpoints page.
func RotateEndpointToken(db DBTX, org, id int64) (string, error) {
	token, err := NewSecret()
	if err != nil {
		return "", err
	}
	// deleteRow reports ErrNotFound when no row matched (wrong id or org).
	if err := deleteRow(db, `UPDATE endpoints SET token = ?, token_plain = ? WHERE id = ? AND org_id = ?`,
		HashToken(token), token, id, org); err != nil {
		return "", err
	}
	return token, nil
}

// GetEndpointToken returns an endpoint's current DoH/DoT token. Endpoints
// created before tokens were viewable have none; rotating issues one.
func GetEndpointToken(db DBTX, org, id int64) (string, error) {
	var token string
	err := db.QueryRow(`SELECT token_plain FROM endpoints WHERE id = ? AND org_id = ?`, id, org).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("endpoint %d: %w", id, ErrNotFound)
	}
	return token, err
}

// CreateToken mints a random token for org with a role. The plaintext is
// returned once and cannot be recovered afterwards.
func CreateToken(db DBTX, org int64, name, role string) (string, error) {
	switch role {
	case "admin", "operator", "viewer":
	default:
		return "", fmt.Errorf("unknown role %q (admin|operator|viewer)", role)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	plain := "oc_" + hex.EncodeToString(buf)
	if _, err := db.Exec(`INSERT INTO api_tokens (org_id, name, role, token_hash) VALUES (?, ?, ?, ?)`,
		org, name, role, HashToken(plain)); err != nil {
		return "", err
	}
	return plain, nil
}

// ListTokens returns the org's token metadata. Hashes are never returned.
func ListTokens(db DBTX, org int64) ([]Token, error) {
	rows, err := db.Query(`SELECT id, name, role, created_at FROM api_tokens WHERE org_id = ? ORDER BY id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Role, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken deletes one of org's tokens; its bearer is refused from the next request.
func RevokeToken(db DBTX, org, id int64) error {
	return deleteRow(db, `DELETE FROM api_tokens WHERE id = ? AND org_id = ?`, id, org)
}

// LookupToken resolves a presented token to its record (including org).
func LookupToken(db DBTX, plain string) (Token, bool, error) {
	var t Token
	err := db.QueryRow(`SELECT id, org_id, name, role, created_at FROM api_tokens WHERE token_hash = ?`,
		HashToken(plain)).Scan(&t.ID, &t.OrgID, &t.Name, &t.Role, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, err
	}
	return t, true, nil
}

func deleteRow(db DBTX, query string, args ...any) error {
	res, err := db.Exec(query, args...)
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
