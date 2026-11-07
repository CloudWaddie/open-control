package store

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// exits.go — egress nodes (PLAN.md M5). Health is "healthy", "down" or
// "unknown". Only "down" excludes an exit: "unknown" (e.g. WireGuard, which
// cannot be probed without a tunnel) is treated as usable.

type ExitNode struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`    // socks5 | http | wireguard
	Address   string `json:"address"` // host:port of the proxy or WireGuard endpoint
	AnswerIP  string `json:"answer_ip"`
	AnswerIP6 string `json:"answer_ipv6,omitempty"`
	Health    string `json:"health"`
	CheckedAt string `json:"checked_at,omitempty"`

	// Socks5/HTTP dial credentials. Never serialized by List/Get; shown via
	// the secrets endpoint like endpoint tokens.
	Username string `json:"username,omitempty"`
	Password string `json:"-"`

	// WireGuard tunnel material.
	WGPrivate   string `json:"-"`
	WGPeer      string `json:"-"`
	WGPreshared string `json:"-"`
	WGAllowed   string `json:"-"`
}

// ExitSecrets is the secret half of an exit, returned only over the secrets
// endpoint so the edit dialog can show what is on file.
type ExitSecrets struct {
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	WGPrivate   string `json:"wg_private,omitempty"`
	WGPeer      string `json:"wg_peer,omitempty"`
	WGPreshared string `json:"wg_preshared,omitempty"`
	WGAllowed   string `json:"wg_allowed,omitempty"`
}

// ExitRecord is an exit as the health checker sees it, across orgs.
type ExitRecord struct {
	ExitNode
	Org int64
}

// wgKey validates a base64-encoded 32-byte WireGuard key.
func wgKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("must be a base64-encoded WireGuard key (32 bytes)")
	}
	return s, nil
}

// AddExitSpec is everything needed to create or update an exit.
type ExitSpec struct {
	Kind        string
	Address     string
	AnswerIP    string
	AnswerIP6   string
	Username    string
	Password    string
	WGPrivate   string
	WGPeer      string
	WGPreshared string
	WGAllowed   string
}

func validateExitSpec(spec *ExitSpec) error {
	switch spec.Kind {
	case "socks5", "http":
		if _, _, err := net.SplitHostPort(spec.Address); err != nil {
			return fmt.Errorf("address must be host:port")
		}
	case "wireguard":
		if _, _, err := net.SplitHostPort(spec.Address); err != nil {
			return fmt.Errorf("endpoint must be host:port")
		}
		if spec.WGPrivate == "" && spec.WGPeer == "" {
			// No tunnel material yet: the exit can still answer redirects
			// through its answer IP. Keys can be added by editing or by
			// supplying a wg-quick config.
			return nil
		}
		for k, v := range map[string]string{
			"private key":   spec.WGPrivate,
			"peer key":      spec.WGPeer,
			"preshared key": spec.WGPreshared,
		} {
			if v == "" {
				continue
			}
			if _, err := wgKey(v); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		if spec.WGPrivate == "" || spec.WGPeer == "" {
			return fmt.Errorf("a WireGuard exit needs its private key and the peer's public key")
		}
	default:
		return fmt.Errorf("kind must be socks5, http or wireguard")
	}
	ip, err := netip.ParseAddr(spec.AnswerIP)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("answer_ip must be an IPv4 address (the gateway that routes to this exit)")
	}
	if spec.AnswerIP6 != "" {
		ip6, err := netip.ParseAddr(spec.AnswerIP6)
		if err != nil || !ip6.Is6() || ip6.Is4In6() {
			return fmt.Errorf("answer_ipv6 must be an IPv6 address")
		}
		spec.AnswerIP6 = ip6.String()
	}
	return nil
}

// AddExitNode registers an egress node in org.
func AddExitNode(db DBTX, org int64, name string, spec ExitSpec) (int64, error) {
	spec.AnswerIP = strings.TrimSpace(spec.AnswerIP)
	if err := validateExitSpec(&spec); err != nil {
		return 0, err
	}
	res, err := db.Exec(`INSERT INTO exit_nodes
		(org_id, kind, name, address, answer_ip, answer_ipv6, health, username, password, wg_private, wg_peer, wg_preshared, wg_allowed)
		VALUES (?, ?, ?, ?, ?, ?, 'unknown', ?, ?, ?, ?, ?, ?)`,
		org, spec.Kind, name, spec.Address, spec.AnswerIP, spec.AnswerIP6,
		spec.Username, spec.Password, spec.WGPrivate, spec.WGPeer, spec.WGPreshared, spec.WGAllowed)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetExitNode updates an exit's fields. Only non-empty spec fields change
// anything, except for AnswerIP6 which may be cleared with "-".
func SetExitNode(db DBTX, org, id int64, spec ExitSpec) error {
	cur, err := GetExitSecrets(db, org, id)
	if err != nil {
		return err
	}
	node, err := GetExitNode(db, org, id)
	if err != nil {
		return err
	}
	if spec.Kind == "" {
		spec.Kind = node.Kind
	}
	if spec.Address == "" {
		spec.Address = node.Address
	}
	if spec.AnswerIP == "" {
		spec.AnswerIP = node.AnswerIP
	}
	if spec.Username == "" {
		spec.Username = cur.Username
	}
	if spec.Password == "" {
		spec.Password = cur.Password
	}
	if spec.WGPrivate == "" {
		spec.WGPrivate = cur.WGPrivate
	}
	if spec.WGPeer == "" {
		spec.WGPeer = cur.WGPeer
	}
	if spec.WGPreshared == "" {
		spec.WGPreshared = cur.WGPreshared
	}
	if spec.WGAllowed == "" {
		spec.WGAllowed = cur.WGAllowed
	}
	if spec.AnswerIP6 == "" {
		spec.AnswerIP6 = node.AnswerIP6
	}
	if err := validateExitSpec(&spec); err != nil {
		return err
	}
	if spec.AnswerIP6 == "-" {
		spec.AnswerIP6 = ""
	}
	_, err = db.Exec(`UPDATE exit_nodes SET kind = ?, address = ?, answer_ip = ?, answer_ipv6 = ?,
		username = ?, password = ?, wg_private = ?, wg_peer = ?, wg_preshared = ?, wg_allowed = ?
		WHERE id = ? AND org_id = ?`,
		spec.Kind, spec.Address, spec.AnswerIP, spec.AnswerIP6, spec.Username, spec.Password,
		spec.WGPrivate, spec.WGPeer, spec.WGPreshared, spec.WGAllowed, id, org)
	return err
}

// ParseWGConfig extracts the useful fields from a wg-quick configuration.
// Only what this server keeps is read: interface private key and address
// (unused, kept out), peer public key, endpoint, preshared key and the first
// AllowedIPs line of the sole peer this provider expects.
func ParseWGConfig(text string) (spec ExitSpec, err error) {
	get := func(section, key string) string {
		inSection := false
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				inSection = strings.EqualFold(strings.TrimSpace(strings.Trim(line, "[]")), section)
				continue
			}
			if !inSection {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), key) {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	private := get("Interface", "PrivateKey")
	peer := get("Peer", "PublicKey")
	endpoint := get("Peer", "Endpoint")
	allowed := get("Peer", "AllowedIPs")
	if private == "" || peer == "" || endpoint == "" {
		return ExitSpec{}, fmt.Errorf("config needs [Interface] PrivateKey and a [Peer] with PublicKey and Endpoint")
	}
	if _, err := wgKey(private); err != nil {
		return ExitSpec{}, fmt.Errorf("PrivateKey: %w", err)
	}
	if _, err := wgKey(peer); err != nil {
		return ExitSpec{}, fmt.Errorf("PublicKey: %w", err)
	}
	preshared := get("Peer", "PresharedKey")
	if preshared != "" {
		if _, err := wgKey(preshared); err != nil {
			return ExitSpec{}, fmt.Errorf("PresharedKey: %w", err)
		}
	}
	return ExitSpec{
		Kind:        "wireguard",
		Address:     endpoint,
		WGPrivate:   private,
		WGPeer:      peer,
		WGPreshared: preshared,
		WGAllowed:   allowed,
	}, nil
}

func ListExitNodes(db DBTX, org int64) ([]ExitNode, error) {
	rows, err := db.Query(`SELECT id, name, kind, address, answer_ip, answer_ipv6, health, checked_at, username, password FROM exit_nodes WHERE org_id = ? ORDER BY id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExitNode{}
	for rows.Next() {
		var e ExitNode
		if err := rows.Scan(&e.ID, &e.Name, &e.Kind, &e.Address, &e.AnswerIP, &e.AnswerIP6, &e.Health, &e.CheckedAt, &e.Username, &e.Password); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetExitNode returns one of org's exits, or ErrNotFound.
func GetExitNode(db DBTX, org, id int64) (ExitNode, error) {
	var e ExitNode
	err := db.QueryRow(`SELECT id, name, kind, address, answer_ip, health, checked_at, username, password FROM exit_nodes WHERE id = ? AND org_id = ?`,
		id, org).Scan(&e.ID, &e.Name, &e.Kind, &e.Address, &e.AnswerIP, &e.Health, &e.CheckedAt, &e.Username, &e.Password)
	if err != nil {
		return e, ErrNotFound
	}
	return e, nil
}

// GetExitSecrets returns the secret half of an exit for the edit dialog.
func GetExitSecrets(db DBTX, org, id int64) (ExitSecrets, error) {
	var s ExitSecrets
	err := db.QueryRow(`SELECT username, password, wg_private, wg_peer, wg_preshared, wg_allowed FROM exit_nodes WHERE id = ? AND org_id = ?`,
		id, org).Scan(&s.Username, &s.Password, &s.WGPrivate, &s.WGPeer, &s.WGPreshared, &s.WGAllowed)
	if err != nil {
		return s, ErrNotFound
	}
	return s, nil
}

// DeleteExitNode removes an exit and every redirect rule that points at it, so
// no rule is left pointing at nothing. It returns how many rules were removed.
func DeleteExitNode(db DBTX, org, id int64) (int64, error) {
	res, err := db.Exec(`DELETE FROM profile_rules WHERE kind = 'redirect' AND answer = ?
		AND profile_id IN (SELECT id FROM profiles WHERE org_id = ?)`, strconv.FormatInt(id, 10), org)
	if err != nil {
		return 0, err
	}
	removed, _ := res.RowsAffected()
	if err := deleteRow(db, `DELETE FROM exit_nodes WHERE id = ? AND org_id = ?`, id, org); err != nil {
		return 0, err
	}
	return removed, nil
}

// SetExitHealth records a health check result.
func SetExitHealth(db DBTX, id int64, health string) error {
	_, err := db.Exec(`UPDATE exit_nodes SET health = ?, checked_at = datetime('now') WHERE id = ?`, health, id)
	return err
}

// ListAllExitRecords returns every exit across orgs, for the health checker.
func ListAllExitRecords(db DBTX) ([]ExitRecord, error) {
	rows, err := db.Query(`SELECT id, org_id, name, kind, address, answer_ip, health, checked_at, username, password FROM exit_nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExitRecord
	for rows.Next() {
		var r ExitRecord
		if err := rows.Scan(&r.ID, &r.Org, &r.Name, &r.Kind, &r.Address, &r.AnswerIP, &r.Health, &r.CheckedAt, &r.Username, &r.Password); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ruleKey is the key domainSet.Match reports for a rule pattern.
func ruleKey(matcher, pattern string) string {
	key := strings.ToLower(strings.Trim(pattern, "."))
	if matcher == "tld" {
		return "." + key
	}
	return key
}
