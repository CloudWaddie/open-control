package store

import (
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
	Kind      string `json:"kind"`    // socks5 | wireguard
	Address   string `json:"address"` // host:port of the proxy or WireGuard endpoint
	AnswerIP  string `json:"answer_ip"`
	Health    string `json:"health"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// ExitRecord is an exit as the health checker sees it, across orgs.
type ExitRecord struct {
	ExitNode
	Org int64
}

// AddExitNode registers an egress node in org.
func AddExitNode(db DBTX, org int64, name, kind, address, answerIP string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("exit name is required")
	}
	switch kind {
	case "socks5", "wireguard":
	default:
		return 0, fmt.Errorf("kind must be socks5 or wireguard")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return 0, fmt.Errorf("address must be host:port")
	}
	ip, err := netip.ParseAddr(answerIP)
	if err != nil || !ip.Is4() {
		return 0, fmt.Errorf("answer_ip must be an IPv4 address (the gateway that routes to this exit)")
	}
	res, err := db.Exec(`INSERT INTO exit_nodes (org_id, kind, name, address, answer_ip, health) VALUES (?, ?, ?, ?, ?, 'unknown')`,
		org, kind, name, address, ip.String())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func ListExitNodes(db DBTX, org int64) ([]ExitNode, error) {
	rows, err := db.Query(`SELECT id, name, kind, address, answer_ip, health, checked_at FROM exit_nodes WHERE org_id = ? ORDER BY id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExitNode{}
	for rows.Next() {
		var e ExitNode
		if err := rows.Scan(&e.ID, &e.Name, &e.Kind, &e.Address, &e.AnswerIP, &e.Health, &e.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetExitNode returns one of org's exits, or ErrNotFound.
func GetExitNode(db DBTX, org, id int64) (ExitNode, error) {
	var e ExitNode
	err := db.QueryRow(`SELECT id, name, kind, address, answer_ip, health, checked_at FROM exit_nodes WHERE id = ? AND org_id = ?`,
		id, org).Scan(&e.ID, &e.Name, &e.Kind, &e.Address, &e.AnswerIP, &e.Health, &e.CheckedAt)
	if err != nil {
		return e, ErrNotFound
	}
	return e, nil
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
	rows, err := db.Query(`SELECT id, org_id, name, kind, address, answer_ip, health, checked_at FROM exit_nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExitRecord
	for rows.Next() {
		var r ExitRecord
		if err := rows.Scan(&r.ID, &r.Org, &r.Name, &r.Kind, &r.Address, &r.AnswerIP, &r.Health, &r.CheckedAt); err != nil {
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
