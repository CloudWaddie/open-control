package store

import (
	"database/sql"
	"time"
)

// logs.go — query log storage and the stats behind the dashboard (PLAN.md M4).
// Every read is filtered by org; rows with org 0 are unattributed (e.g. a
// refused unknown token) and are never visible through the API.

// QueryLog is one resolver decision. Ts is unix seconds.
type QueryLog struct {
	ID       int64  `json:"id"`
	Org      int64  `json:"org"`
	Endpoint int64  `json:"endpoint_id,omitempty"`
	Ts       int64  `json:"ts"`
	Client   string `json:"client"`
	QName    string `json:"qname"`
	QType    string `json:"qtype"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}

// InsertQueryLogs writes a batch in one transaction.
func InsertQueryLogs(db *sql.DB, rows []QueryLog) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO query_logs (org_id, endpoint_id, ts, client_ip, qname, qtype, action, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range rows {
		r := &rows[i]
		var ep any
		if r.Endpoint != 0 {
			ep = r.Endpoint
		}
		res, err := stmt.Exec(r.Org, ep, r.Ts, r.Client, r.QName, r.QType, r.Action, r.Reason)
		if err != nil {
			return err
		}
		// Write the assigned id back so sinks receive the same id the API shows.
		if r.ID, err = res.LastInsertId(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LogFilter narrows a log listing. Zero values mean "no filter".
type LogFilter struct {
	AfterID int64  // only rows with id > AfterID (live tail)
	Action  string // block | forward | rewrite | refused | error
	Client  string // exact client address
	Limit   int
}

// ListQueryLogs returns the org's newest matching rows first.
func ListQueryLogs(db DBTX, org int64, f LogFilter) ([]QueryLog, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q := `SELECT id, org_id, COALESCE(endpoint_id, 0), ts, client_ip, qname, qtype, action, reason
		FROM query_logs WHERE org_id = ? AND id > ?`
	args := []any{org, f.AfterID}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.Client != "" {
		q += ` AND client_ip = ?`
		args = append(args, f.Client)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueryLog{}
	for rows.Next() {
		var l QueryLog
		if err := rows.Scan(&l.ID, &l.Org, &l.Endpoint, &l.Ts, &l.Client, &l.QName, &l.QType, &l.Action, &l.Reason); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Count is one row of a top-N list.
type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Stats summarises the org's traffic since a point in time.
type Stats struct {
	Window     string  `json:"window"`
	Total      int64   `json:"total"`
	Blocked    int64   `json:"blocked"`
	BlockedPct float64 `json:"blocked_pct"`
	TopBlocked []Count `json:"top_blocked"`
	TopClients []Count `json:"top_clients"`
	TopDomains []Count `json:"top_domains"`
}

// QueryStats computes the dashboard numbers for org over the last `window`.
func QueryStats(db DBTX, org int64, window time.Duration, now time.Time) (Stats, error) {
	since := now.Add(-window).Unix()
	var s Stats
	err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END), 0)
		FROM query_logs WHERE org_id = ? AND ts >= ?`, org, since).Scan(&s.Total, &s.Blocked)
	if err != nil {
		return s, err
	}
	if s.Total > 0 {
		s.BlockedPct = 100 * float64(s.Blocked) / float64(s.Total)
	}
	if s.TopBlocked, err = topN(db, `SELECT qname, COUNT(*) c FROM query_logs
		WHERE org_id = ? AND ts >= ? AND action = 'block' GROUP BY qname ORDER BY c DESC, qname LIMIT 10`, org, since); err != nil {
		return s, err
	}
	if s.TopDomains, err = topN(db, `SELECT qname, COUNT(*) c FROM query_logs
		WHERE org_id = ? AND ts >= ? GROUP BY qname ORDER BY c DESC, qname LIMIT 10`, org, since); err != nil {
		return s, err
	}
	if s.TopClients, err = topN(db, `SELECT client_ip, COUNT(*) c FROM query_logs
		WHERE org_id = ? AND ts >= ? GROUP BY client_ip ORDER BY c DESC, client_ip LIMIT 10`, org, since); err != nil {
		return s, err
	}
	return s, nil
}

func topN(db DBTX, query string, args ...any) ([]Count, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PurgeQueryLogs deletes rows older than before (unix seconds) in bounded
// batches, so a large purge never holds the single writer for long.
func PurgeQueryLogs(db *sql.DB, before int64) (int64, error) {
	var total int64
	for {
		res, err := db.Exec(`DELETE FROM query_logs WHERE id IN (
			SELECT id FROM query_logs WHERE ts < ? LIMIT 5000)`, before)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < 5000 {
			return total, nil
		}
	}
}
