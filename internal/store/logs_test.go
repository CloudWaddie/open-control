package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func logsDB(t *testing.T) (*sql.DB, int64, int64) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SeedDefaults(db); err != nil {
		t.Fatal(err)
	}
	a, _ := DefaultOrgID(db)
	b, err := CreateOrg(db, "other")
	if err != nil {
		t.Fatal(err)
	}
	return db, a, b
}

func TestQueryLogsIsolationFiltersAndStats(t *testing.T) {
	db, orgA, orgB := logsDB(t)
	now := time.Now()
	ts := now.Unix()

	rows := []QueryLog{
		{Org: orgA, Client: "10.0.0.1", QName: "ads.example", QType: "A", Action: "block", Ts: ts},
		{Org: orgA, Client: "10.0.0.1", QName: "ads.example", QType: "A", Action: "block", Ts: ts},
		{Org: orgA, Client: "10.0.0.2", QName: "news.example", QType: "A", Action: "forward", Ts: ts},
		{Org: orgB, Client: "192.0.2.9", QName: "tenant-b.example", QType: "A", Action: "block", Ts: ts},
		{Org: 0, Client: "203.0.113.4", QName: "unattributed.example", QType: "A", Action: "refused", Ts: ts},
		{Org: orgA, Client: "10.0.0.1", QName: "old.example", QType: "A", Action: "block", Ts: ts - 90*86400},
	}
	if err := InsertQueryLogs(db, rows); err != nil {
		t.Fatal(err)
	}

	// Listing: org A sees only its rows; org B's and unattributed rows are hidden.
	got, err := ListQueryLogs(db, orgA, LogFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("org A sees %d rows, want 4 (its own, including the old one)", len(got))
	}
	for _, l := range got {
		if l.Org != orgA {
			t.Errorf("row %d reports org %d, want %d", l.ID, l.Org, orgA)
		}
	}
	for _, l := range got {
		if l.QName == "tenant-b.example" || l.QName == "unattributed.example" {
			t.Errorf("org A sees foreign row %q", l.QName)
		}
	}
	if got[0].ID < got[len(got)-1].ID {
		t.Error("newest rows should come first")
	}

	// Filters.
	blocks, _ := ListQueryLogs(db, orgA, LogFilter{Action: "block", Limit: 100})
	if len(blocks) != 3 {
		t.Errorf("block filter: %d rows, want 3", len(blocks))
	}
	byClient, _ := ListQueryLogs(db, orgA, LogFilter{Client: "10.0.0.2", Limit: 100})
	if len(byClient) != 1 || byClient[0].QName != "news.example" {
		t.Errorf("client filter: %+v", byClient)
	}

	// Live tail: only rows newer than the cursor.
	cursor := got[1].ID
	tail, _ := ListQueryLogs(db, orgA, LogFilter{AfterID: cursor, Limit: 100})
	if len(tail) != 1 || tail[0].ID <= cursor {
		t.Errorf("after cursor: %+v", tail)
	}

	// Stats over the last hour exclude the 90-day-old row.
	st, err := QueryStats(db, orgA, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 3 || st.Blocked != 2 {
		t.Fatalf("stats total=%d blocked=%d, want 3 and 2", st.Total, st.Blocked)
	}
	if st.BlockedPct < 66 || st.BlockedPct > 67 {
		t.Errorf("blocked pct %.1f, want ~66.7", st.BlockedPct)
	}
	if len(st.TopBlocked) != 1 || st.TopBlocked[0].Key != "ads.example" || st.TopBlocked[0].Count != 2 {
		t.Errorf("top blocked: %+v", st.TopBlocked)
	}
	if len(st.TopClients) == 0 || st.TopClients[0].Key != "10.0.0.1" {
		t.Errorf("top clients: %+v", st.TopClients)
	}

	// Purge removes only rows older than the cutoff.
	n, err := PurgeQueryLogs(db, now.AddDate(0, 0, -30).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("purged %d rows, want 1 (the 90-day-old row)", n)
	}
	left, _ := ListQueryLogs(db, orgA, LogFilter{Limit: 100})
	if len(left) != 3 {
		t.Errorf("after purge org A has %d rows, want 3", len(left))
	}
}
