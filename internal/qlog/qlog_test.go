package qlog

import (
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedDefaults(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func count(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM query_logs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func event(name string) store.QueryLog {
	return store.QueryLog{Org: 1, Client: "10.0.0.1", QName: name, QType: "A", Action: "block", Ts: time.Now().Unix()}
}

// Recording must never block the caller, even with nobody draining the buffer:
// excess events are dropped and counted.
func TestRecordNeverBlocksAndCountsDrops(t *testing.T) {
	db := testDB(t)
	l := New(db, 2)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			l.Record(event("a.example"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked with a full buffer")
	}
	if l.Dropped() != 3 {
		t.Errorf("dropped %d, want 3", l.Dropped())
	}
	l.Flush()
	if n := count(t, db); n != 2 {
		t.Errorf("rows written %d, want the 2 that fit the buffer", n)
	}
}

type captureSink struct{ got []store.QueryLog }

func (c *captureSink) Send(b []store.QueryLog) error {
	c.got = append(c.got, b...)
	return nil
}

func TestFlushWritesDatabaseAndSinks(t *testing.T) {
	db := testDB(t)
	sink := &captureSink{}
	l := New(db, 16, sink)
	for i := 0; i < 3; i++ {
		l.Record(event("ads.example"))
	}
	if n := l.Flush(); n != 3 {
		t.Fatalf("flush took %d events, want 3", n)
	}
	if count(t, db) != 3 || len(sink.got) != 3 {
		t.Errorf("db rows=%d sink events=%d, want 3 and 3", count(t, db), len(sink.got))
	}
	for _, e := range sink.got {
		if e.ID == 0 {
			t.Error("sink received an event without its database id")
		}
	}
	if l.Flush() != 0 {
		t.Error("second flush should find nothing")
	}
}

func TestWebhookSinkPostsJSONBatch(t *testing.T) {
	var body []store.QueryLog
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctype = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := NewWebhook(srv.URL).Send([]store.QueryLog{event("ads.example")}); err != nil {
		t.Fatal(err)
	}
	if ctype != "application/json" || len(body) != 1 || body[0].QName != "ads.example" {
		t.Errorf("webhook got type=%q body=%+v", ctype, body)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := NewWebhook(bad.URL).Send([]store.QueryLog{event("x.example")}); err == nil {
		t.Error("webhook 500 should be an error")
	}
}

func TestSyslogSinkSendsOneLinePerEvent(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	sl, err := NewSyslog(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	e := event("ads.example")
	e.Reason = "custom block with spaces"
	if err := sl.Send([]store.QueryLog{e}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no syslog datagram: %v", err)
	}
	line := string(buf[:n])
	for _, want := range []string{"<134>1 ", "opencontrol", "action=block", "qname=ads.example", "reason=custom_block_with_spaces"} {
		if !strings.Contains(line, want) {
			t.Errorf("syslog line %q missing %q", line, want)
		}
	}
}
