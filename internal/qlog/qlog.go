// Package qlog records resolver decisions without slowing the DNS hot path.
//
// Record() never blocks: events go into a bounded buffer, and when the buffer
// is full the event is dropped and counted. A single writer batches the buffer
// into SQLite and fans each batch out to the configured sinks (syslog, webhook).
// Logging is best-effort by design: a stalled database must not stall DNS.
package qlog

import (
	"context"
	"database/sql"
	"log"
	"sync/atomic"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

// Sink receives every flushed batch. Errors are logged; batches are not retried.
type Sink interface {
	Send(batch []store.QueryLog) error
}

const maxBatch = 2000

type Logger struct {
	db      *sql.DB
	ch      chan store.QueryLog
	sinks   []Sink
	dropped atomic.Uint64
}

// New creates a logger with room for buffer events before drops begin.
func New(db *sql.DB, buffer int, sinks ...Sink) *Logger {
	if buffer <= 0 {
		buffer = 4096
	}
	return &Logger{db: db, ch: make(chan store.QueryLog, buffer), sinks: sinks}
}

// Record queues one decision. It never blocks the caller.
func (l *Logger) Record(e store.QueryLog) {
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

// Dropped reports how many events were discarded because the buffer was full
// or the database write failed.
func (l *Logger) Dropped() uint64 { return l.dropped.Load() }

// Flush writes up to maxBatch buffered events to the database and sinks. It
// returns how many events it took off the buffer.
func (l *Logger) Flush() int {
	batch := make([]store.QueryLog, 0, 256)
	for len(batch) < maxBatch {
		select {
		case e := <-l.ch:
			batch = append(batch, e)
		default:
			goto done
		}
	}
done:
	if len(batch) == 0 {
		return 0
	}
	if err := store.InsertQueryLogs(l.db, batch); err != nil {
		l.dropped.Add(uint64(len(batch)))
		log.Printf("qlog: write %d events failed, dropped: %v", len(batch), err)
		return len(batch)
	}
	for _, s := range l.sinks {
		if err := s.Send(batch); err != nil {
			log.Printf("qlog: sink: %v", err)
		}
	}
	return len(batch)
}

// Run flushes about once a second, and keeps going while batches are full,
// until ctx is cancelled. On cancel it writes what is left.
func (l *Logger) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for l.Flush() > 0 {
			}
			return
		case <-t.C:
			for l.Flush() == maxBatch {
			}
		}
	}
}

// Retention purges rows older than days, once an hour, until ctx is cancelled.
// days <= 0 keeps everything.
func Retention(ctx context.Context, db *sql.DB, days int) {
	if days <= 0 {
		return
	}
	purge := func() {
		cutoff := time.Now().AddDate(0, 0, -days).Unix()
		n, err := store.PurgeQueryLogs(db, cutoff)
		if err != nil {
			log.Printf("qlog: retention purge: %v", err)
			return
		}
		if n > 0 {
			log.Printf("qlog: retention purged %d rows older than %d days", n, days)
		}
	}
	purge()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}
