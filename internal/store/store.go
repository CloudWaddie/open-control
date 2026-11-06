// Package store handles SQLite (modernc, pure Go / no CGO) and schema migrations.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer connection keeps concurrent writes serialized safely without
	// busy-storms; WAL still gives concurrent reads.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Migrate applies any not-yet-applied migrations, read from the embedded FS,
// in filename order ("0001_init.sql", "0002_....sql").
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}

	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)

	for _, name := range entries {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)`, name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, name); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		log.Printf("store: applied migration %s", name)
	}
	return nil
}
