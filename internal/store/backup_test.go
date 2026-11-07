package store

import (
	"path/filepath"
	"testing"
)

func TestBackupIsReadableCopy(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SeedDefaults(db); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "backups", "copy.db")
	if err := Backup(db, dest); err != nil {
		t.Fatal(err)
	}
	if err := Backup(db, dest); err == nil {
		t.Fatal("second backup to the same path should refuse to overwrite")
	}

	cp, err := Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	var n int
	if err := cp.QueryRow(`SELECT COUNT(*) FROM profiles`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("backup has %d profiles (err %v), want 1", n, err)
	}
}
