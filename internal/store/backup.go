package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

// Backup writes a consistent snapshot of the database to dest using SQLite's
// VACUUM INTO, which is safe while the server is writing. dest must not exist.
func Backup(db *sql.DB, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	if dir := filepath.Dir(dest); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	_, err := db.Exec(`VACUUM INTO ?`, dest)
	return err
}
