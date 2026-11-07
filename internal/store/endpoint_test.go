package store

import (
	"github.com/cloudwaddie/opencontrol/internal/policy"
	"path/filepath"
	"testing"
)

// Endpoint tokens are DoH/DoT credentials: only their hash may be stored, and
// rotation must revoke the old one at once.
func TestEndpointTokenIsStoredHashedAndRotates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ep.db"))
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
	org, _ := DefaultOrgID(db)

	id, token, err := AddEndpoint(db, org, "phone", 1, "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow(`SELECT token FROM endpoints WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Fatal("plaintext endpoint token stored in the database")
	}
	if stored != HashToken(token) {
		t.Fatal("stored value is not the token's hash")
	}

	snap, err := LoadSnapshot(db, t.TempDir(), policy.FetchNone)
	if err != nil {
		t.Fatal(err)
	}
	if snap.EndpointForToken(token) == nil {
		t.Fatal("new token does not resolve to its endpoint")
	}

	fresh, err := RotateEndpointToken(db, org, id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == token {
		t.Fatal("rotation returned the same token")
	}
	snap, _ = LoadSnapshot(db, t.TempDir(), policy.FetchNone)
	if snap.EndpointForToken(token) != nil {
		t.Error("old token still works after rotation")
	}
	if snap.EndpointForToken(fresh) == nil {
		t.Error("rotated token does not work")
	}

	// Rotating another org's endpoint is refused as not found.
	other, _ := CreateOrg(db, "elsewhere")
	if _, err := RotateEndpointToken(db, other, id); err == nil {
		t.Error("rotated an endpoint belonging to another org")
	}
}
