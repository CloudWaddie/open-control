package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUserAccounts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "users.db"))
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

	u, err := CreateUser(db, org, "edward", "correct horse", "admin")
	if err != nil {
		t.Fatal(err)
	}

	// Signing in works, wrong credentials read exactly like no such account.
	if _, err := AuthenticateUser(db, "edward", "correct horse"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if _, err := AuthenticateUser(db, "edward", "wrong"); err != ErrNotFound {
		t.Errorf("wrong password: %v, want ErrNotFound", err)
	}
	if _, err := AuthenticateUser(db, "nobody", "correct horse"); err != ErrNotFound {
		t.Errorf("unknown user: %v, want ErrNotFound", err)
	}

	// A sign-in session is a revocable bearer token.
	session, err := CreateSession(db, u)
	if err != nil {
		t.Fatal(err)
	}
	if tok, ok, err := LookupToken(db, session); err != nil || !ok || tok.Role != "admin" {
		t.Fatalf("session token: %v %v %v", tok, ok, err)
	}

	// Bad input is refused.
	for _, bad := range []struct{ name, pw, role string }{
		{"x", "long enough", "viewer"},    // too short a name
		{"with space", "long enough", ""}, // space in name
		{"ok-name", "short", "viewer"},    // too short a password
		{"ok-name", "long enough", "chef"},
	} {
		if _, err := CreateUser(db, org, bad.name, bad.pw, bad.role); err == nil {
			t.Errorf("created %+v", bad)
		}
	}

	// Changing a password revokes outstanding sessions.
	if err := SetUserPassword(db, org, u.ID, "another good one"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := LookupToken(db, session); ok {
		t.Error("password reset did not revoke the session")
	}
	if _, err := AuthenticateUser(db, "edward", "another good one"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}

	// An admin cannot delete themselves.
	if err := DeleteUser(db, org, u.ID, "login: edward"); err == nil || !strings.Contains(err.Error(), "own") {
		t.Errorf("self delete: %v", err)
	}
	// Deleting someone else removes their sessions too.
	other, err := CreateUser(db, org, "colleague", "correct horse", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	colleagueSession, _ := CreateSession(db, other)
	if err := DeleteUser(db, org, other.ID, "login: edward"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := LookupToken(db, colleagueSession); ok {
		t.Error("deleted user's session still works")
	}
	ListUsers(db, org)
}
