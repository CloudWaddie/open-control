package control

import (
	"net/http"
	"testing"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

func storeCreateUser(f *fixture, name, pw, role string) store.User {
	org, err := store.DefaultOrgID(f.db)
	if err != nil {
		f.t.Fatal(err)
	}
	u, err := store.CreateUser(f.db, org, name, pw, role)
	if err != nil {
		f.t.Fatal(err)
	}
	return u
}

func TestLoginAndAccounts(t *testing.T) {
	f := newFixture(t)
	storeCreateUser(f, "edward", "correct horse", "admin")

	// Trade a username and password for a session that acts as an admin.
	code, body, _ := f.do("POST", "/api/v1/auth/login", "", `{"username":"edward","password":"correct horse"}`)
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}
	session, _ := body["token"].(string)
	if session == "" {
		t.Fatalf("no token in login response: %v", body)
	}
	if code, b, _ := f.do("GET", "/api/v1/whoami", session, ""); code != http.StatusOK || b["name"] != "edward" {
		t.Fatalf("session whoami: %d %v", code, b)
	}

	// Wrong credentials do not reveal which part was wrong, nor which
	// usernames exist.
	if code, _, _ := f.do("POST", "/api/v1/auth/login", "", `{"username":"nobody","password":"correct horse"}`); code != http.StatusUnauthorized {
		t.Errorf("unknown user: %d, want 401", code)
	}
	if code, _, _ := f.do("POST", "/api/v1/auth/login", "", `{"username":"edward","password":"wrong pass"}`); code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d, want 401", code)
	}

	// Accounts are admin-only.
	if code, _, _ := f.do("GET", "/api/v1/users", f.operator, ""); code != http.StatusForbidden {
		t.Errorf("operator listing users: %d, want 403", code)
	}
	code, body, _ = f.do("POST", "/api/v1/users", f.admin, `{"name":"aide","password":"correct horse","role":"operator"}`)
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %v", code, body)
	}
	if _, leaked := body["password_hash"]; leaked {
		t.Error("password hash serialized to the client")
	}
	aide := ftoa(body["id"].(float64))

	// Password reset revokes the target user's sessions.
	code, _, _ = f.do("PATCH", "/api/v1/users/"+aide, f.admin, `{"password":"brand new pass 9"}`)
	if code != http.StatusNoContent {
		t.Fatalf("password reset: %d", code)
	}
	if _, body, _ = f.do("POST", "/api/v1/auth/login", "", `{"username":"aide","password":"correct horse"}`); body["token"] != nil {
		t.Error("old password still accepted after reset")
	}
	code, _, _ = f.do("POST", "/api/v1/auth/login", "", `{"username":"aide","password":"brand new pass 9"}`)
	if code != http.StatusOK {
		t.Errorf("new password rejected: %d", code)
	}

	// Deleting an account removes it.
	if code, _, _ := f.do("DELETE", "/api/v1/users/"+aide, f.admin, ""); code != http.StatusNoContent {
		t.Fatalf("delete user: %d", code)
	}
	code, _, _ = f.do("POST", "/api/v1/auth/login", "", `{"username":"aide","password":"brand new pass 9"}`)
	if code != http.StatusUnauthorized {
		t.Errorf("deleted account still signs in: %d", code)
	}
}
