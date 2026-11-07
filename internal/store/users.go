package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is a dashboard account. API tokens authenticate scripts; users
// authenticate people, signing in with a username and password.
type User struct {
	ID        int64  `json:"id"`
	OrgID     int64  `json:"org_id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

var userName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$`)

// CreateUser adds a dashboard account to org. The password is hashed with
// bcrypt; the plaintext is never stored.
func CreateUser(db DBTX, org int64, name, password, role string) (User, error) {
	switch role {
	case "admin", "operator", "viewer":
	default:
		return User{}, fmt.Errorf("unknown role %q (admin|operator|viewer)", role)
	}
	name = strings.TrimSpace(name)
	if !userName.MatchString(name) {
		return User{}, errors.New("username must be 2-64 letters, digits, dots, dashes or underscores")
	}
	if len(password) < 8 {
		return User{}, errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	res, err := db.Exec(`INSERT INTO users (org_id, name, password_hash, role) VALUES (?, ?, ?, ?)`,
		org, name, string(hash), role)
	if err != nil {
		return User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return User{ID: id, OrgID: org, Name: name, Role: role, CreatedAt: "—"}, nil
}

// AuthenticateUser verifies a sign-in. Wrong username and wrong password are
// the same error, so the response does not reveal which accounts exist.
func AuthenticateUser(db DBTX, name, password string) (User, error) {
	var u User
	var hash string
	err := db.QueryRow(`SELECT id, org_id, name, password_hash, role FROM users WHERE name = ?`,
		strings.TrimSpace(name)).Scan(&u.ID, &u.OrgID, &u.Name, &hash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn the same time a real bcrypt check takes to even out timing.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5B0X0wJk9yOqG0F/TO0QEyOQ1uBiW"), []byte("timing"))
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, ErrNotFound
	}
	return u, nil
}

// CreateSession mints a bearer token for a signed-in user and records it as
// that user's session. Sessions show up on the API tokens page where they can
// be revoked like any other credential.
func CreateSession(db DBTX, u User) (string, error) {
	return CreateToken(db, u.OrgID, "login: "+u.Name, u.Role)
}

// ListUsers returns the org's dashboard accounts, without password material.
func ListUsers(db DBTX, org int64) ([]User, error) {
	rows, err := db.Query(`SELECT id, org_id, name, role, created_at FROM users WHERE org_id = ? ORDER BY id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Name, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func userInOrg(db DBTX, org, id int64) error {
	var one int
	if err := db.QueryRow(`SELECT 1 FROM users WHERE id = ? AND org_id = ?`, id, org).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %d: %w", id, ErrNotFound)
		}
		return err
	}
	return nil
}

// SetUserPassword changes a user's password (an admin reset, or the user
// changing their own).
func SetUserPassword(db DBTX, org, id int64, password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := userInOrg(db, org, id); err != nil {
		return err
	}
	// Signing out everywhere the old password may have leaked: revoke the
	// user's sessions too.
	_, err = db.Exec(`DELETE FROM api_tokens WHERE name = ? AND org_id = ?`, "login: "+userNameOf(db, org, id), org)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE users SET password_hash = ? WHERE id = ? AND org_id = ?`, string(hash), id, org)
	return err
}

func userNameOf(db DBTX, org, id int64) string {
	var name string
	db.QueryRow(`SELECT name FROM users WHERE id = ? AND org_id = ?`, id, org).Scan(&name)
	return name
}

// SetUserRole changes a user's role.
func SetUserRole(db DBTX, org, id int64, role string) error {
	switch role {
	case "admin", "operator", "viewer":
	default:
		return fmt.Errorf("unknown role %q (admin|operator|viewer)", role)
	}
	if err := userInOrg(db, org, id); err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE users SET role = ? WHERE id = ? AND org_id = ?`, role, id, org)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user %d: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteUser removes a dashboard account and revokes its sessions.
// selfName is the signed-in user's principal name; users cannot delete
// themselves.
func DeleteUser(db DBTX, org, id int64, selfName string) error {
	if err := userInOrg(db, org, id); err != nil {
		return err
	}
	name := userNameOf(db, org, id)
	if "login: "+name == selfName {
		return errors.New("you cannot delete your own account")
	}
	if _, err := db.Exec(`DELETE FROM api_tokens WHERE name = ? AND org_id = ?`, "login: "+name, org); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM users WHERE id = ? AND org_id = ?`, id, org)
	return err
}
