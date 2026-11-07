package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cloudwaddie/opencontrol/internal/policy"
)

// settings.go — profile options and locks, the org's default profile, moving
// endpoints between profiles, and exit IPv6 answers.

// LockedError is returned when a change targets a locked profile.
type LockedError struct{ Message string }

func (e *LockedError) Error() string {
	if e.Message != "" {
		return "profile is locked: " + e.Message
	}
	return "profile is locked"
}

// GetProfileOptions returns the options of one of org's profiles.
func GetProfileOptions(db DBTX, org, profileID int64) (policy.Options, error) {
	var raw string
	err := db.QueryRow(`SELECT options FROM profiles WHERE id = ? AND org_id = ?`, profileID, org).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.Options{}, fmt.Errorf("profile not found in this org: %w", ErrNotFound)
	}
	if err != nil {
		return policy.Options{}, err
	}
	return parseOptions(raw), nil
}

// SetProfileOptions validates and stores options. A locked profile only
// accepts a change that unlocks it; the caller checks who may unlock.
func SetProfileOptions(db DBTX, org, profileID int64, o policy.Options) (policy.Options, error) {
	cur, err := GetProfileOptions(db, org, profileID)
	if err != nil {
		return o, err
	}
	if cur.Locked && o.Locked {
		return o, &LockedError{Message: cur.LockMessage}
	}
	if cur.Locked && !o.Locked {
		o = cur // unlocking changes nothing else
		o.Locked, o.LockMessage = false, ""
	}
	n, err := o.Normalize()
	if err != nil {
		return o, err
	}
	b, err := json.Marshal(n)
	if err != nil {
		return o, err
	}
	_, err = db.Exec(`UPDATE profiles SET options = ? WHERE id = ? AND org_id = ?`, string(b), profileID, org)
	return n, err
}

// checkUnlocked refuses changes to a locked profile's rules, filters and services.
func checkUnlocked(db DBTX, profileID int64) error {
	var raw string
	if err := db.QueryRow(`SELECT options FROM profiles WHERE id = ?`, profileID).Scan(&raw); err != nil {
		return nil // a missing profile is reported by the ownership check
	}
	if o := parseOptions(raw); o.Locked {
		return &LockedError{Message: o.LockMessage}
	}
	return nil
}

func parseOptions(raw string) policy.Options {
	var o policy.Options
	_ = json.Unmarshal([]byte(raw), &o) // bad JSON reads as defaults
	return o
}

// DefaultProfileID returns org's default profile (0 if unset).
func DefaultProfileID(db DBTX, org int64) (int64, error) {
	var id sql.NullInt64
	if err := db.QueryRow(`SELECT default_profile_id FROM orgs WHERE id = ?`, org).Scan(&id); err != nil {
		return 0, err
	}
	return id.Int64, nil
}

// SetDefaultProfile makes one of org's profiles the default.
func SetDefaultProfile(db DBTX, org, profileID int64) error {
	if err := profileInOrg(db, org, profileID); err != nil {
		return err
	}
	_, err := db.Exec(`UPDATE orgs SET default_profile_id = ? WHERE id = ?`, profileID, org)
	return err
}

// SetEndpointProfile moves an endpoint to another of org's profiles.
func SetEndpointProfile(db DBTX, org, endpointID, profileID int64) error {
	if err := profileInOrg(db, org, profileID); err != nil {
		return err
	}
	return deleteRow(db, `UPDATE endpoints SET profile_id = ? WHERE id = ? AND org_id = ?`, profileID, endpointID, org)
}

// SetExitIPv6 sets (or clears, with "") the IPv6 answer of one of org's exits.
func SetExitIPv6(db DBTX, org, id int64, v6 string) error {
	if v6 != "" {
		a, err := netip.ParseAddr(v6)
		if err != nil || !a.Is6() || a.Is4In6() {
			return fmt.Errorf("answer_ipv6 must be an IPv6 address")
		}
		v6 = a.String()
	}
	return deleteRow(db, `UPDATE exit_nodes SET answer_ipv6 = ? WHERE id = ? AND org_id = ?`, v6, id, org)
}
