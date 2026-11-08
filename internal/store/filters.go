package store

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/cloudwaddie/opencontrol/internal/catalog"
)

// filters.go — what each profile turns on: built-in filter categories,
// services from the registry, and custom list subscriptions.

// ProfileFilter is one enabled filter, service or list on a profile.
type ProfileFilter struct {
	Kind   string `json:"kind"`  // filter | service | list
	Ref    string `json:"ref"`   // filter id, service id, or blocklist id
	State  string `json:"state"` // block | allow | redirect (services); filters and lists only block
	Level  string `json:"level,omitempty"`
	ExitID int64  `json:"exit_id,omitempty"`
}

var serviceID = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// ListProfileFilters returns the profile's enabled entries, if the profile is in org.
func ListProfileFilters(db DBTX, org, profileID int64) ([]ProfileFilter, error) {
	if err := profileInOrg(db, org, profileID); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT kind, ref, state, level, COALESCE(exit_id, 0)
		FROM profile_filters WHERE profile_id = ? ORDER BY kind, ref`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileFilter{}
	for rows.Next() {
		var f ProfileFilter
		if err := rows.Scan(&f.Kind, &f.Ref, &f.State, &f.Level, &f.ExitID); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetProfileFilter turns an entry on, changes it, or (state "off") removes it.
// Everything it references must belong to org: the profile, a custom list,
// and a redirect's exit.
func SetProfileFilter(db DBTX, org, profileID int64, f ProfileFilter) error {
	if err := profileInOrg(db, org, profileID); err != nil {
		return err
	}
	if err := checkUnlocked(db, profileID); err != nil {
		return err
	}
	if f.State == "off" {
		_, err := db.Exec(`DELETE FROM profile_filters WHERE profile_id = ? AND kind = ? AND ref = ?`,
			profileID, f.Kind, f.Ref)
		return err
	}

	var exit any
	switch f.Kind {
	case "filter":
		flt, _ := catalog.FilterByID(f.Ref, "")
		if flt == nil {
			return fmt.Errorf("unknown filter %q", f.Ref)
		}
		if f.Level == "" {
			f.Level = flt.DefaultLevel()
		}
		if !flt.HasLevel(f.Level) {
			return fmt.Errorf("filter %s has no level %q", f.Ref, f.Level)
		}
		if f.State != "block" {
			return fmt.Errorf("filters can only block")
		}
	case "service":
		if !serviceID.MatchString(f.Ref) {
			return fmt.Errorf("bad service id %q", f.Ref)
		}
		f.Level = ""
		switch f.State {
		case "block", "allow":
		case "redirect":
			if f.ExitID <= 0 {
				return fmt.Errorf("redirect needs an exit")
			}
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM exit_nodes WHERE id = ? AND org_id = ?`, f.ExitID, org).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("exit node not found in this org: %w", ErrNotFound)
			}
			exit = f.ExitID
		default:
			return fmt.Errorf("service state must be block, allow, redirect or off")
		}
	case "list":
		id, err := strconv.ParseInt(f.Ref, 10, 64)
		if err != nil {
			return fmt.Errorf("list ref must be a blocklist id")
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM blocklist_sources WHERE id = ? AND org_id = ?`, id, org).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("blocklist not found in this org: %w", ErrNotFound)
		}
		if f.State != "block" {
			return fmt.Errorf("lists can only block")
		}
		f.Level = ""
	default:
		return fmt.Errorf("kind must be filter, service or list")
	}

	_, err := db.Exec(`INSERT INTO profile_filters (profile_id, kind, ref, state, level, exit_id)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (profile_id, kind, ref) DO UPDATE SET
			state = excluded.state, level = excluded.level, exit_id = excluded.exit_id,
			updated_at = datetime('now')`,
		profileID, f.Kind, f.Ref, f.State, f.Level, exit)
	return err
}

func profileInOrg(db DBTX, org, profileID int64) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM profiles WHERE id = ? AND org_id = ?`, profileID, org).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("profile not found in this org: %w", ErrNotFound)
	}
	return nil
}
