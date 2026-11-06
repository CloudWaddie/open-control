package policy

import (
	"net/netip"
	"testing"
)

func TestEndpointLongestPrefixWins(t *testing.T) {
	broad, err := NewCidrSetFromJSON(`["0.0.0.0/0"]`)
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := NewCidrSetFromJSON(`["10.9.0.0/16"]`)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately load the broad endpoint first.
	snap := NewSnapshot([]*Endpoint{
		{ID: 1, Name: "default", ProfileID: 1, Allowed: broad},
		{ID: 2, Name: "kids", ProfileID: 2, Allowed: narrow},
	}, map[int64]*Profile{})

	cases := map[string]int64{
		"10.9.4.7":  2, // inside narrow → kids
		"192.0.2.1": 1, // outside narrow → default
	}
	for ip, want := range cases {
		e := snap.EndpointForClientIP(netip.MustParseAddr(ip))
		if e == nil || e.ID != want {
			t.Errorf("EndpointForClientIP(%s) = %v, want endpoint %d", ip, e, want)
		}
	}
}

func TestEmptyAllowlistMatchesNothing(t *testing.T) {
	empty, err := NewCidrSetFromJSON(`[]`)
	if err != nil {
		t.Fatal(err)
	}
	snap := NewSnapshot([]*Endpoint{{ID: 1, Allowed: empty}}, nil)
	if e := snap.EndpointForClientIP(netip.MustParseAddr("127.0.0.1")); e != nil {
		t.Fatalf("empty allowlist matched endpoint %d; must fail closed", e.ID)
	}
}
