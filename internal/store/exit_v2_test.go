package store

import (
	"encoding/base64"
	"testing"
)

// genKey is a valid base64 32-byte key for tests.
func genKey(seed byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed ^ byte(i)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestParseWGConfig(t *testing.T) {
	priv, peer, psk := genKey(1), genKey(2), genKey(3)
	conf := `[Interface]
PrivateKey = ` + priv + `
Address = 10.2.0.2/32

[Peer]
PublicKey = ` + peer + `
PresharedKey = ` + psk + `
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.9:51820
`
	spec, err := ParseWGConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := ExitSpec{Kind: "wireguard", Address: "203.0.113.9:51820",
		WGPrivate: priv, WGPeer: peer, WGPreshared: psk, WGAllowed: "0.0.0.0/0"}
	if spec != want {
		t.Fatalf("parsed %+v, want %+v", spec, want)
	}

	// Broken configs are rejected with a usable message.
	bad := []string{
		"", "[Interface]\n", conf[:len(conf)-len("Endpoint = 203.0.113.9:51820")],
		"[Interface]\nPrivateKey = not-base64!!\n[Peer]\n PublicKey = " + peer,
	}
	for _, b := range bad {
		if _, err := ParseWGConfig(b); err == nil {
			t.Errorf("accepted bad config %q…", b[:min(len(b), 20)])
		}
	}
}

func TestWireGuardExitNeedsKeysOnlyIfGiven(t *testing.T) {
	db, org, _ := exitsDB(t)

	// Bare wireguard exit (no tunnel material) is fine.
	if _, err := AddExitNode(db, org, "bare", ExitSpec{Kind: "wireguard", Address: "vpn.example:51820", AnswerIP: "10.77.0.1"}); err != nil {
		t.Fatalf("bare wireguard exit: %v", err)
	}

	full := ExitSpec{Kind: "wireguard", Address: "vpn.example:51820", AnswerIP: "10.77.0.2",
		WGPrivate: genKey(9), WGPeer: genKey(10), WGPreshared: genKey(11), WGAllowed: "0.0.0.0/0"}
	id, err := AddExitNode(db, org, "full-wg", full)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := GetExitSecrets(db, org, id)
	if err != nil {
		t.Fatal(err)
	}
	if sec.WGPrivate != full.WGPrivate || sec.WGPeer != full.WGPeer || sec.WGAllowed != full.WGAllowed {
		t.Fatalf("secrets %+v, want %+v", sec, full)
	}

	// A malformed key is refused.
	bad := full
	bad.WGPrivate = "c2hvcnQ="
	if err := SetExitNode(db, org, id, bad); err == nil {
		t.Error("accepted a truncated key")
	}

	// Updating with empty fields keeps the stored values.
	if err := SetExitNode(db, org, id, ExitSpec{Address: "vpn2.example:51820"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	sec, _ = GetExitSecrets(db, org, id)
	if sec.WGPrivate != full.WGPrivate {
		t.Error("update dropped the private key")
	}
	if n, _ := GetExitNode(db, org, id); n.Address != "vpn2.example:51820" {
		t.Error("update did not change the address")
	}
}

func TestSocksHttpCredentials(t *testing.T) {
	db, org, _ := exitsDB(t)
	id, err := AddExitNode(db, org, "proxy", ExitSpec{
		Kind: "socks5", Address: "proxy.example:1080", AnswerIP: "10.77.0.3",
		Username: "u", Password: "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := ListExitNodes(db, org)
	if l[0].Username != "u" {
		t.Fatalf("username lost: %+v", l[0])
	}
	sec, _ := GetExitSecrets(db, org, id)
	if sec.Password != "p" {
		t.Fatal("password lost")
	}
}
