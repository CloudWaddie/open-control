package egress

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

// fakeSOCKS5 accepts connections and answers the greeting with reply.
func fakeSOCKS5(t *testing.T, reply []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				greet := make([]byte, 3)
				if _, err := io.ReadFull(c, greet); err != nil {
					return
				}
				c.Write(reply)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSOCKS5ProbeNeedsARealHandshake(t *testing.T) {
	good := fakeSOCKS5(t, []byte{0x05, 0x00})
	if h, err := Probe("socks5", good, time.Second); h != Healthy || err != nil {
		t.Errorf("real SOCKS5 proxy: %s %v, want healthy", h, err)
	}

	// Something listens on the port but does not speak SOCKS5.
	imposter := fakeSOCKS5(t, []byte("HTTP/1.1 400 bad request\r\n"))
	if h, _ := Probe("socks5", imposter, time.Second); h != Down {
		t.Errorf("non-SOCKS5 listener: %s, want down", h)
	}

	// SOCKS5 that demands authentication (0xFF = no acceptable method) is not usable here.
	authOnly := fakeSOCKS5(t, []byte{0x05, 0xFF})
	if h, _ := Probe("socks5", authOnly, time.Second); h != Down {
		t.Errorf("auth-only SOCKS5: %s, want down", h)
	}

	// Nothing listening at all.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if h, _ := Probe("socks5", closed, 500*time.Millisecond); h != Down {
		t.Errorf("closed port: %s, want down", h)
	}
}

func TestWireGuardIsUnknownNotHealthy(t *testing.T) {
	if h, err := Probe("wireguard", "vpn.example.net:51820", time.Second); h != Unknown || err != nil {
		t.Errorf("wireguard endpoint: %s %v, want unknown (cannot probe without a tunnel)", h, err)
	}
	if h, _ := Probe("wireguard", "no-port", time.Second); h != Down {
		t.Errorf("malformed wireguard endpoint: %s, want down", h)
	}
}

// A state change calls OnChange once; a repeat of the same state does not.
func TestCheckerNotifiesOnlyOnChange(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedDefaults(db); err != nil {
		t.Fatal(err)
	}
	org, _ := store.DefaultOrgID(db)
	good := fakeSOCKS5(t, []byte{0x05, 0x00})
	id, err := store.AddExitNode(db, org, "vps", "socks5", good, "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}

	changes := 0
	c := &Checker{DB: db, Timeout: time.Second, OnChange: func() { changes++ }}
	if err := c.CheckAll(); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAll(); err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Errorf("unknown→healthy notified %d times, want 1 (second pass unchanged)", changes)
	}
	ex, _ := store.GetExitNode(db, org, id)
	if ex.Health != Healthy {
		t.Errorf("stored health %q, want healthy", ex.Health)
	}
}
