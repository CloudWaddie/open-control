// Package egress checks whether exit nodes are usable (PLAN.md M5).
//
// SOCKS5 exits are probed with a real protocol handshake: a TCP connection and
// the SOCKS5 greeting (05 01 00) must get back 05 00. A plain open port is not
// enough. WireGuard exits cannot be verified without bringing up a tunnel, so
// they report "unknown", which the resolver treats as usable.
package egress

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

const (
	Healthy = "healthy"
	Down    = "down"
	Unknown = "unknown"
)

// Probe checks one exit and returns its health state.
func Probe(kind, address string, timeout time.Duration) (string, error) {
	switch kind {
	case "socks5":
		return probeSOCKS5(address, timeout)
	case "wireguard":
		if _, _, err := net.SplitHostPort(address); err != nil {
			return Down, fmt.Errorf("endpoint %q: %w", address, err)
		}
		return Unknown, nil
	default:
		return Down, fmt.Errorf("unknown exit kind %q", kind)
	}
}

func probeSOCKS5(address string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return Down, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Greeting: version 5, one method, "no authentication".
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return Down, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return Down, fmt.Errorf("no SOCKS5 reply: %w", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return Down, fmt.Errorf("unexpected SOCKS5 reply %x", reply)
	}
	return Healthy, nil
}

// Checker probes every exit on an interval and records changes. OnChange runs
// after a state change so the resolver can reload its snapshot.
type Checker struct {
	DB       *sql.DB
	Interval time.Duration
	Timeout  time.Duration
	OnChange func()
}

func (c *Checker) interval() time.Duration {
	if c.Interval <= 0 {
		return 30 * time.Second
	}
	return c.Interval
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Second
	}
	return c.Timeout
}

// CheckRecord probes one exit, stores the result, and reports whether it changed.
func (c *Checker) CheckRecord(rec store.ExitRecord) (string, error) {
	health, probeErr := Probe(rec.Kind, rec.Address, c.timeout())
	if probeErr != nil {
		log.Printf("egress: exit %s (%s) %s: %v", rec.Name, rec.Address, health, probeErr)
	}
	changed := health != rec.Health
	if err := store.SetExitHealth(c.DB, rec.ID, health); err != nil {
		return health, err
	}
	if changed {
		log.Printf("egress: exit %s is now %s", rec.Name, health)
		if c.OnChange != nil {
			c.OnChange()
		}
	}
	return health, nil
}

// CheckAll probes every exit once.
func (c *Checker) CheckAll() error {
	recs, err := store.ListAllExitRecords(c.DB)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if _, err := c.CheckRecord(r); err != nil {
			return err
		}
	}
	return nil
}

// Run checks all exits now and then every interval, until ctx is cancelled.
func (c *Checker) Run(ctx context.Context) {
	_ = c.CheckAll()
	t := time.NewTicker(c.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.CheckAll()
		}
	}
}
