package qlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/store"
)

// Webhook POSTs each batch as a JSON array to a URL.
type Webhook struct {
	URL  string
	HTTP *http.Client
}

func NewWebhook(url string) *Webhook {
	return &Webhook{URL: url, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (w *Webhook) Send(batch []store.QueryLog) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := w.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", w.URL, err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("webhook %s: status %d", w.URL, res.StatusCode)
	}
	return nil
}

// Syslog sends one RFC 5424-shaped UDP datagram per event.
type Syslog struct {
	conn net.Conn
}

func NewSyslog(addr string) (*Syslog, error) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("syslog %s: %w", addr, err)
	}
	return &Syslog{conn: c}, nil
}

// clean keeps one syslog token free of spaces and line breaks.
var clean = strings.NewReplacer(" ", "_", "\n", "_", "\r", "_")

func (s *Syslog) Send(batch []store.QueryLog) error {
	for _, e := range batch {
		ts := time.Unix(e.Ts, 0).UTC().Format(time.RFC3339)
		line := fmt.Sprintf("<134>1 %s opencontrol opencontrol - - - org=%d client=%s action=%s qtype=%s qname=%s reason=%s",
			ts, e.Org, clean.Replace(e.Client), clean.Replace(e.Action), clean.Replace(e.QType),
			clean.Replace(e.QName), clean.Replace(e.Reason))
		if _, err := s.conn.Write([]byte(line)); err != nil {
			return fmt.Errorf("syslog write: %w", err)
		}
	}
	return nil
}
