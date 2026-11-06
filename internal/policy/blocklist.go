package policy

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// blocklist.go — download + parse subscribed blocklist sources into domain
// entries (M1). Parsing is format-tolerant: hosts/hosts-like lines, bare
// domains, dnsmasq and adguard rules all reduce to the domain token. Anything
// unparseable or comment-like is skipped.

// FetchBlocklist downloads url (ETag-aware, cached under dir) and returns the
// extracted domains.
func FetchBlocklist(url, dir string) ([]string, error) {
	cachePath, err := cachePathFor(url, dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	etag, _ := os.ReadFile(cachePath + ".etag")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if len(etag) > 0 {
		req.Header.Set("If-None-Match", strings.TrimSpace(string(etag)))
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Offline / upstream failure: fall back to last good cache copy.
		return parseFile(cachePath)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && fileExists(cachePath):
		return parseFile(cachePath)
	case resp.StatusCode != http.StatusOK:
		return parseFile(cachePath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if lm := resp.Header.Get("ETag"); lm != "" {
		_ = os.WriteFile(cachePath+".etag", []byte(lm), 0o644)
	}
	if err := os.WriteFile(cachePath, body, 0o644); err != nil {
		return nil, err
	}
	return parseDomains(string(body)), nil
}

// ParseDomains extracts blockable entries from any line-oriented list.
func parseDomains(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		// adguard: ||domain^  and  ||domain^$third-party
		if strings.HasPrefix(line, "||") {
			line = strings.Trim(line[2:], "^ \t")
			line = strings.SplitN(line, "$", 2)[0]
		} else {
			// hosts lines "0.0.0.0 domain", "127.0.0.1 domain domain2 …";
			// bare domain lines pass through unchanged.
			fields := strings.Fields(line)
			if len(fields) > 1 {
				fields = fields[1:] // drop the leading IP
			}
			if len(fields) == 0 {
				continue
			}
			line = fields[0]
		}
		d := strings.ToLower(strings.TrimSuffix(line, "."))
		if !strings.Contains(d, ".") {
			continue // ignore "localhost" etc. — nothing resolvable to block precisely
		}
		if strings.HasPrefix(d, "*") || strings.HasPrefix(d, "@@") {
			continue
		}
		out = append(out, d)
	}
	return out
}

func parseFile(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("blocklist cache read: %w", err)
	}
	return parseDomains(string(body)), nil
}

func cachePathFor(url, dir string) (string, error) {
	sum := md5.Sum([]byte(url))
	return dir + "/bl_" + hex.EncodeToString(sum[:8]) + ".txt", nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
