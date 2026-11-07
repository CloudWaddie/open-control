package policy

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// blocklist.go — download, cache and compile list sources. Parsing is
// format-tolerant: hosts lines, bare domains, dnsmasq and adguard rules all
// reduce to the domain token. Anything unparseable or comment-like is skipped.
//
// Compiled lists are cached per process and keyed by the cached file's size and
// modification time. A list shared by many profiles is held in memory once, and
// a rules-only reload does not re-parse million-entry lists.

// FetchMode controls when LoadList goes to the network.
type FetchMode int

const (
	FetchNone    FetchMode = iota // disk cache only (boot: never wait on the network)
	FetchMissing                  // download lists that were never fetched
	FetchAll                      // refresh every list (ETag-aware)
)

// ListFormat says how list lines are read.
type ListFormat string

const (
	FormatDomains ListFormat = "domains" // hosts / dnsmasq / adguard / bare domains
	FormatTLDs    ListFormat = "tlds"    // one bare TLD per line ("zip"), blocks the whole TLD
)

const maxListBytes = 256 << 20 // refuse absurd downloads

var listClient = &http.Client{Timeout: 90 * time.Second}

type compiledList struct {
	size    int64
	modTime time.Time
	set     *domainSet
}

var (
	listMu    sync.Mutex
	listCache = map[string]*compiledList{} // cache path → compiled set
	fetchMu   sync.Map                     // cache path → *sync.Mutex
)

// LoadList returns the compiled set for url, downloading it first according to
// mode. When a download fails the last good copy is used; with no copy at all
// an error is returned.
func LoadList(url, dir string, format ListFormat, mode FetchMode) (*DomainSet, error) {
	path, err := FetchFile(url, dir, mode)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	listMu.Lock()
	c := listCache[path]
	listMu.Unlock()
	if c != nil && c.size == st.Size() && c.modTime.Equal(st.ModTime()) {
		return c.set, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := parseList(f, format)
	listMu.Lock()
	listCache[path] = &compiledList{size: st.Size(), modTime: st.ModTime(), set: set}
	listMu.Unlock()
	return set, nil
}

// FetchFile makes sure url is in the cache dir according to mode and returns
// the cached file's path. A failed download falls back to the last good copy.
func FetchFile(url, dir string, mode FetchMode) (string, error) {
	path := cachePathFor(url, dir)
	if mode == FetchAll || (mode == FetchMissing && !fileExists(path)) {
		if err := download(url, path); err != nil {
			if !fileExists(path) {
				return "", err
			}
			log.Printf("policy: refresh %s failed, using cached copy: %v", url, err)
		}
	}
	if !fileExists(path) {
		return "", fmt.Errorf("not downloaded yet")
	}
	return path, nil
}

// ListFetchedAt reports when url was last downloaded successfully (zero if never).
func ListFetchedAt(url, dir string) time.Time {
	path := cachePathFor(url, dir)
	var t time.Time
	for _, p := range []string{path, path + ".checked"} {
		if st, err := os.Stat(p); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

// download fetches url into path, honouring the stored ETag. The file is
// replaced atomically, so readers never see a half-written list.
func download(url, path string) error {
	m, _ := fetchMu.LoadOrStore(path, &sync.Mutex{})
	m.(*sync.Mutex).Lock()
	defer m.(*sync.Mutex).Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "opencontrol (+https://github.com/CloudWaddie/open-control)")
	if etag, _ := os.ReadFile(path + ".etag"); len(etag) > 0 && fileExists(path) {
		req.Header.Set("If-None-Match", strings.TrimSpace(string(etag)))
	}
	resp, err := listClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		// Content unchanged: record the check without touching the list file,
		// whose mtime keys the compiled cache.
		return os.WriteFile(path+".checked", nil, 0o644)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxListBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxListBytes {
		return fmt.Errorf("%s: larger than %d MiB", url, maxListBytes>>20)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = os.WriteFile(path+".etag", []byte(etag), 0o644)
	} else {
		_ = os.Remove(path + ".etag")
	}
	return nil
}

func parseList(r io.Reader, format ListFormat) *domainSet {
	set := NewDomainSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if format == FormatTLDs {
			tld := strings.ToLower(strings.Trim(string(line), "."))
			if tld != "" && tld[0] != '#' && !strings.ContainsAny(tld, ". \t") {
				set.Add("."+tld, true)
			}
			continue
		}
		if d := parseLine(string(line)); d != "" {
			set.Add(d, true) // lists block subdomains implicitly
		}
	}
	return set
}

// parseDomains extracts blockable entries from any line-oriented list.
func parseDomains(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if d := parseLine(line); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func parseLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' {
		return ""
	}
	if strings.HasPrefix(line, "||") {
		// adguard: ||domain^  and  ||domain^$third-party
		line = strings.SplitN(line[2:], "$", 2)[0]
		line = strings.Trim(line, "^ \t")
	} else {
		// hosts lines "0.0.0.0 domain", "127.0.0.1 domain domain2 …";
		// bare domain lines pass through unchanged.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) > 1 {
			fields = fields[1:] // drop the leading IP
		}
		if len(fields) == 0 {
			return ""
		}
		line = fields[0]
	}
	d := strings.ToLower(strings.TrimSuffix(line, "."))
	d = strings.TrimPrefix(d, "*.") // wildcard-format lists: subdomains are implied anyway
	if !strings.Contains(d, ".") {
		return "" // ignore "localhost" etc. — nothing resolvable to block precisely
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "" // a bare IP (e.g. the sink "0.0.0.0" in hosts files) is not a domain
	}
	if strings.ContainsAny(d, "*@/|^$ ") {
		return ""
	}
	return d
}

// CachePath is where url's download is cached under dir.
func CachePath(url, dir string) string { return cachePathFor(url, dir) }

func cachePathFor(url, dir string) string {
	sum := md5.Sum([]byte(url))
	return filepath.Join(dir, "bl_"+hex.EncodeToString(sum[:8])+".txt")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
