// Open Control — self-hosted DNS filtering platform.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/resolver"
	"github.com/cloudwaddie/opencontrol/internal/store"
)

const usage = `opencontrol — self-hosted DNS filtering platform

Usage:
  opencontrol serve                     run the resolver + policy engine
  opencontrol migrate                   apply schema migrations
  opencontrol sync                      refresh blocklist subscriptions once
  opencontrol addrule PROFILE_ID KIND MATCHER PATTERN [ANSWER]
                                        rule kinds: block|allow|rewrite|redirect
                                        matchers:   domain|wildcard|tld
                                        rewrite:    domain + ANSWER (IP or name)
  opencontrol addlist URL [FORMAT]      subscribe to a blocklist (hosts|dnsmasq|adguard)
  opencontrol addprofile NAME           create a profile, prints its id
  opencontrol addendpoint NAME PROFILE_ID CIDR[,CIDR...]
                                        create an endpoint; clients in CIDRs get PROFILE

Env: OC_LISTEN, OC_SQLITE_PATH, OC_DATA_DIR. Config file via -config path.yaml.
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("opencontrol: ")
	cfgPath := flag.String("config", "", "YAML config file path")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch flag.Arg(0) {
	case "serve":
		runServe(*cfgPath)
	case "migrate":
		runMigrate(*cfgPath)
	case "sync":
		runSync(*cfgPath)
	case "addrule":
		if flag.NArg() < 5 {
			fmt.Fprint(os.Stderr, "usage: opencontrol addrule PROFILE_ID KIND MATCHER TARGET [NOTE]\n")
			os.Exit(2)
		}
		runAddRule(*cfgPath, flag.Args()[1:])
	case "addprofile":
		if flag.NArg() < 2 {
			fmt.Fprint(os.Stderr, "usage: opencontrol addprofile NAME\n")
			os.Exit(2)
		}
		_, db := openDB(*cfgPath)
		defer db.Close()
		id, err := store.AddProfile(db, flag.Arg(1))
		if err != nil {
			log.Fatalf("addprofile: %v", err)
		}
		fmt.Println(id)
	case "addendpoint":
		if flag.NArg() < 4 {
			fmt.Fprint(os.Stderr, "usage: opencontrol addendpoint NAME PROFILE_ID CIDR[,CIDR...]\n")
			os.Exit(2)
		}
		profileID, err := strconv.ParseInt(flag.Arg(2), 10, 64)
		if err != nil {
			log.Fatalf("addendpoint: PROFILE_ID must be an integer (got %q)", flag.Arg(2))
		}
		_, db := openDB(*cfgPath)
		defer db.Close()
		id, token, err := store.AddEndpoint(db, flag.Arg(1), profileID, flag.Arg(3))
		if err != nil {
			log.Fatalf("addendpoint: %v", err)
		}
		log.Printf("addendpoint: %s (id %d) → profile %d, sources %s", flag.Arg(1), id, profileID, flag.Arg(3))
		fmt.Println(token)
	case "addlist":
		if flag.NArg() < 2 {
			fmt.Fprint(os.Stderr, "usage: opencontrol addlist URL [FORMAT]\n")
			os.Exit(2)
		}
		runAddList(*cfgPath, flag.Args()[1:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func loadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	return cfg
}

func openDB(cfgPath string) (*config.Config, *sql.DB) {	cfg := loadConfig(cfgPath)
	db, err := store.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatalf("store open: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		log.Fatalf("store migrate: %v", err)
	}
	if err := store.SeedDefaults(db); err != nil {
		log.Fatalf("store seed: %v", err)
	}
	return cfg, db
}

func runServe(cfgPath string) {
	cfg, db := openDB(cfgPath)

	// Boot from cached blocklists only: the resolver must start serving even if
	// a list host is slow or down. Fresh lists are fetched in the background.
	snap, err := store.LoadSnapshot(db, cfg.DataDir, false)
	if err != nil {
		log.Fatalf("policy snapshot: %v", err)
	}

	r := resolver.New(cfg)
	r.SetSnapshot(snap)
	log.Printf("policy snapshot loaded (cached lists): %s", snap.Summary())

	// reload recompiles rules + blocklists and swaps atomically; in-flight
	// queries keep the previous snapshot, so nothing is dropped.
	reload := func(fetch bool) {
		s, err := store.LoadSnapshot(db, cfg.DataDir, fetch)
		if err != nil {
			log.Printf("policy snapshot reload failed: %v", err)
			return
		}
		r.SetSnapshot(s)
		log.Printf("policy snapshot reloaded (fetch=%v): %s", fetch, s.Summary())
	}

	// Triggers: first fetch right after boot, then hourly, plus SIGHUP for
	// instant rule changes (e.g. `docker kill -s HUP`).
	go func() {
		reload(true)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			reload(true)
		}
	}()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reload(false) // rules only; lists refresh on the hourly fetch
		}
	}()

	if err := r.ListenAndServe(); err != nil {
		log.Fatalf("resolver: %v", err)
	}
}

func runMigrate(cfgPath string) {
	cfg := loadConfig(cfgPath)
	db, err := store.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatalf("store open: %v", err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		log.Fatalf("store migrate: %v", err)
	}
	log.Println("migrate: done")
}

func runSync(cfgPath string) {
	cfg, db := openDB(cfgPath)
	defer db.Close()
	snap, err := store.LoadSnapshot(db, cfg.DataDir, true)
	if err != nil {
		log.Fatalf("sync: %v", err)
	}
	log.Printf("sync: %s", snap.Summary())
}

func runAddRule(cfgPath string, args []string) {
	cfg, db := openDB(cfgPath)
	defer db.Close()
	_ = cfg

	profileID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		log.Fatalf("addrule: PROFILE_ID must be an integer (got %q)", args[0])
	}
	kind, matcher, pattern := args[1], args[2], args[3]
	answer := ""
	if len(args) > 4 {
		answer = args[4] // rewrite answer; ignored by other kinds
	}
	if err := store.AddRule(db, profileID, kind, matcher, pattern, answer); err != nil {
		log.Fatalf("addrule: %v", err)
	}
	log.Printf("addrule: %s %s %s → profile %d (applies on next snapshot reload; restart serve to apply now)", kind, matcher, pattern, profileID)
}

func runAddList(cfgPath string, args []string) {
	_, db := openDB(cfgPath)
	defer db.Close()

	url := args[0]
	format := "hosts"
	if len(args) > 1 {
		format = args[1]
	}
	if err := store.AddBlocklistSource(db, url, format); err != nil {
		log.Fatalf("addlist: %v", err)
	}
	log.Printf("addlist: %s (%s) subscribed — run 'opencontrol sync' to fetch now", url, format)
}
