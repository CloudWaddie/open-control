// Open Control — self-hosted DNS filtering platform.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
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
  opencontrol addrule PROFILE_ID KIND MATCHER TARGET [NOTE]
                                        rule kinds: block|allow|rewrite|redirect
                                        matchers:   domain|wildcard|tld
  opencontrol addlist URL [FORMAT]      subscribe to a blocklist (hosts|dnsmasq|adguard)

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

	snap, err := store.LoadSnapshot(db, cfg.DataDir)
	if err != nil {
		log.Fatalf("policy snapshot: %v", err)
	}

	r := resolver.New(cfg)
	r.SetSnapshot(snap)
	log.Printf("policy snapshot loaded: %s", snap.Summary())

	// Periodic recompile: picks up new rules and refreshed blocklists without
	// downtime (atomic swap; in-flight queries keep the previous snapshot).
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			snap, err := store.LoadSnapshot(db, cfg.DataDir)
			if err != nil {
				log.Printf("policy snapshot refresh failed: %v", err)
				continue
			}
			r.SetSnapshot(snap)
			log.Printf("policy snapshot reloaded: %s", snap.Summary())
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
	snap, err := store.LoadSnapshot(db, cfg.DataDir)
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
	kind, matcher, target := args[1], args[2], args[3]
	note := ""
	if len(args) > 4 {
		note = strings.Join(args[4:], " ")
	}
	if err := store.AddRule(db, profileID, kind, matcher, target, note); err != nil {
		log.Fatalf("addrule: %v", err)
	}
	log.Printf("addrule: %s %s %s → profile %d (pick up: restart serve or wait for snapshot refresh)", kind, matcher, target, profileID)
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
