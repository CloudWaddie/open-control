// Open Control — self-hosted DNS filtering platform.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/control"
	"github.com/cloudwaddie/opencontrol/internal/egress"
	"github.com/cloudwaddie/opencontrol/internal/metrics"
	"github.com/cloudwaddie/opencontrol/internal/policy"
	"github.com/cloudwaddie/opencontrol/internal/qlog"
	"github.com/cloudwaddie/opencontrol/internal/resolver"
	"github.com/cloudwaddie/opencontrol/internal/store"
)

const usage = `opencontrol — self-hosted DNS filtering platform

Usage:
  opencontrol serve                     run the resolver + policy engine
  opencontrol version                   print the version
  opencontrol healthcheck               exit 0 if the local API answers /healthz (for containers)
  opencontrol backup FILE               write a consistent copy of the database to FILE
  opencontrol migrate                   apply schema migrations
  opencontrol sync                      refresh blocklist subscriptions once
  opencontrol addrule PROFILE_ID KIND MATCHER PATTERN [ANSWER]
                                        rule kinds: block|allow|rewrite|redirect
                                        matchers:   domain|wildcard|tld
                                        rewrite:    domain + ANSWER (IP or name)
  opencontrol addlist URL [FORMAT]      subscribe to a blocklist (hosts|dnsmasq|adguard)
  opencontrol addorg NAME               create an org (tenant), prints its id
  opencontrol addtoken NAME ROLE [ORG]  mint an API token (admin|operator|viewer) for ORG
  opencontrol adduser NAME ROLE PASSWORD  create a dashboard account (USERNAME/ROLE/PASSWORD)
                                        (default: the default org), printed once
  opencontrol addprofile NAME           create a profile, prints its id
  opencontrol addendpoint NAME PROFILE_ID CIDR[,CIDR...]
                                        create an endpoint; clients in CIDRs get PROFILE

Config file via -config path.yaml; every setting also has an OC_* env var
(see README). Common: OC_LISTEN, OC_API_LISTEN, OC_SQLITE_PATH, OC_DATA_DIR.
`

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

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
	case "version":
		fmt.Println(version)
	case "healthcheck":
		runHealthcheck(*cfgPath)
	case "backup":
		if flag.NArg() < 2 {
			fmt.Fprint(os.Stderr, "usage: opencontrol backup FILE\n")
			os.Exit(2)
		}
		runBackup(*cfgPath, flag.Arg(1))
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
		id, err := store.AddProfile(db, defaultOrg(db), flag.Arg(1))
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
		id, token, err := store.AddEndpoint(db, defaultOrg(db), flag.Arg(1), profileID, flag.Arg(3))
		if err != nil {
			log.Fatalf("addendpoint: %v", err)
		}
		log.Printf("addendpoint: %s (id %d) → profile %d, sources %s", flag.Arg(1), id, profileID, flag.Arg(3))
		fmt.Println(token)
	case "addtoken":
		if flag.NArg() < 3 {
			fmt.Fprint(os.Stderr, "usage: opencontrol addtoken NAME admin|operator|viewer\n")
			os.Exit(2)
		}
		_, db := openDB(*cfgPath)
		defer db.Close()
		org := defaultOrg(db)
		orgName := "default"
		if flag.NArg() > 3 {
			orgName = flag.Arg(3)
			id, err := store.OrgIDByName(db, orgName)
			if err != nil {
				log.Fatalf("addtoken: %v", err)
			}
			org = id
		}
		tok, err := store.CreateToken(db, org, flag.Arg(1), flag.Arg(2))
		if err != nil {
			log.Fatalf("addtoken: %v", err)
		}
		log.Printf("addtoken: %s (%s) for org %s — copy it now, it is not shown again", flag.Arg(1), flag.Arg(2), orgName)
		fmt.Println(tok)
	case "adduser":
		if flag.NArg() < 4 {
			fmt.Fprint(os.Stderr, "usage: opencontrol adduser NAME ROLE PASSWORD\n")
			os.Exit(2)
		}
		_, db := openDB(*cfgPath)
		defer db.Close()
		u, err := store.CreateUser(db, defaultOrg(db), flag.Arg(1), flag.Arg(3), flag.Arg(2))
		if err != nil {
			log.Fatalf("adduser: %v", err)
		}
		log.Printf("adduser: %s (%s) can sign in with the given password", u.Name, u.Role)
	case "addorg":
		if flag.NArg() < 2 {
			fmt.Fprint(os.Stderr, "usage: opencontrol addorg NAME\n")
			os.Exit(2)
		}
		_, db := openDB(*cfgPath)
		defer db.Close()
		id, err := store.CreateOrg(db, flag.Arg(1))
		if err != nil {
			log.Fatalf("addorg: %v", err)
		}
		fmt.Println(id)
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

// defaultOrg is the org the CLI manages. Use the API with an org's token for others.
func defaultOrg(db *sql.DB) int64 {
	id, err := store.DefaultOrgID(db)
	if err != nil {
		log.Fatalf("no org: %v", err)
	}
	return id
}

func openDB(cfgPath string) (*config.Config, *sql.DB) {
	cfg := loadConfig(cfgPath)
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
	log.Printf("opencontrol %s starting", version)

	// Boot from cached blocklists only: the resolver must start serving even if
	// a list host is slow or down. Fresh lists are fetched in the background.
	snap, err := store.LoadSnapshot(db, cfg.DataDir, policy.FetchNone)
	if err != nil {
		log.Fatalf("policy snapshot: %v", err)
	}

	// Query log: decisions are recorded without blocking DNS; a background writer
	// batches them into SQLite and fans them out to the configured sinks.
	var sinks []qlog.Sink
	if cfg.WebhookURL != "" {
		sinks = append(sinks, qlog.NewWebhook(cfg.WebhookURL))
	}
	if cfg.SyslogAddr != "" {
		sl, err := qlog.NewSyslog(cfg.SyslogAddr)
		if err != nil {
			log.Fatalf("query log: %v", err)
		}
		sinks = append(sinks, sl)
	}
	logger := qlog.New(db, cfg.LogBuffer, sinks...)
	metrics.NewGauge("opencontrol_querylog_dropped_total", "Query-log events dropped (buffer full or write failed).",
		func() float64 { return float64(logger.Dropped()) })

	bg, stopBG := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	goBG := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	goBG(func() { logger.Run(bg) })
	goBG(func() { qlog.Retention(bg, db, cfg.LogRetentionDays) })

	r := resolver.New(cfg)
	r.SetRecorder(logger)
	r.SetSnapshot(snap)

	log.Printf("policy snapshot loaded (cached lists): %s", snap.Summary())

	// reload recompiles rules + blocklists and swaps atomically; in-flight
	// queries keep the previous snapshot, so nothing is dropped. Reloads are
	// serialized so a slow fetch cannot race a quick rules-only reload and
	// install an older snapshot last.
	var reloadMu sync.Mutex
	reload := func(fetch bool) {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		mode := policy.FetchMissing // a settings change: download newly enabled lists
		if fetch {
			mode = policy.FetchAll
		}
		s, err := store.LoadSnapshot(db, cfg.DataDir, mode)
		if err != nil {
			log.Printf("policy snapshot reload failed: %v", err)
			return
		}
		r.SetSnapshot(s)
		log.Printf("policy snapshot reloaded (fetch=%v): %s", fetch, s.Summary())
	}

	// Exit health: probe exits in the background. A state change reloads the
	// snapshot so redirects stop (or resume) without a restart.
	checker := &egress.Checker{DB: db, OnChange: func() { reload(false) }}
	goBG(func() { checker.Run(bg) })

	// First fetch right after boot, then hourly, plus SIGHUP for instant rule
	// changes (e.g. `docker kill -s HUP`).
	goBG(func() {
		reload(true)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-t.C:
				reload(true)
			}
		}
	})
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reload(false) // rules only; lists refresh on the hourly fetch
		}
	}()

	// Control plane. Writes reload the snapshot immediately.
	handler := control.Handler(db, func() { reload(false) }, checker, cfg.DataDir)
	control.SetSetup(handler, control.Setup{
		Host: cfg.PublicHost, DoHPort: cfg.PublicDoHPort, DoTPort: cfg.PublicDoTPort,
		DoH: cfg.DoHListen != "", DoT: cfg.DoTListen != "",
	})
	api := &http.Server{
		Addr:              cfg.APIListen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	fatal := make(chan error, 3)
	go func() {
		log.Printf("control: API and web UI listening on %s", cfg.APIListen)
		if err := api.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal <- fmt.Errorf("control: %w", err)
		}
	}()

	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler())
		metricsSrv = &http.Server{Addr: cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("metrics: listening on %s/metrics", cfg.MetricsListen)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fatal <- fmt.Errorf("metrics: %w", err)
			}
		}()
	}

	go func() {
		if err := r.ListenAndServe(); err != nil {
			fatal <- fmt.Errorf("resolver: %w", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	exitCode := 0
	select {
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
	case err := <-fatal:
		log.Printf("%v; shutting down", err)
		exitCode = 1
	}

	// Stop taking new work, let in-flight queries and requests finish, then
	// flush the query log and close the database.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.Shutdown(ctx)
	_ = api.Shutdown(ctx)
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(ctx)
	}
	stopBG()
	wg.Wait()
	if err := db.Close(); err != nil {
		log.Printf("close database: %v", err)
	}
	log.Printf("stopped")
	os.Exit(exitCode)
}

// runHealthcheck asks the local API for /healthz. Container images have no
// curl, so the binary checks itself.
func runHealthcheck(cfgPath string) {
	cfg := loadConfig(cfgPath)
	addr := cfg.APIListen
	if host, port, err := net.SplitHostPort(addr); err == nil && (host == "" || host == "0.0.0.0" || host == "::") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: status", resp.Status)
		os.Exit(1)
	}
}

// runBackup writes a transactionally consistent copy of the live database.
// Safe while serve is running.
func runBackup(cfgPath, dest string) {
	cfg := loadConfig(cfgPath)
	db, err := store.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatalf("backup: %v", err)
	}
	defer db.Close()
	if err := store.Backup(db, dest); err != nil {
		log.Fatalf("backup: %v", err)
	}
	log.Printf("backup: wrote %s", dest)
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
	snap, err := store.LoadSnapshot(db, cfg.DataDir, policy.FetchAll)
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
	if _, err := store.AddRule(db, defaultOrg(db), profileID, kind, matcher, pattern, answer); err != nil {
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
	if _, err := store.AddBlocklistSource(db, defaultOrg(db), url, format, 0); err != nil {
		log.Fatalf("addlist: %v", err)
	}
	log.Printf("addlist: %s (%s) subscribed — run 'opencontrol sync' to fetch now", url, format)
}
