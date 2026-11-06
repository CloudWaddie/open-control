// Open Control — self-hosted DNS filtering platform (M0).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cloudwaddie/opencontrol/internal/config"
	"github.com/cloudwaddie/opencontrol/internal/resolver"
	"github.com/cloudwaddie/opencontrol/internal/store"
)

const usage = `opencontrol — self-hosted DNS filtering platform

Usage:
  opencontrol serve   [-config path.yaml]
  opencontrol migrate [-config path.yaml]

  M0 stores config in YAML, with OC_LISTEN / OC_SQLITE_PATH / OC_DATA_DIR env overrides.
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("opencontrol: ")
	cfgPath := flag.String("config", "", "YAML config file path")
	flag.Parse()

	cmd := "serve"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}

	switch cmd {
	case "serve":
		runServe(*cfgPath)
	case "migrate":
		runMigrate(*cfgPath)
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

func runServe(cfgPath string) {
	cfg := loadConfig(cfgPath)

	db, err := store.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatalf("store open: %v", err)
	}
	defer db.Close()

	if err := store.Migrate(db); err != nil {
		log.Fatalf("store migrate: %v", err)
	}
	log.Printf("store: %s ready", cfg.SQLitePath)

	r := resolver.New(cfg)
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
