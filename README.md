# Open Control

Open-source, self-hosted alternative to Control D: DNS filtering, routing and
analytics you run on your own infrastructure. See [PLAN.md](PLAN.md) for the
architecture and roadmap. Current state: **M0 (walking skeleton)**.

## What works today

- UDP53 + TCP53 listeners (miekg/dns), forwarding to public upstreams
- Size-capped LRU cache with TTL floor/ceiling and concurrent-dedupe
- SQLite storage (modernc, pure Go) with embedded migrations
- Single static binary; measured steady-state RSS ~16 MB on Windows dev box

## Local development (no Docker)

```sh
air                                    # hot-reload dev server (127.0.0.1:1053), config in .air.toml
go run ./cmd/opencontrol serve         # plain run, no hot reload
dig @127.0.0.1 -p 1053 example.com      # test query
dig @127.0.0.1 -p 1053 example.com +tcp # TCP path
go run ./cmd/opencontrol migrate        # apply schema migrations only
```

Config: `config.yaml` (see keys in `internal/config/config.go`) or env
`OC_LISTEN`, `OC_SQLITE_PATH`, `OC_DATA_DIR`.

## Deploy (Coolify / docker compose)

```
docker compose up -d --build
dig @<server-ip> example.com
```

Ports 53 UDP+TCP are mapped natively — Coolify's HTTP proxy/TLS termination
does not apply to DNS. Make sure no other service holds port 53 on the host.

## Repo layout

```
cmd/opencontrol/   main binary (serve, migrate)
internal/config/   YAML + env config
internal/resolver/ listeners, cache wiring, upstream pool, policy hook
internal/policy/   rule engine (Action: FORWARD/BLOCK/REWRITE/redirect stub)
internal/cache/    LRU + TTL clamp response cache
internal/store/    SQLite + migrations
Dockerfile         multi-stage → scratch (~15 MB image)
docker-compose.yml Coolify-ready single service
```
