# Open Control

Open-source, self-hosted alternative to Control D: DNS filtering, routing and
analytics you run on your own infrastructure. See [PLAN.md](PLAN.md) for the
architecture and roadmap. Current state: **M2 (control plane: API, web UI, orgs)**
— user accounts and OIDC are still to come.

## What works today

- UDP53 + TCP53 listeners (miekg/dns), forwarding to public upstreams
- Size-capped LRU cache with TTL floor/ceiling and concurrent-dedupe
- Profiles and endpoints: an endpoint is selected by client source CIDR; the
  most specific (longest-prefix) match wins; empty allowlists match nothing
- Rules per profile: `block` / `allow` with `domain` (exact), `wildcard`
  (domain + all subdomains) or `tld`; `rewrite` for exact domains
- Blocklist subscriptions (hosts / adguard-style lines), cached on disk with ETag
- Evaluation order: rewrite → allow → blocklists + custom block → forward
- SQLite storage (modernc, pure Go) with embedded migrations
- Boots from cached blocklists (never waits on the network); fresh lists are
  fetched in the background; SIGHUP reloads rules without restart

## Admin CLI

```sh
opencontrol migrate
opencontrol addprofile kids                       # prints profile id
opencontrol addrule 1 block domain ads.example
opencontrol addrule 1 block wildcard tracker.example
opencontrol addrule 1 allow wildcard ok.tracker.example
opencontrol addrule 1 block tld xyz
opencontrol addrule 1 rewrite domain router.lan 10.0.0.1
opencontrol addendpoint kids 2 10.9.0.0/16      # prints endpoint token
opencontrol addlist https://example.org/hosts hosts
opencontrol sync                                  # fetch blocklists now
```

## Web UI

The control plane serves a React SPA from the same port as the API
(`http://127.0.0.1:8080/` by default). Sign in with an API token. The UI is
compiled into the binary (`internal/web/dist`, committed), so `go build` needs no
Node. To change the UI: `cd web && npm install && npm run build`.

Pages: profiles and rules, endpoints (shows the token once), blocklists, tokens
(admin: mint and revoke), audit log (admin).

## Organizations (tenants)

Every token belongs to one org and sees only that org's data. A cross-org
reference (binding an endpoint to another org's profile, or deleting another
org's rule) is answered `404`, the same as a missing row.

```sh
opencontrol addorg acme                          # prints the org id
opencontrol addtoken acme-admin admin acme       # token for that org, shown once
```

The CLI commands (`addprofile`, `addrule`, `addendpoint`, `addlist`) operate on
the default org. Other orgs are managed through the API with their own token.

## Control API (M2, partial)

Listens on `OC_API_LISTEN` (default `127.0.0.1:8080`). Authenticate with a
bearer token minted by `opencontrol addtoken NAME admin|operator|viewer [ORG]`.

| Role     | Can                                                        |
|----------|------------------------------------------------------------|
| viewer   | read profiles, rules, endpoints, blocklists                |
| operator | viewer + create/delete rules, endpoints, blocklists, profiles |
| admin    | operator + mint tokens, read the audit log                 |

```sh
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/profiles
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"kind":"block","matcher":"wildcard","pattern":"evil.example"}' \
     http://127.0.0.1:8080/api/v1/profiles/1/rules
```

Every write runs in one transaction with its audit row (`GET /api/v1/audit`,
admin), then reloads the resolver. Tokens are stored as SHA-256 hashes and shown
once at creation. Admins can list and revoke their org's tokens
(`GET`/`DELETE /api/v1/tokens`); an admin cannot revoke the token they are using.

Not yet: user accounts and OIDC (only API tokens exist), and an OpenAPI spec.

## Local development (no Docker)

```sh
air                                             # hot-reload dev server, 127.0.0.1:1053 (.air.toml)
go run ./cmd/opencontrol serve                  # plain run, no hot reload
dig @127.0.0.1 -p 1053 example.com
dig @127.0.0.1 -p 1053 example.com +tcp
go test ./...
```

Config: `config.yaml` (see `internal/config/config.go`) or env
`OC_LISTEN`, `OC_SQLITE_PATH`, `OC_DATA_DIR`.

## Deploy (Coolify / docker compose)

```
docker compose up -d --build
dig @<server-ip> example.com
```

Ports 53 UDP+TCP are mapped natively — Coolify's HTTP proxy/TLS termination
does not apply to DNS. Make sure no other service holds port 53 on the host.

## Known gaps (M1)

- Per-endpoint dedicated listen ports are not implemented (source-CIDR only)
- Cache is shared across profiles; policy runs before the cache, so blocks are
  per-profile, but upstream answers are not
- SIGHUP reload is untested on Windows (Linux/Docker only)

## Repo layout

```
cmd/opencontrol/   main binary (serve, migrate, admin commands)
internal/config/   YAML + env config
internal/resolver/ listeners, cache wiring, upstream pool, policy hook
internal/policy/   matcher, evaluation order, endpoint selection, blocklist parser
internal/cache/    LRU + TTL clamp response cache
internal/store/    SQLite + migrations, snapshot loader, admin queries
Dockerfile         multi-stage → scratch
docker-compose.yml Coolify-ready single service
```
