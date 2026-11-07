# Open Control — Project Plan

**Open Control** is an open-source, self-hosted alternative to Control D: a DNS filtering,
routing, and analytics platform you run on your own infrastructure. Control D's model
(Profiles → Endpoints → Analytics) with NextDNS's polish, but self-hosted and multi-tenant
enough for orgs and MSPs.

## 1. Core model

The product is built entirely around these concepts (borrowed from Control D):

| Concept    | Meaning                                                                 |
|------------|-------------------------------------------------------------------------|
| **Org**    | A tenant. Has users, profiles, endpoints. MSPs create many orgs.         |
| **User**   | Human with RBAC role (admin / operator / viewer), OIDC or local login.   |
| **Profile**| A policy bundle: filters, blocklists, allow/block rules, rewrites, redirect rules, upstream selection, options. |
| **Endpoint**| A named DNS resolver identity bound to a profile. MVP identification: query source IP / subnet (+ optional dedicated listen port per endpoint). DoT SNI and DoH path tokens join when encrypted transports land. |
| **Log**    | Per-query decision record (allowed/blocked/redirected/rewritten + reason). |
| **Exits**  | Registered egress nodes (WireGuard peer or SOCKS5 proxy) reachable from the server, used for traffic redirection. |
| **Upstream** | Where queries that pass filtering go: public plain-DNS resolvers for the MVP, **the operator's own unbound resolver network later** — same config entity either way. |

Rule evaluation order per query:
1. Local rewrites / split-DNS entries
2. Custom allow rules (BYPASS)
3. Custom block rules (BLOCK), incl. wildcard + TLD
4. Service filters (curated per-app domain sets)
5. Blocklist filters (subscribed third-party + native lists)
6. Redirect rules (scoped by domain/client) → else forwarded upstream

## 2. Architecture (MVP)

Single **Go binary**, ~3 layers:

- **Resolver core: `miekg/dns` (BSD), used directly.** MVP transports: UDP53 + TCP53
  listeners, upstream exchange (plain DNS, UDP with TCP fallback). Own small, strictly
  scoped cache: size-capped LRU, TTL clamped to [min, max] policy, concurrent identical
  queries deduplicated (singleflight), no exotic features.
- **Policy engine (ours).** Blocklist matcher (memory trie / hash set, compiled on
  blocklist update, atomically swapped — reload never drops queries), custom rules,
  rewrites, endpoint→profile binding by source identity. The engine returns an abstract
  `Action` (ALLOW / BLOCK / REWRITE / FORWARD / REDIRECT) — REDIRECT is a stub until the
  egress phase, but the evaluation链 and data model are final from day one.
- **Control plane (ours).** REST `/api/v1/*` (OpenAPI spec), orgs/users/RBAC, audit
  log, token enrollment for endpoints. React SPA built at compile time, embedded via
  `go:embed`.

**Encrypted DNS (DoH/DoT) is a follow-on milestone, not MVP.** Server-side DoH over
miekg/dns is a thin HTTP handler (RFC 8484 message encode/decode); DoT is a `tls.NewListener`
around the existing TCP server. DoQ is deliberately out of scope until needed.

**Storage: SQLite via `modernc.org/sqlite`** — pure Go, no CGO, supports static
binary. A second container (Postgres) is not worth its RAM for the MVP; the store layer
stays thin so a Postgres variant can come later.

**Upstreams:** config entity per profile/org. MVP: public resolvers over plain DNS.
Next phase: **self-hosted unbound resolver network** — Open Control sits in front as the
policy/filtering edge and forwards to unbound over port 53 / DoT. Building the resolver
network stays out of scope for this codebase.

Resource envelope target: **< 40 MB RSS** steady state; docker image **< 25 MB**
(scratch/distroless static build, no CGO). SQLite WAL mode; query log retention is
configurable (N days) — the only grow-forever data.

### Deployment

- **Production: Docker Compose on Coolify.** Single app container + a volume.
  Ports 53 (UDP+TCP) and any DoH port exposed as explicit compose port maps; no
  privileged mode, no host networking. TLS termination is ours (certificate files
  mounted), not Coolify proxy — DNS ports can't go through HTTP proxies.
- **Local development: no Docker.** `go run ./cmd/opencontrol` against the SQLite file,
  listener on unprivileged ports (e.g. 1053/UDP+TCP); test with `dig @localhost -p 1053`.

## 3. Repo layout (suggested)

```
opencontrol/
  cmd/opencontrol/       # main binary + subcommands (serve, migrate, admin)
  internal/
    resolver/            # miekg/dns wiring: listeners, cache, upstream pool
    policy/              # rule engine → Action, matchers, blocklist compiler
    control/             # REST API, auth, RBAC, audit
    store/               # SQLite (modernc) models + migrations
    analytics/           # query log ingest + aggregation
    web/                 # embedded React app (assets + build glue)
  api/openapi.yaml       # public API contract (generated)
  deploy/                # docker-compose.yml for Coolify, Dockerfile, example configs
  docs/
```

`resolver` exposes one narrow interface to the policy engine so the transport layer can
be swapped later without touching product code.

## 4. Data model (initial — SQLite)

```
orgs(id, name, created_at)
users(id, org_id, email, role, auth_source)
profiles(id, org_id, name, options TEXT)          -- JSON TEXT: upstreams, cache policy, log level
blocklist_sources(id, org_id, url, format, etag, last_synced)
profile_rules(profile_id, kind, matcher, target, note)   -- kind: block|allow|redirect|rewrite
profile_filters(profile_id, service_or_filter_id, state)
endpoints(id, org_id, profile_id, token, name, allowed_source_ips, schedule TEXT, created_at)
exit_nodes(id, org_id, kind, config TEXT, health)           -- later phase
query_logs(id, org_id, endpoint_id, ts, client_ip, qname, qtype, action, reason)  -- index on (org_id, ts)
audit_logs(id, org_id, user_id, ts, action, target, diff TEXT)
```

## 5. Traffic redirection — later phase, behind the Action interface

Control D's moat needs exit infrastructure. Realistic take:

- **Egress nodes** the operator registers (their own VPS): WireGuard endpoint or SOCKS5/HTTP proxy
- Redirect flow: policy decides domain D → exit E for client C
  - Resolver-only mode: domain resolves to the egress gateway (Linux server with nftables/WG)
  - Companion client daemon (like Control D's `ctrld`): local resolver + per-domain routing via Linux policy routing/WG
- Because the policy engine already returns `Action` values, REDIRECT slots in without
  touching the evaluation order, DB schema, or resolver plumbing that landed in M0–M1.

## 6. Milestones

**M0 — Walking skeleton (week 1):** repo, go mod, cmd + config, SQLite migrations,
miekg/dns UDP+TCP listener → forward to one public resolver, minimal cache (LRU, TTL
clamp, singleflight dedupe), Dockerfile + compose for Coolify.
Success = `dig @localhost -p 1053` resolves; image < 25 MB, steady RSS < 40 MB.

**M1 — Policy core (weeks 2–4):** profiles + endpoints in SQLite; blocklist subscriptions
(URL, ETag cache, trie compiler, atomic reload); allow/block/wildcard rules; rewrites;
endpoint→profile binding via source IP / subnet / dedicated port.
Success = two endpoints, same binary, different filtering behavior.

**M2 — Control plane (weeks 5–8):** REST API + OpenAPI, orgs/users/RBAC, local auth +
OIDC, API tokens, audit log. Embedded React UI: endpoints, profiles, rule editor,
blocklist manager.
Success = everything manageable from a browser, as two users in separate orgs.

**M3 — Encrypted DNS (weeks 9–10):** DoH (HTTP handler per RFC 8484, HTTP/2; HTTP/3 later)
and DoT (TLS-wrapped TCP listener, RFC 7766 TCP pipelining in-order), certificate
handling, endpoint identity from DoH path token / DoT SNI.
Success = Android Private DNS-style client works against DoT endpoint; same UI, no new
filtering logic (policy engine untouched).

**M4 — Observability (weeks 11–13):** query log ingest, dashboards (live tail, top-N,
blocked %, per-client), syslog + webhook streaming, retention job.
Success = real-time debugging of a live network.

**M5 — Egress (weeks 14–17):** exit node registration + health, SOCKS5 & WireGuard,
resolver-only mode, companion client skeleton.
Success = one domain redirected via your own exit node, verified in logs.

**M6 — Resolver network + hardening (weeks 18+):** unbound deployment recipe
(Open Control in front, unbound behind on an internal network, DoT between them);
metrics (Prometheus); config-as-code for profiles; backup/restore; DoQ only if a real
client demand appears; first tagged 0.1.0.

## 7. Risks / honest trade-offs

- **Cache correctness is now ours** — cache poisoning is the classic DNS bug class, and we
  write the cache. Mitigation: smallest correct feature set (no negative caching, no
  prefetch until proven), fuzz the cache against upstream behavior, write order-of-key
  protocol tests early in M0.
- **RFC 7766 TCP pipelining** — TCP queries may be pipelined and responses must return in
  query order; miekg/dns leaves server write-ordering to us per connection. Handle with a
  per-connection ordered queue from day one, or clients hang (some resolvers/middleware
  genuinely rely on this).
- **Encrypted DNS delayed** — Android Private DNS / iOS encrypted resolver setups need
  DoH/DoT; until M3, phone users must point at plain DNS by IP. Accepted: M3 is short
  because policy logic is untouched.
- **SQLite at MSP scale** — fine to dozens of orgs at home-lab query rates; store
  interface built for a Postgres variant as the known escape hatch.
- **Blocklist RAM** — million-domain lists with a pure-Go trie need early benchmarks;
  cap subscription size per org in config as a safety valve.
- **Ports on shared hosts** — 53/853 binding in containers needs explicit port maps, not
  host networking; document for Coolify specifically.

## 8. Immediate next steps

1. `go mod init`, repo skeleton per §3, small config (env + YAML)
2. M0 spike: miekg/dns UDP listener (:1053) → forward to a public resolver, cache on;
   measure RSS + latency; add TCP listener with in-order pipelining queue
3. SQLite migration v1 (schema §4) + `modernc.org/sqlite` WAL config
4. Dockerfile (multi-stage → scratch, static, ~15–20 MB image) + compose for Coolify

