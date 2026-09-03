# Sub2API ↔ sub2api-sidecar Contract

The Rust sidecar lives in its own repository (`sub2api-sidecar`, split from
this repo's archived `rustsidecar/` tree). This document is the interface
contract the Go gateway depends on.

## Layering

| Layer | Owns |
|---|---|
| Go gateway | business logic: accounts, groups, quota, scheduling, billing, REST web API |
| Rust sidecar | egress boundary: rustls TLS disguise, **full identity mimic (convergence engine)**, loopback E2EE, Responses WS pump, DB-direct account resolution |

Under `SUB2API_PATCH` the sidecar is the sole identity engine (Go mimic off):
single converged level `Device` — installation convergence plus full
session-family regeneration (`session_id`/`thread_id`/window chain/turn ids
thread-keyed so root/fork sharing a session-id stay distinct, codex-shaped
`prompt_cache_key` regeneration, body topology enrichment on the first WS
frame), a write-back sticky identity map per (account, client thread) over
infra cache tiers (moka L1 + redis L2), and converged injection into headers,
`client_metadata` and embedded turn metadata. Legacy `session`/`full` mode
values coerce to `device`; the default comes from
`SUB2API_PATCH_DEFAULT_CODEX_FINGERPRINT` (unset = device). See the sidecar
repo README (`Identity convergence`, `Sticky identity map`) for the ported
contract.

## Routing boundaries

Through the sidecar (OAuth-origin hosts only — `chatgpt.com`,
`auth.openai.com`; `api.openai.com` API-key traffic stays native Go):

- `/backend-api/codex/*`
- `/backend-api/conversation`, `/backend-api/conversation/*`
- `/backend-api/wham/*`
- `/backend-api/files`
- `auth.openai.com` `/api/accounts/*`

Never through the sidecar (sidecar blocks them; Go keeps Chrome TLS
impersonation to satisfy Cloudflare):

- `/backend-api/settings/*`, `/backend-api/accounts/*`,
  `/backend-api/subscriptions/*` (ChatGPT web management surface)

## Loopback control headers (Go → sidecar)

| Header | Meaning |
|---|---|
| `x-s2s-token` | shared secret (`SUB2API_SIDECAR_TOKEN`) |
| `x-s2s-enc: 1` | request loopback E2EE negotiation / response echo on 101 |
| `x-upstream-url` | real upstream URL the sidecar must dial |
| `x-upstream-proxy` | base64-encoded per-account upstream proxy (`socks5`→`socks5h` normalized) |
| `x-upstream-account-id` | scheduler-owned account ID (overrides any client-supplied value) |

`stripSidecarControlHeaders` removes all of these from client input before
rebuilding them from trusted scheduler arguments (anti-smuggling). Dot-segment
and userinfo URLs are rejected.

## E2EE framing

Record: `[0xE2][version=1][len u32 BE][nonce 12B][ciphertext+16B tag]`,
AES-256-GCM, HKDF-SHA256 with info `"loopback-channel"` (WS) /
`"forward-channel"` (HTTP), max payload 64 MB (DoS bound). Truncated or
trailing-byte streams fail closed (`errSidecarE2EETrunc` /
`errSidecarE2EETrailing`). Go: `service/sidecar_e2ee.go`; Rust:
`src/e2ee.rs` (byte-for-byte parity — change both together).

## WS pump semantics

- The sidecar dials the upstream **before** answering the local upgrade; an
  upstream 429/401 relays the original status, `Retry-After`,
  `X-RateLimit-*` headers and JSON body to the client (Codex CLI retry
  semantics must survive — never invent a bare 429).
- Responses WS has a 60-minute absolute upstream lifetime; ping only guards
  idle. Root/fork (main/subagent) sessions are isolated by
  `thread_id`/`conversation_id`, never by shared `session_id`.
- WS and HTTP auto-passthrough are mutually exclusive for OAuth accounts;
  under `SUB2API_PATCH` the gateway forces WS v2 + `passthrough` mode.
- **Upstream connection pool (ctx pool transport)**: when pooled, the sidecar
  reuses upstream sockets keyed by `(account, target, proxy, thread scope)` —
  never the shared `session_id`. Leases are exclusive; 55m proactive rotation
  and 60m hard lifetime; acquire-time + background health pings; a reused hop
  surfaces the cached handshake response headers on the local 101. The
  gateway owns business logic (scheduling, quota, failover, replay payloads);
  the sidecar owns connection lifetime. Counters: `/v1/pool-stats`.
- **Account-switch signaling (two channels)**: the gateway stamps scheduler
  failover events onto the request ctx (in-process, zero delay) and the
  WS dial / HTTP forward seams emit `x-s2s-account-switched: <previous
  account id>`; WS delta turns whose continuation chain is bound elsewhere
  get the retryable `previous_response_not_found` error from the gateway
  itself, so a switch always re-establishes the WS. The sidecar also
  subscribes to redis keyevents on the sticky-binding keys
  (`sticky_session:*`; needs `notify-keyspace-events` incl. `$g`) and warms
  its hot caches for the switched-to account. Incoming dials double-validate
  (hot cache; header-before-notify waits bounded); on signal the pool evicts
  every other account's socket for the thread scope, strips the
  server-issued `x-codex-turn-state`, and regenerates the codex-shaped
  `prompt_cache_key` under the new account's converged identity. Nothing
  reaches upstream.

## Deployment

`systemd` pair on the host: `sub2api.service` (Go) + `sub2api-sidecar.service`
(Rust, `SUB2API_SIDECAR_ADDR=127.0.0.1:21333`, `SUB2API_SIDECAR_TOKEN=…`,
`DATABASE_URL=postgres://…`). Gateway drop-in sets
`SUB2API_SIDECAR_ENABLED=true`, `SUB2API_SIDECAR_BASE_URL=http://127.0.0.1:21333`,
same token. The gateway fail-closes to the native transport if the sidecar is
not configured; a configured-but-unreachable sidecar surfaces upstream errors
honestly. Start sidecar first, then gateway.

Capture utilities for wire debugging (`scripts/` in the sidecar repo):
`dummy_codex_server.py` (zero-filter dump server) and `codex_dump_proxy.py`
(dump-and-forward proxy in front of a running gateway).
