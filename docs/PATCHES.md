# Sub2API Go-side Patch Catalog (`patch/upstream-hooks`)

This branch carries the deployment patches for the wignerStan fork on top of
upstream `origin/main` (Wei-Shaw/sub2api). Design rules (enforced):

1. **Small patch points** — every edit inside an upstream file is a 1–3 line
   hook (a function call or a branch). No business logic in upstream files.
2. **Env-only toggles** — all patch behavior is triggered by environment
   variables (`SUB2API_PATCH`, `SUB2API_SIDECAR_*` / `GATEWAY_SIDECAR_*`).
   No new config-file fields; `config.example.yaml` stays upstream.
3. **Patch logic in patch files** — new logic lives in dedicated
   `*_patch.go` / `*sidecar*.go` / `*guardian*.go` files; upstream tables and
   structs stay untouched.

Motivation: heavy in-file patching makes upstream merges painful. With hooks,
a rebase onto a new upstream main only needs to re-verify the hook lines
listed below.

## Environment switches

| Variable | Effect |
|---|---|
| `SUB2API_PATCH=1/true/yes/on` | Master patch switch (per-account overrides below; OpenAI OAuth accounts only). |
| `SUB2API_SIDECAR_ENABLED` / `GATEWAY_SIDECAR_ENABLED` | Enable sidecar routing (fail-closed on explicit false/invalid). |
| `SUB2API_SIDECAR_BASE_URL` / `GATEWAY_SIDECAR_BASE_URL` | Sidecar loopback URL, e.g. `http://127.0.0.1:21333`. |
| `SUB2API_SIDECAR_TOKEN` / `GATEWAY_SIDECAR_TOKEN` | Shared loopback token (`x-s2s-token`). |
| `BACKUP_PROXY_URL` | Optional S3 backup egress proxy (upstream-compatible config field `backup.proxy_url`). |

Auto-enable legacy rule: if no explicit `*_SIDECAR_ENABLED` is set but
base_url + token are both present, the sidecar is enabled.

## Hook points (files upstream may touch on merge)

| Upstream file | Hook | Patch file with the logic |
|---|---|---|
| `service/account.go` | `IsOpenAIPassthroughEnabled`: +1 branch → force `false` | `account_patch.go` (`sub2apiPatchDisableOpenAIHTTPPassthrough`) |
| `service/account.go` | `IsOpenAIResponsesWebSocketV2Enabled`: +1 branch → force `true` | `account_patch.go` (`sub2apiPatchForceOpenAIWSV2`) |
| `service/account.go` | `ResolveOpenAIResponsesWebSocketV2Mode`: +1 branch → force `passthrough` | `account_patch.go` (`sub2apiPatchForceOpenAIWSModePassthrough`) |
| `service/openai_codex_fingerprint.go` | `GetCodexFingerprintMode`: +1 branch → `codexFingerprintOff` (Go-side mimic off; sidecar owns identity) | `account_patch.go` (`isSub2apiPatchEnabled`) |
| `repository/http_upstream.go` | `Do` / `DoWithTLS`: dispatch on `service.ShouldUseSidecarTLS(req)` → `doViaSidecar` | `service/openai_sidecar_tls.go` |
| `repository/req_client_pool.go` | `reqClientOptions.Sidecar*` + `SidecarAwareRoundTripper` wrap; `sidecarOptsFromConfig` | `service/openai_sidecar_tls.go` |
| `repository/openai_oauth_service.go` | constructor threads `*config.Config` for sidecar-aware OAuth exchange/refresh clients | `service/openai_sidecar_tls.go` |
| `service/openai_privacy_service.go` | broadened Cloudflare-challenge body markers (lowercase match, `challenge-platform`, `<html`) | inline (small robustness fix) |
| `service/openai_ws_client.go` | coder dialer strips sidecar control headers; conn read pump; `ensureReadPump` before publish | `service/openai_ws_client_sidecar.go` |
| `service/openai_account_runtime_block_fastpath.go` | `blockAccountSchedulingLocked`: remember block reason; `ClearAccountSchedulingBlock`: delete reason | `service/openai_guardian_route.go` |
| `service/openai_ws_pool.go` / `openai_ws_forwarder.go` | dialer construction → `openAIWSDefaultDialer()` (sidecar-aware when configured) | `service/openai_ws_pool_sidecar.go` |
| `service/openai_ws_forwarder_ingress.go` | after `sessionLease` acquisition: WS delta turn whose continuation chain (response→account binding) belongs to another account → return the retryable `previous_response_not_found` error + benign close | `service/openai_ws_sidecar_account_switch.go` |
| `handler/openai_gateway_handler.go` | WS + HTTP failover loops: stamp the scheduler switch onto the request ctx | `service/openai_ws_sidecar_account_switch.go` |
| `service/openai_ws_forwarder_v2.go` | WS dial seam: switch-stamped ctx → `x-s2s-account-switched` dial header (sidecar-gated) | `service/openai_ws_sidecar_account_switch.go` |
| `service/openai_sidecar_tls.go` | `ForwardHTTPViaSidecarForAccount`: switch-stamped ctx → `x-s2s-account-switched` header | same file (patch-owned) |
| `service/openai_ws_v2_passthrough_adapter.go` | `openAIWSClientFrameConn.WriteFrame`: +1 line downstream capacity-shed rewrite (`server_is_overloaded`/`slow_down` → `server_error` in the client copy only) | `service/openai_ws_v2_relay_patch.go` |
| `service/openai_ws_v2_passthrough_adapter.go` | response.create frame path: +3 lines `openAIWSRelayBeforeTurnPatch` before `BeforeRequest` (per-turn profit gate + pricingAt freeze in passthrough mode) | `service/openai_ws_v2_relay_patch.go` |
| `service/openai_gateway_upstream_errors.go` | `newOpenAIAccountFailoverErrorWithClassificationHeaders`: +1 line `applyOpenAIAccountCustomErrorMappingPatch` (account-level custom error-code mapping) | `service/openai_ws_v2_relay_patch.go` |
| `handler/openai_gateway_handler.go` | `closeOpenAIWSFailoverExhausted`: +2 lines → patched close (structured error event, rate-limit message alignment, passthrough rules, client overrides) | `handler/openai_ws_failover_close_patch.go` |
| `handler/openai_gateway_handler.go` | `ResponsesWebSocket`: +3 lines bind `errorPassthroughService` into gin ctx (HTTP paths already bind it) | `handler/openai_ws_failover_close_patch.go` |

Upstream files that stay **byte-identical** on this branch (all patch content
in sidecar/guardian files): `service/openai_gateway_service.go` (whitelist
additions injected via `init()` in `openai_guardian_route.go`), the scheduler
files, the WS forwarder/pool files.

## New patch files

| File | Content |
|---|---|
| `service/account_patch.go` | `SUB2API_PATCH` switch + per-account OAuth overrides |
| `service/openai_sidecar_tls.go` | env settings, TLS-route dispatch, loopback client, sidecar HTTP forwarding |
| `service/sidecar_e2ee.go` | AES-256-GCM record codec, HKDF keys, 64 MB cap (Go↔rust parity with sidecar `src/e2ee.rs`) |
| `service/openai_ws_client_sidecar.go` | WS dialer selector, sidecar `/v1/ws` dialer, E2EE conn wrapper |
| `service/openai_guardian_route.go` | Guardian route detection, dedicated URLs, schedulability gates, block-reason state |
| `service/openai_ws_v2_relay_patch.go` | sync-183 WS relay/failover parity: downstream capacity-shed rewrite, passthrough BeforeTurn gate, account custom-error-code mapping |
| `handler/openai_gateway_ws_failover_event.go` | Structured failover error event writer (Responses WS error contract before the close frame, retry-after fallback) |
| `handler/openai_ws_failover_close_patch.go` | sync-183 failover-exhausted close end-state (event + rule matching + client overrides), `SUB2API_PATCH`-gated |

## Intended next hook points (defined, not yet wired)

These are tested on the branch but intentionally not wired into request
paths yet (matching the reviewed migrate state):

- `service.WithOpenAICodexGuardianRoute(ctx, c, body, requestedModel, forceCodexCLI)`
  — call in the OpenAI gateway request path to detect Guardian traffic.
- `openAICodexBackendURLForContext(ctx)` — use where the Codex backend URL is
  selected to route Guardian review/classifier traffic to the unmetered
  endpoints.
- `isOpenAIAccountRequestRuntimeBlockedForContext` /
  `getOpenAIAccountForSchedulingContext` / `shouldClearOpenAIStickySessionForRequest`
  / `isOpenAIAccountSchedulableForRequest` — Guardian-aware scheduling checks.
- `service.newOpenAIWSClientDialer(cfg)` — replace
  `newDefaultOpenAIWSClientDialer()` at `openai_ws_forwarder.go` /
  `openai_ws_pool.go` to route Codex WS dials through the sidecar.

## Upstream-merge playbook

1. `git fetch origin && git rebase origin/main patch/upstream-hooks`.
2. Conflicts should only occur inside the hook lines of the table above —
   re-apply the 1–3 line hook; the logic files merge cleanly (they are
   append-only).
3. Run: `go build ./...` and
   `go test ./internal/service/ ./internal/repository/ -run 'Sidecar|E2EE|Patch|Passthrough|Guardian|WS' -count=1`.
4. If upstream codex wire format changed, update the sidecar first (see the
   sidecar repo README; `codex_wire_audit.py` composes the fingerprint set
   from one immutable `openai/codex` SHA — no capture snapshots), then
   re-verify.

## Upstream WS connection pool (sidecar-owned transport)

The ctx_pool transport engine is owned by the sidecar (`src/ws_pool.rs` in the
sidecar repo): thread-scoped socket reuse, exclusive leases, 55m/60m rotation,
acquire-time and background health pings, idle trimming. The gateway's
ownership is business-only: scheduling, quota, failover, replay payload
construction, preemption/state stores. The wiring is the
`openAIWSDefaultDialer()` hook above — with `SUB2API_SIDECAR_*` configured,
pool and passthrough WS dials relay through the sidecar, whose pool reuses
sockets per thread scope (root/subagent stay independent); without it the
native path is untouched. Live counters: `GET /v1/pool-stats` on the sidecar.

## Account-switch signaling

Two channels; the gateway stays nearly passthrough and owns no identity
correlation logic:

1. **Header channel** — the gateway hooks scheduler failover events directly
   (in-process fact: zero delay, works when redis is down). The failover
   loops stamp the switch onto the request ctx (1 line each); the sidecar
   forward/dial seams turn it into `x-s2s-account-switched: <previous account
   id>` (control header, stripped from upstream egress). A switch always
   re-establishes the WS: delta turns (continuation chain bound to another
   account, via the response→account state store) get the retryable
   `previous_response_not_found` error event + benign `NormalClosure` from
   the gateway itself (Codex discards the WS, reconnects, full-replays), so
   headers always ride a fresh dial.
2. **Redis notify channel** — the gateway's existing sticky-binding writes
   (`sticky_session:{group}:{hash}`) publish redis keyevents; the sidecar
   subscribes and warms its hot caches (db profile → hot cache) for the
   switched-to account ahead of its traffic. Requires redis
   `notify-keyspace-events` to include string + generic events (e.g.
   `KEg$`, or `KEA`). Zero gateway patches.

The sidecar double-validates incoming traffic: header consistency (previous
account != current account, hot path); a dial that beats the redis event
waits (bounded) for the ledger entry, on timeout the header stays
authoritative. The correlation split then runs sidecar-side: old account's
identity entries invalidated (moka L1 + redis L2), pooled sockets evicted
for the thread scope, hop-level `x-codex-turn-state` stripping seeded, and
the codex-shaped `prompt_cache_key` regenerated under the new account's
identity. The gateway never touches `x-codex-turn-state` bindings for
switching.

The original sub2api ctx-pool transport mode is retired: the switch hooks
live in the WS v2 ingress general path, never in pool-mode forwarder paths.

## Identity convergence ownership

Under `SUB2API_PATCH` the Go-side mimic is fully disabled
(`GetCodexFingerprintMode() = off`) and the **Rust sidecar is the sole
identity engine**. The complete Go convergence semantics (mode machine,
thread-keyed derivation, parent/fork topology, body enrichment, header/body
injection, prompt_cache_key rewrite — the sync-183 fix lineage) were ported to
`sub2api-sidecar/src/mimic/converge.rs` on branch `feat/converge-mimic-port`.
The sidecar's mode machine has a single converged level: `Device`
(installation + full session-family regeneration; the legacy session/full
levels are gone). Per-account mode comes from
`accounts.extra.codex_fingerprint_mode` (`session`/`full` coerce to
`device`); the deployment default is
`SUB2API_PATCH_DEFAULT_CODEX_FINGERPRINT`
(`SUB2API_SIDECAR_DEFAULT_CODEX_FINGERPRINT` alias), unset = device. See the
sidecar repo README for the full ported contract and test matrix.

## Archive

`migrate/v0.2.0-clean-sidecar` is the historical integration branch
(includes the vendored `rustsidecar/` sources, now split into the standalone
`sub2api-sidecar` repository). It is kept as an archive and no longer the
patch baseline. See `docs/SIDECAR.md` for the Go↔sidecar contract.
