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
| `service/openai_ws_forwarder_ingress.go` | after `sessionLease` acquisition: turn-shape account-switch dispatch (delta → retryable error; full → vframe + turn-state purge) | `service/openai_ws_sidecar_account_switch.go` |
| `service/openai_ws_forwarder_v2.go` | dial-time: sticky-route mismatch/miss → `x-s2s-account-switched` dial header (sidecar-gated) | `service/openai_ws_sidecar_account_switch.go` |
| `handler/openai_gateway_handler.go` | HTTP responses selection point: sticky-route mismatch/miss → switch-marked request ctx | `service/openai_ws_sidecar_account_switch.go` |
| `service/openai_sidecar_tls.go` | `ForwardHTTPViaSidecarForAccount` sets `x-s2s-account-switched` from the ctx marker | same file (patch-owned) |

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
   sidecar repo README; `codex_wire_audit.py` snapshots), then re-verify.

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

Signaling is keyed on the turn shape (Codex responses semantics):

- **WS delta turn** (`previous_response_id` present): the chain binding
  (response→account state store) belongs to the account that issued it. When
  the scheduler has moved the session to another account, the gateway itself
  returns the downstream error: a Realtime-style `error` event with code
  `previous_response_not_found` (Codex classifies it as retryable → discard
  the WS, reconnect, resend the full request context), followed by a benign
  `NormalClosure` (no failover loop, no account-health charge). No virtual
  frame: the reconnect abandons the old hop on its own.
- **WS full turn** (no `previous_response_id`): the request is self-contained,
  so it proceeds — but when the sticky route (redis session→account) hit a
  different account (previous unschedulable, abandoned by the scheduler) or
  missed entirely (fresh correlation), the hook first sends the sidecar
  virtual frame (previous account id `0` when unknown) and deletes the
  session's harvested `x-codex-turn-state` binding
  (`DeleteSessionTurnState` — `BindSessionTurnState` treats empty as no-op).
- **New WS connections**: the dial carries `x-s2s-account-switched: <previous
  account id>` (0 when unknown) whenever the sticky route mismatches or
  misses, so the sidecar strips the old account's turn-state at handshake
  time (sidecar-gated; the header is a control header, never forwarded).
- **HTTPS** is always full: one selection-point hook compares the selected
  account against the sticky route and marks the outbound ctx;
  `ForwardHTTPViaSidecarForAccount` turns the marker into the
  `x-s2s-account-switched` header (stripped from upstream egress).
- **Sidecar reaction** (see the sidecar README): strip server-issued
  `x-codex-turn-state`, invalidate the previous account's sticky identity-map
  entry, and regenerate the codex-shaped `prompt_cache_key` under the new
  account's converged identity (never delete the carrier).

Recognition is structural — turn shape + sticky route — not remembered
state: there is no session-switch memory to expire.

The WS/HTTP mutual exclusion stays intact in both modes: under
`SUB2API_PATCH` OAuth accounts are forced WS-only (HTTP auto-passthrough
disabled); with the patch off, account config rules. OAuth HTTPS egress
routes through the sidecar regardless of WS mode (host-based dispatch, no WS
dependency).

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
