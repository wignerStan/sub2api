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
| `service/openai_ws_forwarder_ingress.go` | after `sessionLease` acquisition: emit sidecar account-switch virtual frame when the continuation chain is bound to another account | `service/openai_ws_sidecar_account_switch.go` |
| `handler/openai_gateway_handler.go` | HTTP responses failover loop: mark request context on scheduler account switch | `service/openai_ws_sidecar_account_switch.go` |
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

When the scheduler rebinds a session to a different account mid-WS-turn, the
gateway itself returns the downstream error: a Realtime-style `error` event
carrying code `previous_response_not_found` (Codex classifies it as retryable
→ discard the WS, reconnect, resend the full request context), followed by a
benign `NormalClosure` — the handler neither failovers again nor charges
account health. The same hook notifies the sidecar (virtual frame) and
purges the session's harvested `x-codex-turn-state` so the reconnect dial on
the new account starts clean.

- **WS**: virtual frame `{"x-s2s-vframe":"account-switch",
  "previous_account_id":N,"account_id":M}` inside the hop — consumed by the
  sidecar, never forwarded upstream. Emitted when a session's
  `previous_response_id` chain is bound to another account (response→account
  state store), after preflight-ping re-dials, and on post-reconnect
  recognition (session switch memory, 15m TTL).
- **Sidecar purge at first switch**: per-hop flag removes `x-codex-turn-state`
  (flat client_metadata, both envelopes) and the root `prompt_cache_key` from
  every subsequent frame; dial-time purge strips the harvested turn-state
  header for switched scopes (15m TTL).
- **HTTP**: `x-s2s-account-switched: <previous account id>` request header on
  sidecar forwards (stripped from upstream egress; informational).

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
Per-account mode comes from `accounts.extra.codex_fingerprint_mode`; the
deployment default is `SUB2API_PATCH_DEFAULT_CODEX_FINGERPRINT`
(`SUB2API_SIDECAR_DEFAULT_CODEX_FINGERPRINT` alias), unset = off. See the
sidecar repo README for the full ported contract and test matrix.

## Archive

`migrate/v0.2.0-clean-sidecar` is the historical integration branch
(includes the vendored `rustsidecar/` sources, now split into the standalone
`sub2api-sidecar` repository). It is kept as an archive and no longer the
patch baseline. See `docs/SIDECAR.md` for the Go↔sidecar contract.
