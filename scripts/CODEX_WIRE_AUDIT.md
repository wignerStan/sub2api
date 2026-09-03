# Codex wire metadata source audit

`codex_wire_audit.py` reads the current `openai/codex` GitHub source and composes the request identity/metadata surfaces that matter to a Codex-compatible gateway.

It resolves the requested ref to one immutable commit SHA first, then fetches every source file at that SHA. This avoids mixing files from different revisions while `main` is moving.

## Usage

```bash
python3 scripts/codex_wire_audit.py
```

JSON output:

```bash
python3 scripts/codex_wire_audit.py --json
```

Pin a branch, tag, or commit explicitly:

```bash
python3 scripts/codex_wire_audit.py --ref main
python3 scripts/codex_wire_audit.py --ref <commit-sha>
```

Use a token to avoid the low unauthenticated GitHub API rate limit:

```bash
GITHUB_TOKEN=... python3 scripts/codex_wire_audit.py --json --output /tmp/codex-wire.json
```

Prefer `GITHUB_TOKEN` / `GH_TOKEN` over `--token` so a credential is not placed directly in shell history or process arguments.

Use strict mode when an automation should fail if a previously known conditional source field or endpoint disappears:

```bash
python3 scripts/codex_wire_audit.py --strict --json
```

Without `--strict`, required/base transport fields still fail loudly, while disappearance of known conditional fields is reported under `scope.warnings` instead of aborting the audit.

The script uses only the Python standard library.

## Report layout

The output is deliberately separated into:

1. **Account / status check** — `accounts/check` request endpoints and HTTP headers. `client_metadata` and turn metadata do not apply here.
2. **Responses / HTTP** — actual HTTP request headers, optional tracking headers, flat `client_metadata`, and canonical `x-codex-turn-metadata` transport.
3. **Responses / WebSocket** — HTTP upgrade headers and `response.create.client_metadata`, including WebSocket per-message projections such as W3C trace context, Responses Lite, stream-start time, and turn-state.
4. **Full turn metadata schema** — fields parsed directly from `CodexTurnMetadataPayload`, plus nested workspace/tool/compaction structures.

## Header vs client_metadata classification

Header discovery intentionally does **not** treat arbitrary Rust `.insert(...)` calls as HTTP header writes. That old behavior could classify `HashMap<String, String>` metadata keys such as `turn_id`, `parent_turn_id`, `root_turn_id`, and `ws_request_header_*` as HTTP-header candidates.

The audit now recognizes header-specific constants/APIs separately from `client_metadata` builders. Any header-shaped source item that is discovered but not classified into the composed surfaces is exposed in `scope.unclassified_header_candidates` for review.

A particularly important transport distinction is Responses Lite:

- HTTP: `x-openai-internal-codex-responses-lite: true` is an actual request header.
- WebSocket: the corresponding per-request value is `response.create.client_metadata["ws_request_header_x_openai_internal_codex_responses_lite"]`; it is **not** a mutable WebSocket handshake header.

Likewise, `x-codex-turn-state` is a normal HTTP request header on replay but is transported in `response.create.client_metadata` for WebSocket turns.

Rollout tracing can also add `x-codex-inference-call-id` to HTTP inference attempts. It is reported separately under `responses_http.tracking_headers` because it is optional tracking state rather than stable protocol identity.

## Optional / serde information

Each composed header and flat `client_metadata` entry now includes an `optional` flag and a source-derived condition.

Turn-metadata schema fields additionally expose source-derived serialization information:

- `wire_name`
- `optional` (derived from `Option<T>`)
- `serde_default`
- `skip_serializing_if`
- `skipped`
- `serialized`
- `flattened`

This makes the snapshot useful for allow/strip policy generation without incorrectly assuming that every Rust struct field appears on every request.

## What “full HTTP headers” means

The audit enumerates headers that are explicitly constructed by Codex source or injected by its auth/provider/request-preparation layers. It does **not** invent values that the HTTP/WebSocket stack creates at runtime, such as:

- `Host`
- `Content-Length` / `Transfer-Encoding`
- `Accept-Encoding`
- `Connection` / `Upgrade`
- `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, negotiated extensions
- proxy-added headers
- actual Cloudflare cookie names/values

Those are reported as runtime transport headers instead of being presented as stable Codex protocol fields.

## Why this is source-driven

The script extracts the current `CodexTurnMetadataPayload` and related nested structs directly from Rust source. It also verifies the small set of truly required base `client_metadata` fields while treating other known fields as conditional by default. If a required source anchor disappears, the audit still fails loudly; optional upstream evolution is surfaced as warnings unless `--strict` is requested.
