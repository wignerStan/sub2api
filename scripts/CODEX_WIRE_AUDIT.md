# Codex wire metadata source audit

`codex_wire_audit.py` reads the current `openai/codex` GitHub source and prints the request identity/metadata surfaces that matter to a Codex-compatible gateway.

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

The script uses only the Python standard library.

## Report layout

The output is deliberately separated into:

1. **Account / status check** — `accounts/check` request endpoints and HTTP headers. `client_metadata` and turn metadata do not apply here.
2. **Responses / HTTP** — HTTP request headers, flat `client_metadata`, and canonical `x-codex-turn-metadata` transport.
3. **Responses / WebSocket** — HTTP upgrade headers and `response.create.client_metadata`, including WebSocket-only projections such as W3C trace context and turn-state.
4. **Full turn metadata schema** — fields parsed directly from `CodexTurnMetadataPayload`, plus nested workspace/tool/compaction structures.

## What “full HTTP headers” means

The audit enumerates headers that are explicitly constructed by Codex source or injected by its auth/provider layers. It does **not** invent values that the HTTP/WebSocket stack creates at runtime, such as:

- `Host`
- `Content-Length` / `Transfer-Encoding`
- `Accept-Encoding`
- `Connection` / `Upgrade`
- `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, negotiated extensions
- proxy-added headers
- actual Cloudflare cookie names/values

Those are reported as runtime transport headers instead of being presented as stable Codex protocol fields.

## Why this is source-driven

The script extracts the current `CodexTurnMetadataPayload` and related nested structs directly from Rust source. It also verifies known request-header anchors against the fetched revision. If OpenAI renames/removes a required source anchor, the audit fails loudly instead of silently returning a stale baked-in schema.
