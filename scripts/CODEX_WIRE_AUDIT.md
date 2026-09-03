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

Use an environment variable to avoid the low unauthenticated GitHub API rate limit:

```bash
GITHUB_TOKEN=... python3 scripts/codex_wire_audit.py --json --output /tmp/codex-wire.json
```

Prefer `GITHUB_TOKEN`/`GH_TOKEN` over passing a token on the command line. Command-line secrets can be exposed through shell history and process listings.

The script uses only the Python standard library.

## Report layout

The output is deliberately separated into:

1. **Account / status check** — `accounts/check` request endpoints and HTTP headers. `client_metadata` and turn metadata do not apply here.
2. **Responses / HTTP** — HTTP request headers, flat `client_metadata`, and canonical `x-codex-turn-metadata` transport.
3. **Responses / WebSocket** — HTTP upgrade headers and `response.create.client_metadata`, including WebSocket-only projections such as W3C trace context and turn-state.
4. **Full turn metadata schema** — fields parsed directly from `CodexTurnMetadataPayload`, plus nested workspace/tool/compaction structures. The extracted `serde` attributes show fields that are optional/skipped by upstream serialization.

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

## Safe live capture

`scripts/dummy_codex_server.py` is for local HTTP/WebSocket wire inspection. It is now **safe-by-default** rather than a zero-filter recorder.

Default behavior:

- listens on `127.0.0.1` only
- refuses non-loopback binds unless `--allow-remote` is explicit
- redacts credentials, cookies, account/session/thread/turn IDs, attestation values, trace IDs, WebSocket keys, and continuation state
- parses `x-codex-turn-metadata` and keeps its structure while redacting sensitive values
- skips prompt/tool/content-heavy fields such as `input`, `instructions`, `content`, `text`, `tools`, `tool_namespaces_info`, and `workspaces`
- strips URL query strings from stored/logged request paths
- does not save raw HTTP bodies or raw WebSocket frames
- uses private dump permissions (`umask 077`, directories mode `0700`)
- rejects HTTP bodies, WS frames, and assembled WS messages larger than 16 MiB by default
- keeps permissive CORS disabled unless explicitly enabled

Run it normally:

```bash
python3 scripts/dummy_codex_server.py
```

Add project-specific redaction/skipping without changing the script:

```bash
python3 scripts/dummy_codex_server.py \
  --redact-header x-provider-session \
  --redact-field custom_identity \
  --skip-field proprietary_payload
```

The same additions can be supplied through comma-separated `REDACT_HEADERS`, `REDACT_FIELDS`, and `SKIP_FIELDS` environment variables.

A built-in sanitizer self-test is available:

```bash
python3 scripts/dummy_codex_server.py --self-test
```

### Unsafe full capture

If exact raw bytes/values are required for a synthetic test, opt in explicitly:

```bash
python3 scripts/dummy_codex_server.py --unsafe-full-capture
```

That mode restores full values and raw payload files. It can contain bearer tokens, cookies, prompts, workspace metadata, tool arguments/schemas, and other private material. Keep it loopback-only and use synthetic credentials/data.

Remote binding is a separate opt-in because the capture server has no authentication:

```bash
python3 scripts/dummy_codex_server.py --host 0.0.0.0 --allow-remote
```

Do not combine remote binding with unsafe full capture except in an isolated disposable environment.

## Why this is source-driven

The audit extracts the current `CodexTurnMetadataPayload` and related nested structs directly from Rust source. It also verifies known request-header anchors against the fetched revision. If OpenAI renames/removes a required source anchor, the audit fails loudly instead of silently returning a stale baked-in schema.
