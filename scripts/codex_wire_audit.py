#!/usr/bin/env python3
"""Fetch latest openai/codex source and audit Codex wire metadata.

The report is split into:
  1) account/status check requests (accounts/check)
  2) Responses over HTTP requests
  3) Responses over WebSocket requests (upgrade + response.create)
  4) response-side HTTP headers and dynamic header families consumed by Codex
  5) the full x-codex-turn-metadata schema

Request-side entries describe headers Codex constructs or injects. Response-side
entries describe headers the Codex client parser knows how to consume; they are
*not* claims that the production server currently emits every listed header.
One GitHub ref is resolved to an immutable SHA before files are fetched, so a
report never mixes revisions while main is moving.

Standard-library only.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

REPO = "openai/codex"
REF = "main"
API = "https://api.github.com"

FILES = {
    "account": "codex-rs/backend-client/src/client.rs",
    "default_client": "codex-rs/login/src/auth/default_client.rs",
    "auth": "codex-rs/model-provider/src/bearer_auth_provider.rs",
    "core": "codex-rs/core/src/client.rs",
    "metadata": "codex-rs/core/src/responses_metadata.rs",
    "common": "codex-rs/codex-api/src/common.rs",
    "headers": "codex-rs/codex-api/src/requests/headers.rs",
    "http": "codex-rs/codex-api/src/endpoint/responses.rs",
    "ws": "codex-rs/codex-api/src/endpoint/responses_websocket.rs",
    "provider": "codex-rs/codex-api/src/provider.rs",
    "request": "codex-rs/http-client/src/request.rs",
    "attestation": "codex-rs/core/src/attestation.rs",
    "rate_limits": "codex-rs/codex-api/src/rate_limits.rs",
    "api_bridge": "codex-rs/codex-api/src/api_bridge.rs",
    "sse": "codex-rs/codex-api/src/sse/responses.rs",
    "safety_buffering": "codex-rs/codex-api/src/safety_buffering.rs",
    "models": "codex-rs/codex-api/src/endpoint/models.rs",
    "realtime_call": "codex-rs/codex-api/src/endpoint/realtime_call.rs",
}

STANDARD_CONSTS = {
    "USER_AGENT": "User-Agent",
    "AUTHORIZATION": "Authorization",
    "CONTENT_TYPE": "Content-Type",
    "CONTENT_ENCODING": "Content-Encoding",
    "ACCEPT": "Accept",
}


class AuditError(RuntimeError):
    pass


def gh_json(url: str, token: str | None) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "codex-wire-audit/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:1000]
        raise AuditError(f"GitHub HTTP {e.code}: {url}: {detail}") from e
    except urllib.error.URLError as e:
        raise AuditError(f"GitHub request failed: {url}: {e}") from e


def resolve_commit(repo: str, ref: str, api: str, token: str | None) -> dict[str, Any]:
    url = f"{api.rstrip('/')}/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}"
    d = gh_json(url, token)
    commit = d.get("commit") or {}
    return {
        "sha": d["sha"],
        "date": (commit.get("committer") or {}).get("date"),
        "message": (commit.get("message") or "").splitlines()[0],
        "html_url": d.get("html_url"),
    }


def fetch_file(repo: str, sha: str, path: str, api: str, token: str | None) -> str:
    p = urllib.parse.quote(path, safe="/")
    url = f"{api.rstrip('/')}/repos/{repo}/contents/{p}?ref={urllib.parse.quote(sha, safe='')}"
    d = gh_json(url, token)
    if d.get("encoding") != "base64" or "content" not in d:
        raise AuditError(f"unexpected contents response for {path}")
    return base64.b64decode(d["content"]).decode("utf-8")


def line_no(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def src(text: str, path: str, needle: str, symbol: str | None = None) -> dict[str, Any]:
    i = text.find(needle)
    if i < 0:
        raise AuditError(f"expected source anchor missing: {path}: {needle}")
    return {"path": path, "line": line_no(text, i), "symbol": symbol or needle}


def consts(sources: dict[str, str]) -> dict[str, str]:
    out = dict(STANDARD_CONSTS)
    rx = re.compile(
        r'(?ms)^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"\s*;'
    )
    for text in sources.values():
        out.update(rx.findall(text))
    return out


def struct_body(text: str, name: str) -> tuple[str, int]:
    m = re.search(rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+{re.escape(name)}\b[^{{]*\{{", text)
    if not m:
        raise AuditError(f"struct not found: {name}")
    start = m.end()
    end = re.search(r"(?m)^\s*}\s*$", text[start:])
    if not end:
        raise AuditError(f"struct closing brace not found: {name}")
    return text[start : start + end.start()], start


def struct_fields(text: str, path: str, name: str) -> list[dict[str, Any]]:
    body, offset = struct_body(text, name)
    fields: list[dict[str, Any]] = []
    attrs: list[str] = []
    for m in re.finditer(r"(?m)^\s*(#\[[^\n]+\]|(?:pub(?:\([^)]*\))?\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:[^\n]+)", body):
        raw = m.group(1).strip()
        if raw.startswith("#["):
            attrs.append(raw)
            continue
        f = re.match(r"(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?),?\s*$", raw)
        if not f:
            attrs.clear()
            continue
        fields.append({
            "name": f.group(1),
            "type": f.group(2).rstrip(","),
            "serde": attrs,
            "flattened": any("flatten" in a for a in attrs),
            "source": {"path": path, "line": line_no(text, offset + m.start()), "symbol": name},
        })
        attrs = []
    return fields


def client_metadata_keys(metadata: str, core: str, common: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cmap = consts({"metadata": metadata, "core": core, "common": common})
    a = metadata.find("fn client_metadata")
    b = metadata.find("fn compatibility_headers", a)
    if a < 0 or b < 0:
        raise AuditError("CodexResponsesMetadata client_metadata builder not found")
    block = metadata[a:b]

    names: set[str] = set()
    for token in re.findall(r"\b([A-Z][A-Z0-9_]*)\.to_string\(\)", block):
        if token in cmap:
            names.add(cmap[token])
    for literal in re.findall(r'"([^"]+)"\.to_string\(\)', block):
        if literal != "true":
            names.add(literal)

    required = [
        "x-codex-installation-id", "session_id", "thread_id", "x-codex-window-id",
        "turn_id", "x-openai-subagent", "x-codex-parent-thread-id",
        "parent_turn_id", "root_turn_id", "x-codex-turn-metadata",
    ]
    reverse = {value: name for name, value in cmap.items()}
    for key in required:
        token = reverse.get(key)
        if key not in metadata and (not token or token not in metadata):
            raise AuditError(f"expected client_metadata key missing upstream: {key}")
        names.add(key)

    def metadata_key_source(key: str) -> dict[str, Any]:
        anchor = key if key in metadata else reverse.get(key)
        if not anchor:
            raise AuditError(f"no source anchor for client_metadata key: {key}")
        return src(metadata, FILES["metadata"], anchor, "CodexResponsesMetadata::client_metadata")

    base = [
        {"name": key, "source": metadata_key_source(key)}
        for key in sorted(names)
    ]

    combined = core + "\n" + common
    ws_names = {
        value
        for name, value in cmap.items()
        if name.endswith("CLIENT_METADATA_KEY") and value in combined
    }
    if "client_metadata.insert(X_CODEX_TURN_STATE_HEADER" in core:
        ws_names.add("x-codex-turn-state")
    ws = []
    for key in sorted(ws_names):
        if key in core:
            s = src(core, FILES["core"], key, "WS client_metadata")
        else:
            s = src(common, FILES["common"], key, "WS client_metadata")
        ws.append({"name": key, "source": s})
    return base, ws


def header(name: str, condition: str, text: str, path: str, anchor: str, value: str | None = None, layer: str = "codex") -> dict[str, Any]:
    return {
        "name": name,
        "condition": condition,
        "value_shape": value,
        "layer": layer,
        "source": src(text, path, anchor, name),
    }


def response_header(name: str, condition: str, text: str, path: str, anchor: str) -> dict[str, Any]:
    item = header(name, condition, text, path, anchor, layer="response-parser")
    item["evidence"] = "parser_supported_not_server_observed"
    return item


def discover_header_candidates(sources: dict[str, str]) -> list[str]:
    cmap = consts(sources)
    found: set[str] = set()
    for text in sources.values():
        for lit in re.findall(r'(?:insert_header\([^,]+,\s*|\.header\(\s*|\.insert\(\s*)"([A-Za-z0-9_-]+)"', text):
            if "-" in lit or lit.lower() in {"originator", "authorization"}:
                found.add(lit)
        for token in re.findall(r'(?:\.insert\(\s*|\.header\(\s*)(?:http::header::)?([A-Z][A-Z0-9_]*)', text):
            if token in cmap:
                found.add(cmap[token])
    return sorted(found, key=str.lower)


def response_header_schema(s: dict[str, str]) -> dict[str, Any]:
    rate_limits = s["rate_limits"]
    api_bridge = s["api_bridge"]
    sse = s["sse"]
    safety = s["safety_buffering"]
    models = s["models"]
    realtime_call = s["realtime_call"]

    exact = [
        response_header("x-reasoning-included", "successful Responses/SSE or WS handshake metadata", sse, FILES["sse"], '"x-reasoning-included"'),
        response_header("x-codex-turn-state", "successful Responses/SSE or WS continuation state", sse, FILES["sse"], '"x-codex-turn-state"'),
        response_header("openai-model", "server-selected model", sse, FILES["sse"], '"openai-model"'),
        response_header("x-models-etag", "model manifest cache validator", sse, FILES["sse"], '"X-Models-Etag"'),
        response_header("x-request-id", "upstream request tracking and retry errors", sse, FILES["sse"], '"x-request-id"'),
        response_header("etag", "model manifest cache validator on GET /models", models, FILES["models"], "get(ETAG)"),
        response_header("location", "created realtime call resource URI", realtime_call, FILES["realtime_call"], "get(LOCATION)"),
        response_header("x-codex-safety-buffering-enabled", "safety buffering treatment metadata", safety, FILES["safety_buffering"], '"x-codex-safety-buffering-enabled"'),
        response_header("x-codex-safety-buffering-faster-model", "safety buffering fallback model", safety, FILES["safety_buffering"], '"x-codex-safety-buffering-faster-model"'),
        response_header("x-codex-active-limit", "429 usage_limit_reached selects the active quota family", api_bridge, FILES["api_bridge"], '"x-codex-active-limit"'),
        response_header("x-codex-promo-message", "429 usage_limit_reached promotional message", rate_limits, FILES["rate_limits"], '"x-codex-promo-message"'),
        response_header("x-codex-rate-limit-reached-type", "429 usage_limit_reached classification", rate_limits, FILES["rate_limits"], '"x-codex-rate-limit-reached-type"'),
        response_header("x-codex-credits-has-credits", "Codex credits snapshot", rate_limits, FILES["rate_limits"], '"x-codex-credits-has-credits"'),
        response_header("x-codex-credits-unlimited", "Codex credits snapshot", rate_limits, FILES["rate_limits"], '"x-codex-credits-unlimited"'),
        response_header("x-codex-credits-balance", "Codex credits snapshot", rate_limits, FILES["rate_limits"], '"x-codex-credits-balance"'),
        response_header("x-oai-request-id", "fallback upstream request tracking on errors", api_bridge, FILES["api_bridge"], '"x-oai-request-id"'),
        response_header("cf-ray", "fallback request tracking and unexpected-status diagnostics", api_bridge, FILES["api_bridge"], '"cf-ray"'),
        response_header("x-openai-authorization-error", "unexpected-status identity authorization diagnostics", api_bridge, FILES["api_bridge"], '"x-openai-authorization-error"'),
        response_header("x-error-json", "unexpected-status structured error diagnostics", api_bridge, FILES["api_bridge"], '"x-error-json"'),
    ]

    dynamic = [
        response_header("x-<limit-id>-primary-used-percent", "discovers and parses a metered quota family", rate_limits, FILES["rate_limits"], 'format!("{prefix}-primary-used-percent")'),
        response_header("x-<limit-id>-primary-window-minutes", "primary quota window length", rate_limits, FILES["rate_limits"], 'format!("{prefix}-primary-window-minutes")'),
        response_header("x-<limit-id>-primary-reset-at", "primary quota reset epoch", rate_limits, FILES["rate_limits"], 'format!("{prefix}-primary-reset-at")'),
        response_header("x-<limit-id>-secondary-used-percent", "secondary quota usage", rate_limits, FILES["rate_limits"], 'format!("{prefix}-secondary-used-percent")'),
        response_header("x-<limit-id>-secondary-window-minutes", "secondary quota window length", rate_limits, FILES["rate_limits"], 'format!("{prefix}-secondary-window-minutes")'),
        response_header("x-<limit-id>-secondary-reset-at", "secondary quota reset epoch", rate_limits, FILES["rate_limits"], 'format!("{prefix}-secondary-reset-at")'),
        response_header("x-<limit-id>-limit-name", "display name for a dynamically discovered quota family", rate_limits, FILES["rate_limits"], 'format!("{prefix}-limit-name")'),
    ]

    return {
        "evidence": "client_parser_schema; not proof of production server emission",
        "exact_headers": exact,
        "dynamic_header_patterns": dynamic,
        "websocket_events": [
            {
                "type": "codex.rate_limits",
                "effect": "converted to the same RateLimitSnapshot used by HTTP response headers",
                "source": src(rate_limits, FILES["rate_limits"], 'event.kind != "codex.rate_limits"', "parse_rate_limit_event"),
            }
        ],
    }


def build_report(repo: str, ref: str, commit: dict[str, Any], s: dict[str, str]) -> dict[str, Any]:
    account, default, auth = s["account"], s["default_client"], s["auth"]
    core, metadata, common = s["core"], s["metadata"], s["common"]
    hdrs, http, provider, request = s["headers"], s["http"], s["provider"], s["request"]
    att = s["attestation"]

    account_headers = [
        header("User-Agent", "always", account, FILES["account"], "USER_AGENT", "get_codex_user_agent() or codex-cli"),
        header("Authorization", "bearer auth when token exists", auth, FILES["auth"], "AUTHORIZATION", "Bearer <token>", "auth"),
        header("ChatGPT-Account-ID", "when account/workspace id exists", account, FILES["account"], "ChatGPT-Account-Id", "<account-id>", "auth/account"),
        header("X-OpenAI-Fedramp", "FedRAMP only", account, FILES["account"], "X-OpenAI-Fedramp", "true", "auth/account"),
    ]

    shared = [
        header("originator", "default process originator; may be thread-overridden", default, FILES["default_client"], 'headers.insert("originator"', "codex_cli_rs or host originator"),
        header("User-Agent", "default Codex client", default, FILES["default_client"], "USER_AGENT", "<originator>/<version> (<OS> <version>; <arch>) <terminal>"),
        header("x-openai-internal-codex-residency", "configured residency only", default, FILES["default_client"], "RESIDENCY_HEADER_NAME", "us"),
        header("Authorization", "bearer auth when active", auth, FILES["auth"], "AUTHORIZATION", "Bearer <token>", "auth"),
        header("ChatGPT-Account-ID", "when auth carries account id", auth, FILES["auth"], "ChatGPT-Account-ID", None, "auth"),
        header("X-OpenAI-Fedramp", "FedRAMP auth only", auth, FILES["auth"], "X-OpenAI-Fedramp", "true", "auth"),
        header("session-id", "normal Responses session identity", hdrs, FILES["headers"], '"session-id"'),
        header("thread-id", "normal Responses thread identity", hdrs, FILES["headers"], '"thread-id"'),
        header("x-client-request-id", "set to thread_id", http, FILES["http"], '"x-client-request-id"'),
        header("x-codex-window-id", "window compatibility projection", metadata, FILES["metadata"], "X_CODEX_WINDOW_ID_HEADER"),
        header("x-codex-turn-metadata", "request_kind present; compatibility projection omits tool_namespaces_info", metadata, FILES["metadata"], "X_CODEX_TURN_METADATA_HEADER", "ASCII JSON"),
        header("x-codex-parent-thread-id", "when parent thread exists", metadata, FILES["metadata"], "X_CODEX_PARENT_THREAD_ID_HEADER"),
        header("x-openai-subagent", "subagent requests", metadata, FILES["metadata"], "X_OPENAI_SUBAGENT_HEADER"),
        header("x-codex-beta-features", "enabled beta feature keys", core, FILES["core"], '"x-codex-beta-features"', "comma-separated"),
        header("x-codex-routing-hint", "Codex backend routing hint when available", core, FILES["core"], "X_CODEX_ROUTING_HINT_HEADER", "model=<model>[;tier=<tier>]"),
        header("x-oai-attestation", "when attestation is enabled/provider returns value", att, FILES["attestation"], "X_OAI_ATTESTATION_HEADER", None, "attestation"),
        header("x-openai-memgen-request", "memory-consolidation session only", core, FILES["core"], "X_OPENAI_MEMGEN_REQUEST_HEADER", "true"),
        header("x-openai-internal-codex-responses-lite", "Responses Lite only", core, FILES["core"], "X_OPENAI_INTERNAL_CODEX_RESPONSES_LITE_HEADER", "true"),
    ]

    http_headers = shared + [
        header("x-codex-turn-state", "replayed within the same turn after server supplies it", core, FILES["core"], '"x-codex-turn-state"'),
        header("Accept", "HTTP streaming Responses", http, FILES["http"], "http::header::ACCEPT", "text/event-stream", "http"),
        header("Content-Type", "JSON body", request, FILES["request"], "CONTENT_TYPE", "application/json", "http"),
        header("Content-Encoding", "request compression enabled", request, FILES["request"], "CONTENT_ENCODING", "zstd", "http"),
    ]

    ws_headers = shared + [
        header("OpenAI-Beta", "Responses WebSocket upgrade", core, FILES["core"], "OPENAI_BETA_HEADER", "responses_websockets=2026-02-06", "ws-handshake"),
        header("x-responsesapi-include-timing-metrics", "timing metrics enabled", core, FILES["core"], "X_RESPONSESAPI_INCLUDE_TIMING_METRICS_HEADER", "true", "ws-handshake"),
    ]

    base_cm, ws_cm = client_metadata_keys(metadata, core, common)
    turn = struct_fields(metadata, FILES["metadata"], "CodexTurnMetadataPayload")
    extra = next((f for f in turn if f["name"] == "extra"), None)
    fixed = [f for f in turn if f["name"] != "extra"]

    kinds = re.findall(r'CodexResponsesRequestKind::\w+(?:\([^)]*\))?\s*=>\s*\("([^"]+)"', metadata)
    kinds = list(dict.fromkeys(kinds))

    endpoints = []
    for path in ("/api/codex/accounts/check", "/wham/accounts/check"):
        if path not in account:
            raise AuditError(f"account status endpoint missing upstream: {path}")
        endpoints.append(path)

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {"repo": repo, "ref": ref, "commit": commit, "files": list(FILES.values())},
        "scope": {
            "request_http_headers": "Codex-explicit + auth/provider/request-preparation headers. Runtime transport-generated values are not guessed.",
            "response_http_headers": "Headers statically consumed by Codex response/error parsers. Parser support is not evidence that production currently emits each header.",
            "runtime_transport_headers": [
                "Host", "Content-Length/Transfer-Encoding", "Accept-Encoding",
                "Connection/Upgrade", "Sec-WebSocket-*", "proxy-added headers",
                "runtime Cloudflare Cookie values",
            ],
            "all_discovered_request_header_candidates": discover_header_candidates({
                k: v for k, v in s.items() if k not in {"rate_limits", "api_bridge", "sse", "safety_buffering"}
            }),
        },
        "account_status_check": {
            "request": "GET accounts/check",
            "endpoints": endpoints,
            "http_headers": account_headers,
            "client_metadata": [],
            "turn_metadata": None,
            "notes": [
                "The backend status client builds its own HeaderMap; originator is not part of that builder.",
                "ChatGPT Cloudflare cookies can be attached by the transport at runtime.",
            ],
        },
        "responses_http": {
            "request": "POST /responses (and Responses-compatible Guardian routes)",
            "http_headers": http_headers,
            "dynamic_header_sources": [{
                "name": "provider.headers",
                "source": src(provider, FILES["provider"], "pub headers: HeaderMap", "Provider.headers"),
            }],
            "client_metadata_wire_type": "Option<HashMap<String, String>>",
            "client_metadata": base_cm,
            "turn_metadata": {
                "canonical": 'client_metadata["x-codex-turn-metadata"] JSON string',
                "compatibility_header": "x-codex-turn-metadata; tool_namespaces_info removed from bounded header projection",
            },
        },
        "responses_websocket": {
            "request": "HTTP Upgrade + response.create",
            "handshake_http_headers": ws_headers,
            "client_metadata_wire_type": "Option<HashMap<String, String>> in response.create",
            "client_metadata_base": base_cm,
            "client_metadata_ws_additions": ws_cm,
            "turn_metadata": {
                "canonical": 'response.create.client_metadata["x-codex-turn-metadata"] JSON string',
                "compatibility_handshake_header": "x-codex-turn-metadata can be in upgrade compatibility headers; tool_namespaces_info omitted there",
            },
            "notes": [
                "x-codex-turn-state is carried in response.create client_metadata for per-message WS continuation state.",
                "Connection/Upgrade/Sec-WebSocket-* are generated by the WebSocket stack, not hard-coded protocol identity fields.",
            ],
        },
        "response_headers": response_header_schema(s),
        "turn_metadata_schema": {
            "fixed_fields": fixed,
            "flattened_extra": extra,
            "request_kind_values": kinds,
            "nested": {
                "workspace": struct_fields(metadata, FILES["metadata"], "TurnMetadataWorkspace"),
                "tool_namespace": struct_fields(metadata, FILES["metadata"], "TurnToolNamespaceInfo"),
                "tool_function": struct_fields(metadata, FILES["metadata"], "TurnToolFunctionInfo"),
                "compaction": struct_fields(metadata, FILES["metadata"], "CompactionTurnMetadata"),
            },
            "notes": [
                "Fields are conditional/optional according to request kind and available context.",
                "serde(flatten) extra fields serialize at the same JSON object level; there is no wire-level extra wrapper.",
                "Memory request_kind suppresses normal turn/request identity according to has_turn_identity().",
            ],
        },
    }


def fmt_source(s: dict[str, Any]) -> str:
    return f"{s['path']}:{s['line']} ({s['symbol']})"


def print_headers(items: list[dict[str, Any]]) -> None:
    for h in items:
        value = f"; value={h['value_shape']}" if h.get("value_shape") else ""
        evidence = f"; evidence={h['evidence']}" if h.get("evidence") else ""
        print(f"  - {h['name']}: {h['condition']}{value}{evidence}")
        print(f"      source: {fmt_source(h['source'])}")


def print_cm(items: list[dict[str, Any]]) -> None:
    for x in items:
        print(f"  - {x['name']}")
        print(f"      source: {fmt_source(x['source'])}")


def print_text(r: dict[str, Any]) -> None:
    c = r["source"]["commit"]
    print(f"Codex wire audit: {r['source']['repo']}@{c['sha']}")
    print(f"ref: {r['source']['ref']}")
    print(f"commit date: {c.get('date')}")
    print(f"commit: {c.get('message')}\n")

    print("=== 1. ACCOUNT / STATUS CHECK REQUEST ===")
    print("Endpoints:")
    for x in r["account_status_check"]["endpoints"]:
        print(f"  - {x}")
    print("HTTP headers:")
    print_headers(r["account_status_check"]["http_headers"])
    print("client_metadata: none")
    print("turn_metadata: none")

    print("\n=== 2. RESPONSES / HTTP REQUEST ===")
    print("HTTP headers:")
    print_headers(r["responses_http"]["http_headers"])
    print("client_metadata:")
    print_cm(r["responses_http"]["client_metadata"])
    print("turn_metadata:")
    print(f"  canonical: {r['responses_http']['turn_metadata']['canonical']}")
    print(f"  compatibility: {r['responses_http']['turn_metadata']['compatibility_header']}")

    print("\n=== 3. RESPONSES / WEBSOCKET REQUEST ===")
    print("Handshake HTTP headers:")
    print_headers(r["responses_websocket"]["handshake_http_headers"])
    print("Base response.create client_metadata:")
    print_cm(r["responses_websocket"]["client_metadata_base"])
    print("WS-only/additional response.create client_metadata:")
    print_cm(r["responses_websocket"]["client_metadata_ws_additions"])

    print("\n=== 4. RESPONSE HEADERS CONSUMED BY CODEX ===")
    print("Exact response headers:")
    print_headers(r["response_headers"]["exact_headers"])
    print("Dynamic response header patterns:")
    print_headers(r["response_headers"]["dynamic_header_patterns"])
    print("WebSocket response-side events:")
    for event in r["response_headers"]["websocket_events"]:
        print(f"  - {event['type']}: {event['effect']}")
        print(f"      source: {fmt_source(event['source'])}")

    print("\n=== 5. FULL x-codex-turn-metadata SCHEMA ===")
    for f in r["turn_metadata_schema"]["fixed_fields"]:
        print(f"  - {f['name']}: {f['type']}")
    if r["turn_metadata_schema"]["flattened_extra"]:
        f = r["turn_metadata_schema"]["flattened_extra"]
        print(f"  - [flattened extra]: {f['type']}")
    print("request_kind: " + ", ".join(r["turn_metadata_schema"]["request_kind_values"]))
    for name, fields in r["turn_metadata_schema"]["nested"].items():
        print(f"Nested {name}:")
        for f in fields:
            print(f"  - {f['name']}: {f['type']}")

    print("\nRuntime-generated / not statically fixed:")
    for x in r["scope"]["runtime_transport_headers"]:
        print(f"  - {x}")


def self_test() -> None:
    demo = '''\nstruct Demo<'a> {\n    #[serde(skip_serializing_if = "Option::is_none")]\n    a: Option<&'a str>,\n    b: u64,\n    #[serde(flatten)]\n    extra: &'a BTreeMap<String, String>,\n}\n'''
    f = struct_fields(demo, "demo.rs", "Demo")
    assert [x["name"] for x in f] == ["a", "b", "extra"]
    assert f[-1]["flattened"]

    dynamic_demo = 'let name = format!("{prefix}-limit-name");'
    assert src(dynamic_demo, "demo.rs", 'format!("{prefix}-limit-name")')["line"] == 1
    print("self-test: ok")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", default=REPO)
    p.add_argument("--ref", default=REF)
    p.add_argument("--api-base", default=API)
    p.add_argument("--token", default=os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"))
    p.add_argument("--json", action="store_true")
    p.add_argument("--output")
    p.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    a = p.parse_args()

    if a.self_test:
        self_test()
        return 0

    commit = resolve_commit(a.repo, a.ref, a.api_base, a.token)
    sources = {k: fetch_file(a.repo, commit["sha"], path, a.api_base, a.token) for k, path in FILES.items()}
    report = build_report(a.repo, a.ref, commit, sources)

    if a.json:
        out = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    else:
        import io
        old, buf = sys.stdout, io.StringIO()
        try:
            sys.stdout = buf
            print_text(report)
        finally:
            sys.stdout = old
        out = buf.getvalue()

    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)
