#!/usr/bin/env python3
"""Fetch openai/codex source and audit Codex wire identity metadata.

The report separates actual HTTP headers from flat client_metadata and from
WebSocket response.create-only metadata. Rust serde annotations are preserved so
consumers can distinguish optional/skipped fields instead of treating every
source field as always present on the wire.

One GitHub ref is resolved to an immutable SHA before files are fetched, so a
report never mixes revisions while main is moving. Standard-library only.
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
    "inference": "codex-rs/rollout-trace/src/inference.rs",
}

STANDARD_CONSTS = {
    "USER_AGENT": "User-Agent",
    "AUTHORIZATION": "Authorization",
    "CONTENT_TYPE": "Content-Type",
    "CONTENT_ENCODING": "Content-Encoding",
    "ACCEPT": "Accept",
}

CORE_BASE_CLIENT_METADATA = {
    "x-codex-installation-id",
    "session_id",
    "thread_id",
    "x-codex-window-id",
}

KNOWN_CONDITIONAL_CLIENT_METADATA = {
    "turn_id",
    "x-openai-subagent",
    "x-codex-parent-thread-id",
    "parent_turn_id",
    "root_turn_id",
    "x-codex-turn-metadata",
}

CLIENT_METADATA_CONDITIONS = {
    "x-codex-installation-id": "always in CodexResponsesMetadata::client_metadata",
    "session_id": "always in CodexResponsesMetadata::client_metadata",
    "thread_id": "always in CodexResponsesMetadata::client_metadata",
    "x-codex-window-id": "always in CodexResponsesMetadata::client_metadata",
    "turn_id": "when turn_id exists",
    "x-openai-subagent": "when subagent_header exists",
    "x-codex-parent-thread-id": "when parent_thread_id exists",
    "parent_turn_id": "when parent_turn_id exists",
    "root_turn_id": "when root_turn_id exists",
    "x-codex-turn-metadata": "when request_kind exists and metadata serializes",
}

WS_METADATA_CONDITIONS = {
    "ws_request_header_traceparent": "when W3C traceparent exists",
    "ws_request_header_tracestate": "when W3C tracestate exists",
    "ws_request_header_x_openai_internal_codex_responses_lite": "Responses Lite only",
    "x-codex-turn-state": "when the server supplied turn state for this turn",
    "x-codex-ws-stream-request-start-ms": "always on each response.create just before send",
}


class AuditError(RuntimeError):
    pass


def gh_json(url: str, token: str | None) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "codex-wire-audit/1.1",
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


def src(text: str, path: str, needle: str, symbol: str | None = None, start: int = 0) -> dict[str, Any]:
    i = text.find(needle, start)
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


def const_definitions(sources: dict[str, str]) -> list[tuple[str, str]]:
    rx = re.compile(
        r'(?ms)^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"\s*;'
    )
    out: list[tuple[str, str]] = []
    for text in sources.values():
        out.extend(rx.findall(text))
    return out


def struct_body(text: str, name: str) -> tuple[str, int]:
    m = re.search(rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+{re.escape(name)}\b[^{{]*\{{", text)
    if not m:
        raise AuditError(f"struct not found: {name}")
    start = m.end()
    depth = 1
    i = start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i], start
        i += 1
    raise AuditError(f"struct closing brace not found: {name}")


def serde_field_properties(field_type: str, attrs: list[str], name: str) -> dict[str, Any]:
    serde = " ".join(attrs)
    rename = re.search(r'\brename\s*=\s*"([^"]+)"', serde)
    skip_if = re.search(r'\bskip_serializing_if\s*=\s*"([^"]+)"', serde)
    skipped = bool(re.search(r'\bskip(?:\s*[,\)])|\bskip_serializing(?:\s*[,\)])', serde))
    return {
        "wire_name": rename.group(1) if rename else name,
        "optional": bool(re.search(r"\bOption\s*<", field_type)),
        "serde_default": bool(re.search(r"(?:\(|,)\s*default(?:\s*[,\)])", serde)),
        "skip_serializing_if": skip_if.group(1) if skip_if else None,
        "skipped": skipped,
        "serialized": not skipped,
    }


def struct_fields(text: str, path: str, name: str) -> list[dict[str, Any]]:
    body, offset = struct_body(text, name)
    fields: list[dict[str, Any]] = []
    attrs: list[str] = []
    rx = re.compile(
        r"(?m)^\s*(#\[[^\n]+\]|(?:pub(?:\([^)]*\))?\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:[^\n]+)"
    )
    for m in rx.finditer(body):
        raw = m.group(1).strip()
        if raw.startswith("#["):
            attrs.append(raw)
            continue
        f = re.match(
            r"(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?),?\s*$",
            raw,
        )
        if not f:
            attrs.clear()
            continue
        field_name = f.group(1)
        field_type = f.group(2).rstrip(",")
        item = {
            "name": field_name,
            "type": field_type,
            "serde": list(attrs),
            "flattened": any("flatten" in a for a in attrs),
            "source": {"path": path, "line": line_no(text, offset + m.start()), "symbol": name},
        }
        item.update(serde_field_properties(field_type, attrs, field_name))
        fields.append(item)
        attrs = []
    return fields


def key_tokens(block: str, cmap: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for token in re.findall(r"\b([A-Z][A-Z0-9_]*)\.to_string\(\)", block):
        if token in cmap:
            names.add(cmap[token])
    for literal in re.findall(r'"([A-Za-z0-9_.-]+)"\.to_string\(\)', block):
        if literal != "true":
            names.add(literal)
    return names


def client_metadata_keys(
    metadata: str, core: str, common: str, *, strict: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    cmap = consts({"metadata": metadata, "core": core, "common": common})
    a = metadata.find("fn client_metadata")
    b = metadata.find("fn compatibility_headers", a)
    if a < 0 or b < 0:
        raise AuditError("CodexResponsesMetadata client_metadata builder not found")
    block = metadata[a:b]

    initial_match = re.search(r"HashMap::from\(\[(.*?)\]\s*\)", block, re.S)
    initial = key_tokens(initial_match.group(1), cmap) if initial_match else set()
    names = key_tokens(block, cmap)

    missing_base = sorted(CORE_BASE_CLIENT_METADATA - names)
    if missing_base:
        raise AuditError("required base client_metadata keys missing upstream: " + ", ".join(missing_base))

    warnings: list[str] = []
    missing_conditional = sorted(KNOWN_CONDITIONAL_CLIENT_METADATA - names)
    if missing_conditional:
        warnings.append(
            "known conditional client_metadata keys absent upstream: " + ", ".join(missing_conditional)
        )
    if strict and warnings:
        raise AuditError("; ".join(warnings))

    reverse = {value: token for token, value in cmap.items()}

    def metadata_key_source(key: str) -> dict[str, Any]:
        token = reverse.get(key)
        local = block.find(token) if token else -1
        if local < 0:
            local = block.find(f'"{key}"')
        if local < 0:
            raise AuditError(f"no source anchor for client_metadata key: {key}")
        return {
            "path": FILES["metadata"],
            "line": line_no(metadata, a + local),
            "symbol": "CodexResponsesMetadata::client_metadata",
        }

    base = []
    for key in sorted(names):
        required = key in initial or key in CORE_BASE_CLIENT_METADATA
        base.append(
            {
                "name": key,
                "optional": not required,
                "condition": CLIENT_METADATA_CONDITIONS.get(
                    key, "always" if required else "conditional insertion in client_metadata()"
                ),
                "source": metadata_key_source(key),
            }
        )

    combined = core + "\n" + common
    definitions = const_definitions({"core": core, "common": common})
    ws_tokens = {
        token: value
        for token, value in definitions
        if token.endswith("CLIENT_METADATA_KEY") and len(re.findall(rf"\b{re.escape(token)}\b", combined)) >= 2
    }
    ws: list[dict[str, Any]] = []
    for token, key in sorted(ws_tokens.items(), key=lambda item: item[1]):
        text, path = (core, FILES["core"]) if token in core else (common, FILES["common"])
        ws.append(
            {
                "name": key,
                "optional": key != "x-codex-ws-stream-request-start-ms",
                "condition": WS_METADATA_CONDITIONS.get(key, "WS response.create metadata"),
                "source": src(text, path, token, "WS response.create client_metadata"),
            }
        )
    if "client_metadata.insert(X_CODEX_TURN_STATE_HEADER" in core:
        ws.append(
            {
                "name": "x-codex-turn-state",
                "optional": True,
                "condition": WS_METADATA_CONDITIONS["x-codex-turn-state"],
                "source": src(
                    core,
                    FILES["core"],
                    "client_metadata.insert(X_CODEX_TURN_STATE_HEADER",
                    "WS response.create client_metadata",
                ),
            }
        )
    ws.sort(key=lambda x: x["name"])
    return base, ws, warnings


def header(
    name: str,
    condition: str,
    text: str,
    path: str,
    anchor: str,
    value: str | None = None,
    layer: str = "codex",
    *,
    optional: bool = True,
    category: str = "protocol",
) -> dict[str, Any]:
    return {
        "name": name,
        "condition": condition,
        "optional": optional,
        "value_shape": value,
        "layer": layer,
        "category": category,
        "source": src(text, path, anchor, name),
    }


def discover_header_candidates(sources: dict[str, str]) -> list[str]:
    """Discover HTTP-header-shaped names without treating generic map inserts as headers."""
    cmap = consts(sources)
    found: set[str] = set()

    # Only header-specific APIs count. A constant name ending in _HEADER is not
    # enough: some Codex constants (for example installation identity) are used
    # only as client_metadata keys.
    literal_patterns = [
        r'insert_header\([^,]+,\s*"([A-Za-z0-9_-]+)"',
        r'\.(?:header)\(\s*"([A-Za-z0-9_-]+)"',
        r'\b(?:headers|extra_headers|default_headers|provider_headers)\.insert\(\s*"([A-Za-z0-9_-]+)"',
    ]
    token_patterns = [
        r'insert_header\([^,]+,\s*(?:http::header::)?([A-Z][A-Z0-9_]*)',
        r'\b(?:headers|extra_headers|default_headers|provider_headers)\.insert\(\s*(?:http::header::)?([A-Z][A-Z0-9_]*)',
        r'HeaderName::from_static\(\s*([A-Z][A-Z0-9_]*)',
    ]
    for text in sources.values():
        for pattern in literal_patterns:
            found.update(re.findall(pattern, text))
        for pattern in token_patterns:
            for token in re.findall(pattern, text):
                if token in cmap:
                    found.add(cmap[token])

    return sorted(found, key=str.lower)


def build_report(
    repo: str,
    ref: str,
    commit: dict[str, Any],
    s: dict[str, str],
    *,
    strict: bool = False,
) -> dict[str, Any]:
    account, default, auth = s["account"], s["default_client"], s["auth"]
    core, metadata, common = s["core"], s["metadata"], s["common"]
    hdrs, http, provider, request = s["headers"], s["http"], s["provider"], s["request"]
    att, inference = s["attestation"], s["inference"]

    account_headers = [
        header("User-Agent", "always", account, FILES["account"], "USER_AGENT", "get_codex_user_agent() or codex-cli", optional=False),
        header("Authorization", "bearer auth when token exists", auth, FILES["auth"], "AUTHORIZATION", "Bearer <token>", "auth", category="auth"),
        header("ChatGPT-Account-ID", "when account/workspace id exists", account, FILES["account"], "ChatGPT-Account-Id", "<account-id>", "auth/account", category="auth"),
        header("X-OpenAI-Fedramp", "FedRAMP only", account, FILES["account"], "X-OpenAI-Fedramp", "true", "auth/account", category="auth"),
    ]

    common_responses_headers = [
        header("originator", "normal Codex request", default, FILES["default_client"], 'headers.insert("originator"', "codex_cli_rs or host originator", optional=False),
        header("User-Agent", "default Codex client", default, FILES["default_client"], "USER_AGENT", "<originator>/<version> (<OS> <version>; <arch>) <terminal>", optional=False),
        header("x-openai-internal-codex-residency", "configured residency only", default, FILES["default_client"], "RESIDENCY_HEADER_NAME", "us"),
        header("Authorization", "bearer auth when active", auth, FILES["auth"], "AUTHORIZATION", "Bearer <token>", "auth", category="auth"),
        header("ChatGPT-Account-ID", "when auth carries account id", auth, FILES["auth"], "ChatGPT-Account-ID", None, "auth", category="auth"),
        header("X-OpenAI-Fedramp", "FedRAMP auth only", auth, FILES["auth"], "X-OpenAI-Fedramp", "true", "auth", category="auth"),
        header("session-id", "normal Codex Responses request", hdrs, FILES["headers"], '"session-id"', optional=False),
        header("thread-id", "normal Codex Responses request", hdrs, FILES["headers"], '"thread-id"', optional=False),
        header("x-codex-window-id", "window compatibility projection", metadata, FILES["metadata"], "X_CODEX_WINDOW_ID_HEADER", optional=False),
        header("x-codex-turn-metadata", "request_kind present; bounded compatibility projection omits tool_namespaces_info", metadata, FILES["metadata"], "X_CODEX_TURN_METADATA_HEADER", "ASCII JSON"),
        header("x-codex-parent-thread-id", "when parent thread exists", metadata, FILES["metadata"], "X_CODEX_PARENT_THREAD_ID_HEADER"),
        header("x-openai-subagent", "subagent/internal source when header value exists", metadata, FILES["metadata"], "X_OPENAI_SUBAGENT_HEADER"),
        header("x-codex-beta-features", "enabled beta feature keys", core, FILES["core"], '"x-codex-beta-features"', "comma-separated"),
        header("x-codex-routing-hint", "Codex backend routing hint when available", core, FILES["core"], "X_CODEX_ROUTING_HINT_HEADER", "model=<model>[;tier=<tier>]"),
        header("x-oai-attestation", "when attestation is enabled/provider returns value", att, FILES["attestation"], "X_OAI_ATTESTATION_HEADER", None, "attestation", category="attestation"),
        header("x-openai-memgen-request", "memory-consolidation session only", core, FILES["core"], "X_OPENAI_MEMGEN_REQUEST_HEADER", "true"),
    ]

    http_headers = common_responses_headers + [
        header("x-client-request-id", "set from thread_id", http, FILES["http"], '"x-client-request-id"', optional=False),
        header("x-openai-internal-codex-responses-lite", "Responses Lite only; real HTTP request header", core, FILES["core"], "X_OPENAI_INTERNAL_CODEX_RESPONSES_LITE_HEADER", "true"),
        header("x-codex-turn-state", "replayed within the same turn after server supplies it", core, FILES["core"], "X_CODEX_TURN_STATE_HEADER"),
        header("Accept", "HTTP streaming Responses", http, FILES["http"], "http::header::ACCEPT", "text/event-stream", "http", optional=False),
        header("Content-Type", "JSON body", request, FILES["request"], "CONTENT_TYPE", "application/json", "http", optional=False),
        header("Content-Encoding", "request compression enabled", request, FILES["request"], "CONTENT_ENCODING", "zstd", "http"),
    ]

    http_tracking_headers = [
        header("x-codex-inference-call-id", "rollout inference tracing enabled", inference, FILES["inference"], "INFERENCE_CALL_ID_HEADER", "UUID-like inference call id", "tracking", category="tracking"),
    ]

    ws_headers = common_responses_headers + [
        header("x-client-request-id", "set from thread_id during WebSocket handshake", core, FILES["core"], 'headers.insert("x-client-request-id"', optional=False),
        header("OpenAI-Beta", "Responses WebSocket upgrade", core, FILES["core"], "OPENAI_BETA_HEADER", "responses_websockets=2026-02-06", "ws-handshake", optional=False),
        header("x-responsesapi-include-timing-metrics", "timing metrics enabled", core, FILES["core"], "X_RESPONSESAPI_INCLUDE_TIMING_METRICS_HEADER", "true", "ws-handshake"),
    ]

    base_cm, ws_cm, warnings = client_metadata_keys(metadata, core, common, strict=strict)
    turn = struct_fields(metadata, FILES["metadata"], "CodexTurnMetadataPayload")
    extra = next((f for f in turn if f["name"] == "extra"), None)
    fixed = [f for f in turn if f["name"] != "extra"]

    kinds = re.findall(r'CodexResponsesRequestKind::\w+(?:\([^)]*\))?\s*=>\s*\("([^"]+)"', metadata)
    kinds = list(dict.fromkeys(kinds))

    endpoints = []
    for path in ("/api/codex/accounts/check", "/wham/accounts/check"):
        if path not in account:
            warnings.append(f"account status endpoint absent upstream: {path}")
        else:
            endpoints.append(path)
    if strict and warnings:
        raise AuditError("; ".join(warnings))

    declared = {
        h["name"]
        for h in account_headers + http_headers + http_tracking_headers + ws_headers
    }
    candidate_sources = {k: v for k, v in s.items() if k != "ws"}
    candidates = discover_header_candidates(candidate_sources)
    unclassified = [name for name in candidates if name not in declared]

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {"repo": repo, "ref": ref, "commit": commit, "files": list(FILES.values())},
        "scope": {
            "http_headers": "Actual Codex/auth/provider/request-preparation headers. Generic HashMap.insert calls are intentionally excluded from header discovery.",
            "runtime_transport_headers": [
                "Host", "Content-Length/Transfer-Encoding", "Accept-Encoding",
                "Connection/Upgrade", "Sec-WebSocket-*", "proxy-added headers",
                "runtime Cloudflare Cookie values",
            ],
            "all_discovered_header_candidates": candidates,
            "unclassified_header_candidates": unclassified,
            "warnings": warnings,
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
            "tracking_headers": http_tracking_headers,
            "dynamic_header_sources": [{
                "name": "provider.headers",
                "optional": True,
                "source": src(provider, FILES["provider"], "pub headers: HeaderMap", "Provider.headers"),
            }],
            "client_metadata_wire_type": "Option<HashMap<String, String>>",
            "client_metadata": base_cm,
            "turn_metadata": {
                "canonical": 'client_metadata["x-codex-turn-metadata"] JSON string',
                "optional": True,
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
                "optional": True,
                "compatibility_handshake_header": "x-codex-turn-metadata can be in upgrade compatibility headers; tool_namespaces_info omitted there",
            },
            "notes": [
                "Responses Lite is a literal HTTP header on HTTP transport but ws_request_header_x_openai_internal_codex_responses_lite inside response.create on WebSocket.",
                "x-codex-turn-state is carried in response.create client_metadata for per-message WS continuation state, not as a mutable handshake header.",
                "Connection/Upgrade/Sec-WebSocket-* are generated by the WebSocket stack, not hard-coded protocol identity fields.",
            ],
        },
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
                "optional is derived from Option<T>; skip_serializing_if/default/rename are derived from serde attributes.",
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
        optional = "optional" if h.get("optional") else "required/current-normal-path"
        print(f"  - {h['name']}: {optional}; {h['condition']}{value}")
        print(f"      source: {fmt_source(h['source'])}")


def print_cm(items: list[dict[str, Any]]) -> None:
    for x in items:
        optional = "optional" if x.get("optional") else "required/current-normal-path"
        print(f"  - {x['name']}: {optional}; {x.get('condition', '')}")
        print(f"      source: {fmt_source(x['source'])}")


def print_schema_fields(items: list[dict[str, Any]]) -> None:
    for f in items:
        flags: list[str] = []
        if f.get("optional"):
            flags.append("optional")
        if f.get("skip_serializing_if"):
            flags.append(f"skip_if={f['skip_serializing_if']}")
        if f.get("serde_default"):
            flags.append("serde_default")
        if f.get("skipped"):
            flags.append("serde_skip")
        if f.get("wire_name") != f.get("name"):
            flags.append(f"wire={f['wire_name']}")
        suffix = f" [{', '.join(flags)}]" if flags else ""
        print(f"  - {f['name']}: {f['type']}{suffix}")


def print_text(r: dict[str, Any]) -> None:
    c = r["source"]["commit"]
    print(f"Codex wire audit: {r['source']['repo']}@{c['sha']}")
    print(f"ref: {r['source']['ref']}")
    print(f"commit date: {c.get('date')}")
    print(f"commit: {c.get('message')}\n")

    print("=== 1. ACCOUNT / STATUS CHECK ===")
    print("Endpoints:")
    for x in r["account_status_check"]["endpoints"]:
        print(f"  - {x}")
    print("HTTP headers:")
    print_headers(r["account_status_check"]["http_headers"])
    print("client_metadata: none")
    print("turn_metadata: none")

    print("\n=== 2. RESPONSES / HTTP ===")
    print("HTTP headers:")
    print_headers(r["responses_http"]["http_headers"])
    if r["responses_http"].get("tracking_headers"):
        print("Optional tracking headers:")
        print_headers(r["responses_http"]["tracking_headers"])
    print("client_metadata:")
    print_cm(r["responses_http"]["client_metadata"])

    print("\n=== 3. RESPONSES / WEBSOCKET ===")
    print("Handshake HTTP headers:")
    print_headers(r["responses_websocket"]["handshake_http_headers"])
    print("Base response.create client_metadata:")
    print_cm(r["responses_websocket"]["client_metadata_base"])
    print("WS-only/additional response.create client_metadata:")
    print_cm(r["responses_websocket"]["client_metadata_ws_additions"])

    print("\n=== 4. FULL x-codex-turn-metadata SCHEMA ===")
    print_schema_fields(r["turn_metadata_schema"]["fixed_fields"])
    if r["turn_metadata_schema"]["flattened_extra"]:
        f = r["turn_metadata_schema"]["flattened_extra"]
        print(f"  - [flattened extra]: {f['type']}")
    print("request_kind: " + ", ".join(r["turn_metadata_schema"]["request_kind_values"]))
    for name, fields in r["turn_metadata_schema"]["nested"].items():
        print(f"Nested {name}:")
        print_schema_fields(fields)

    if r["scope"]["unclassified_header_candidates"]:
        print("\nUnclassified header candidates (review upstream changes):")
        for x in r["scope"]["unclassified_header_candidates"]:
            print(f"  - {x}")
    if r["scope"]["warnings"]:
        print("\nWarnings:")
        for x in r["scope"]["warnings"]:
            print(f"  - {x}")


def self_test() -> None:
    demo = """
struct Demo<'a> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    a: Option<&'a str>,
    #[serde(rename = "wire_b", skip_serializing_if = "str::is_empty")]
    b: &'a str,
    #[serde(skip)]
    hidden: String,
    #[serde(flatten)]
    extra: &'a BTreeMap<String, String>,
}
"""
    f = struct_fields(demo, "demo.rs", "Demo")
    assert [x["name"] for x in f] == ["a", "b", "hidden", "extra"]
    assert f[0]["optional"] and f[0]["serde_default"]
    assert f[0]["skip_serializing_if"] == "Option::is_none"
    assert f[1]["wire_name"] == "wire_b"
    assert f[2]["skipped"] and not f[2]["serialized"]
    assert f[3]["flattened"]

    fake_sources = {
        "x": '''
const X_REAL_HEADER: &str = "x-real-header";
const WS_REQUEST_HEADER_THING_CLIENT_METADATA_KEY: &str = "ws_request_header_thing";
fn f(headers: &mut HeaderMap, client_metadata: &mut HashMap<String, String>) {
    headers.insert(X_REAL_HEADER, v);
    headers.insert("x-literal-header", v);
    insert_header(headers, "session-id", v);
    client_metadata.insert("turn_id".to_string(), v.to_string());
    client_metadata.insert(WS_REQUEST_HEADER_THING_CLIENT_METADATA_KEY.to_string(), v.to_string());
}
'''
    }
    candidates = discover_header_candidates(fake_sources)
    assert "x-real-header" in candidates
    assert "x-literal-header" in candidates
    assert "session-id" in candidates
    assert "turn_id" not in candidates
    assert "ws_request_header_thing" not in candidates

    metadata = '''
const X_CODEX_INSTALLATION_ID_HEADER: &str = "x-codex-installation-id";
const X_CODEX_WINDOW_ID_HEADER: &str = "x-codex-window-id";
const X_CODEX_TURN_METADATA_HEADER: &str = "x-codex-turn-metadata";
const X_OPENAI_SUBAGENT_HEADER: &str = "x-openai-subagent";
const X_CODEX_PARENT_THREAD_ID_HEADER: &str = "x-codex-parent-thread-id";
const SESSION_ID_KEY: &str = "session_id";
const THREAD_ID_KEY: &str = "thread_id";
const TURN_ID_KEY: &str = "turn_id";
const PARENT_TURN_ID_KEY: &str = "parent_turn_id";
const ROOT_TURN_ID_KEY: &str = "root_turn_id";
fn client_metadata(&self) -> HashMap<String, String> {
    let mut client_metadata = HashMap::from([
        (X_CODEX_INSTALLATION_ID_HEADER.to_string(), self.installation_id.clone()),
        (SESSION_ID_KEY.to_string(), self.session_id.clone()),
        (THREAD_ID_KEY.to_string(), self.thread_id.clone()),
        (X_CODEX_WINDOW_ID_HEADER.to_string(), self.window_id.clone()),
    ]);
    if let Some(turn_id) = &self.turn_id {
        client_metadata.insert(TURN_ID_KEY.to_string(), turn_id.clone());
    }
    if let Some(subagent) = &self.subagent {
        client_metadata.insert(X_OPENAI_SUBAGENT_HEADER.to_string(), subagent.clone());
    }
    if let Some(parent) = &self.parent {
        client_metadata.insert(X_CODEX_PARENT_THREAD_ID_HEADER.to_string(), parent.clone());
    }
    if let Some(parent_turn) = &self.parent_turn {
        client_metadata.insert(PARENT_TURN_ID_KEY.to_string(), parent_turn.clone());
    }
    if let Some(root_turn) = &self.root_turn {
        client_metadata.insert(ROOT_TURN_ID_KEY.to_string(), root_turn.clone());
    }
    client_metadata.insert(X_CODEX_TURN_METADATA_HEADER.to_string(), "{}".to_string());
    client_metadata
}
fn compatibility_headers(&self) {}
'''
    cm, _, warnings = client_metadata_keys(metadata, "", "")
    by_name = {x["name"]: x for x in cm}
    assert not by_name["session_id"]["optional"]
    assert by_name["turn_id"]["optional"]
    assert not warnings
    print("self-test: ok")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", default=REPO)
    p.add_argument("--ref", default=REF)
    p.add_argument("--api-base", default=API)
    p.add_argument("--token", default=os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"))
    p.add_argument("--json", action="store_true")
    p.add_argument("--output")
    p.add_argument("--strict", action="store_true", help="fail on missing known conditional fields/endpoints")
    p.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    a = p.parse_args()

    if a.self_test:
        self_test()
        return 0

    commit = resolve_commit(a.repo, a.ref, a.api_base, a.token)
    sources = {k: fetch_file(a.repo, commit["sha"], path, a.api_base, a.token) for k, path in FILES.items()}
    report = build_report(a.repo, a.ref, commit, sources, strict=a.strict)

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
