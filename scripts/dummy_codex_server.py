#!/usr/bin/env python3
"""
Threaded HTTP/WebSocket capture server for inspecting Codex wire metadata.

Safe capture is the default:
- binds to loopback only
- redacts credentials, identity/continuation values, and metadata IDs
- skips prompt/tool/content fields
- strips URL query strings from logs
- does not persist raw request/WS payload bytes
- creates private dump files (umask 077)

Use --unsafe-full-capture only in an isolated environment with synthetic data.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DEFAULT_DUMP_DIR = os.environ.get("DUMP_DIR", "/tmp/codex_dumps")
DEFAULT_HOST = os.environ.get("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_MAX_CAPTURE_BYTES = int(os.environ.get("MAX_CAPTURE_BYTES", str(16 * 1024 * 1024)))

REDACTED = "<redacted>"
SKIPPED = "<skipped>"

DEFAULT_REDACT_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-openai-api-key",
    "chatgpt-account-id",
    "x-oai-attestation",
    "x-codex-installation-id",
    "session-id",
    "thread-id",
    "x-client-request-id",
    "x-codex-window-id",
    "x-codex-parent-thread-id",
    "x-codex-turn-state",
    "traceparent",
    "tracestate",
    "sec-websocket-key",
}

DEFAULT_REDACT_FIELDS = {
    "authorization",
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "cookie",
    "credentials",
    "account_id",
    "installation_id",
    "session_id",
    "thread_id",
    "turn_id",
    "parent_thread_id",
    "parent_turn_id",
    "root_turn_id",
    "window_id",
    "x-codex-window-id",
    "x-codex-parent-thread-id",
    "x-codex-installation-id",
    "x-codex-turn-state",
    "traceparent",
    "tracestate",
    "ws_request_header_traceparent",
    "ws_request_header_tracestate",
}

# These fields commonly carry user content, tool schemas/arguments, filesystem
# paths, or large inventories. Safe mode records their presence, not contents.
DEFAULT_SKIP_FIELDS = {
    "input",
    "instructions",
    "messages",
    "prompt",
    "content",
    "text",
    "arguments",
    "tool_calls",
    "tool_outputs",
    "tools",
    "tool_namespaces_info",
    "workspaces",
    "workspace",
    "cwd",
    "path",
    "paths",
    "description",
}

SAFE_SCALAR_FIELDS = {
    "type",
    "object",
    "model",
    "role",
    "status",
    "request_kind",
    "service_tier",
    "stream",
    "store",
}

DUMP_DIR = DEFAULT_DUMP_DIR
HOST = DEFAULT_HOST
PORT = DEFAULT_PORT
MAX_CAPTURE_BYTES = DEFAULT_MAX_CAPTURE_BYTES
UNSAFE_FULL_CAPTURE = False
ALLOW_REMOTE = False
ENABLE_CORS = False
REDACT_HEADERS = set(DEFAULT_REDACT_HEADERS)
REDACT_FIELDS = set(DEFAULT_REDACT_FIELDS)
SKIP_FIELDS = set(DEFAULT_SKIP_FIELDS)


class CaptureLimitError(ValueError):
    pass


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str) -> set[str]:
    value = os.environ.get(name, "")
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def now_str() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def normalize_name(name: object) -> str:
    return str(name).strip().lower()


def looks_sensitive_name(name: str) -> bool:
    n = normalize_name(name).replace("_", "-")
    markers = (
        "authorization",
        "credential",
        "password",
        "secret",
        "cookie",
        "api-key",
        "access-token",
        "refresh-token",
        "account-id",
        "installation-id",
        "session-id",
        "thread-id",
        "turn-id",
        "window-id",
        "turn-state",
        "request-id",
        "traceparent",
        "tracestate",
        "attestation",
    )
    return any(marker in n for marker in markers)


def sanitize_turn_metadata_string(value: str) -> str:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return REDACTED
    return json.dumps(sanitize_json(parsed), ensure_ascii=False, separators=(",", ":"))


def sanitize_header_value(name: str, value: str) -> str:
    if UNSAFE_FULL_CAPTURE:
        return value

    n = normalize_name(name)
    if n == "x-codex-turn-metadata":
        return sanitize_turn_metadata_string(value)
    if n in REDACT_HEADERS or looks_sensitive_name(n):
        return REDACTED
    return value


def sanitize_headers(headers) -> dict[str, str]:
    return {
        str(name): sanitize_header_value(str(name), str(value))
        for name, value in headers.items()
    }


def sanitize_json(value, key: str | None = None):
    if UNSAFE_FULL_CAPTURE:
        return value

    normalized = normalize_name(key) if key is not None else None

    if normalized is not None:
        if normalized in SKIP_FIELDS:
            return SKIPPED
        if normalized in REDACT_FIELDS or looks_sensitive_name(normalized):
            return REDACTED
        if normalized == "x-codex-turn-metadata" and isinstance(value, str):
            return sanitize_turn_metadata_string(value)

    if isinstance(value, dict):
        return {str(k): sanitize_json(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_json(v, key) for v in value]
    if isinstance(value, str):
        if normalized in SAFE_SCALAR_FIELDS:
            return value
        return REDACTED
    return value


def display_path(path: str) -> str:
    if UNSAFE_FULL_CAPTURE:
        return path
    return urlsplit(path).path or "/"


def safe_client(client_address) -> str:
    if UNSAFE_FULL_CAPTURE:
        return str(client_address)
    return REDACTED


def ensure_private_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_json(path: str, value) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False)


def parse_ws_frame(buf: bytes | bytearray):
    """Parse one WebSocket frame and enforce the configured payload limit."""
    if len(buf) < 2:
        return None, None, None, None, buf

    b0 = buf[0]
    b1 = buf[1]
    fin = (b0 & 0x80) != 0
    rsv = (b0 & 0x70) >> 4
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) != 0
    payload_len = b1 & 0x7F

    idx = 2
    if payload_len == 126:
        if len(buf) < idx + 2:
            return None, None, None, None, buf
        payload_len = struct.unpack("!H", buf[idx : idx + 2])[0]
        idx += 2
    elif payload_len == 127:
        if len(buf) < idx + 8:
            return None, None, None, None, buf
        payload_len = struct.unpack("!Q", buf[idx : idx + 8])[0]
        idx += 8

    if payload_len > MAX_CAPTURE_BYTES:
        raise CaptureLimitError(
            f"WebSocket frame payload {payload_len} exceeds limit {MAX_CAPTURE_BYTES}"
        )

    if masked:
        if len(buf) < idx + 4:
            return None, None, None, None, buf
        mask_key = buf[idx : idx + 4]
        idx += 4
    else:
        mask_key = None

    total_frame_len = idx + payload_len
    if len(buf) < total_frame_len:
        return None, None, None, None, buf

    raw_payload = bytearray(buf[idx:total_frame_len])
    remaining = buf[total_frame_len:]

    if masked and mask_key:
        for i in range(payload_len):
            raw_payload[i] ^= mask_key[i % 4]

    return fin, rsv, opcode, bytes(raw_payload), remaining


def make_ws_frame(opcode: int, payload_bytes: bytes) -> bytes:
    b0 = 0x80 | (opcode & 0x0F)
    payload_len = len(payload_bytes)
    if payload_len <= 125:
        header = bytes([b0, payload_len])
    elif payload_len <= 65535:
        header = bytes([b0, 126]) + struct.pack("!H", payload_len)
    else:
        header = bytes([b0, 127]) + struct.pack("!Q", payload_len)
    return header + payload_bytes


def make_ws_close(code: int, reason: str) -> bytes:
    reason_bytes = reason.encode("utf-8", errors="replace")[:123]
    return make_ws_frame(0x8, struct.pack("!H", code) + reason_bytes)


class MultiThreadedCatchAllHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        # BaseHTTPRequestHandler otherwise logs the full request target,
        # including query strings that can carry secrets.
        if UNSAFE_FULL_CAPTURE:
            super().log_message(fmt, *args)
        else:
            sys.stderr.write(
                '%s - - [%s] "%s %s" %s\n'
                % (
                    REDACTED,
                    self.log_date_time_string(),
                    getattr(self, "command", "-"),
                    display_path(getattr(self, "path", "/")),
                    args[-1] if args else "-",
                )
            )

    def do_all(self, method: str) -> None:
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.handle_websocket()
        else:
            self.handle_http(method)

    def do_GET(self):  # noqa: N802
        self.do_all("GET")

    def do_POST(self):  # noqa: N802
        self.do_all("POST")

    def do_PUT(self):  # noqa: N802
        self.do_all("PUT")

    def do_DELETE(self):  # noqa: N802
        self.do_all("DELETE")

    def do_PATCH(self):  # noqa: N802
        self.do_all("PATCH")

    def do_HEAD(self):  # noqa: N802
        self.do_all("HEAD")

    def do_OPTIONS(self):  # noqa: N802
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_cors_headers(self) -> None:
        if not ENABLE_CORS:
            return
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _new_dump_dir(self, prefix: str) -> str:
        path = os.path.join(DUMP_DIR, prefix)
        ensure_private_dir(path)
        return path

    def handle_websocket(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key", "")
        guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_key = base64.b64encode(
            hashlib.sha1((key + guid).encode("utf-8")).digest()
        ).decode("utf-8")

        headers_dict = sanitize_headers(self.headers)
        ts = now_str()
        session_dir = self._new_dump_dir(f"ws_{ts}")
        request_path = display_path(self.path)

        print(
            f"\n{'=' * 90}\n"
            f"[WS CONNECT in Thread {threading.current_thread().name}] "
            f"Path: {request_path} | Client: {safe_client(self.client_address)}\n"
            f"{'=' * 90}",
            flush=True,
        )
        print(
            f"Headers:\n{json.dumps(headers_dict, indent=2, ensure_ascii=False)}\n",
            flush=True,
        )

        write_json(
            os.path.join(session_dir, "00_handshake.json"),
            {
                "timestamp": ts,
                "path": request_path,
                "client": safe_client(self.client_address),
                "headers": headers_dict,
                "capture_mode": "unsafe-full" if UNSAFE_FULL_CAPTURE else "safe",
            },
        )

        # Do not negotiate permessage-deflate: captured frames stay plain JSON.
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        self.end_headers()

        sock = self.connection
        sock.settimeout(600.0)

        recv_buf = bytearray()
        frag_buf = bytearray()
        first_op = None
        turn = 0

        try:
            while True:
                chunk = sock.recv(131072)
                if not chunk:
                    break
                recv_buf.extend(chunk)

                while True:
                    fin, _rsv, opcode, frame_data, remaining = parse_ws_frame(recv_buf)
                    if opcode is None:
                        break
                    recv_buf = bytearray(remaining)

                    if opcode == 0x8:  # Close
                        print("[WS CLOSE] Client closed connection.", flush=True)
                        try:
                            sock.sendall(make_ws_frame(0x8, b""))
                        except Exception:
                            pass
                        return
                    if opcode == 0x9:  # Ping
                        sock.sendall(make_ws_frame(0xA, frame_data))
                        continue
                    if opcode == 0xA:  # Pong
                        continue
                    if opcode in (0x1, 0x2):
                        first_op = opcode
                        frag_buf = bytearray(frame_data)
                    elif opcode == 0x0:
                        frag_buf.extend(frame_data)

                    if len(frag_buf) > MAX_CAPTURE_BYTES:
                        raise CaptureLimitError(
                            f"fragmented WebSocket message exceeds limit {MAX_CAPTURE_BYTES}"
                        )

                    if not fin:
                        continue

                    turn += 1
                    msg_bytes = bytes(frag_buf)
                    frag_buf = bytearray()
                    first_op = None

                    if UNSAFE_FULL_CAPTURE:
                        with open(
                            os.path.join(session_dir, f"frame_{turn:04d}_raw.bin"), "wb"
                        ) as f:
                            f.write(msg_bytes)

                    parsed_json = None
                    try:
                        parsed_json = json.loads(msg_bytes.decode("utf-8"))
                    except Exception:
                        pass

                    if isinstance(parsed_json, dict):
                        ev_type = str(parsed_json.get("type") or "raw")
                        captured = sanitize_json(parsed_json)
                    else:
                        ev_type = "raw"
                        captured = {
                            "type": "raw",
                            "bytes": len(msg_bytes),
                            "payload": (
                                msg_bytes.decode("utf-8", errors="replace")
                                if UNSAFE_FULL_CAPTURE
                                else SKIPPED
                            ),
                        }

                    safe_ev_type = "".join(
                        c if c.isalnum() or c in "._-" else "_" for c in ev_type
                    )[:80] or "raw"
                    json_out_path = os.path.join(
                        session_dir, f"frame_{turn:04d}_{safe_ev_type}.json"
                    )
                    write_json(json_out_path, captured)

                    print(
                        f"\n[WS FRAME #{turn}] Type: {ev_type} | "
                        f"Bytes: {len(msg_bytes)} | Saved: {json_out_path}",
                        flush=True,
                    )
                    print(
                        json.dumps(captured, indent=2, ensure_ascii=False)[:3000],
                        flush=True,
                    )

                    if ev_type == "session.update":
                        ack = {
                            "type": "session.updated",
                            "session": {
                                "id": f"sess_{ts}",
                                "object": "realtime.session",
                            },
                        }
                        sock.sendall(
                            make_ws_frame(0x1, json.dumps(ack).encode("utf-8"))
                        )
                    elif ev_type == "response.create":
                        resp_id = f"resp_{now_str()}"
                        item_id = f"item_{now_str()}"
                        mock_frames = [
                            {
                                "type": "response.created",
                                "response": {
                                    "id": resp_id,
                                    "object": "realtime.response",
                                    "status": "in_progress",
                                    "status_details": None,
                                },
                            },
                            {
                                "type": "response.output_item.added",
                                "response_id": resp_id,
                                "output_index": 0,
                                "item": {
                                    "id": item_id,
                                    "object": "realtime.item",
                                    "type": "message",
                                    "status": "in_progress",
                                    "role": "assistant",
                                    "content": [],
                                },
                            },
                            {
                                "type": "response.content_part.added",
                                "response_id": resp_id,
                                "item_id": item_id,
                                "output_index": 0,
                                "content_index": 0,
                                "part": {"type": "text", "text": ""},
                            },
                            {
                                "type": "response.text.delta",
                                "response_id": resp_id,
                                "item_id": item_id,
                                "output_index": 0,
                                "content_index": 0,
                                "delta": "[Capture server] request received.",
                            },
                            {
                                "type": "response.text.done",
                                "response_id": resp_id,
                                "item_id": item_id,
                                "output_index": 0,
                                "content_index": 0,
                                "text": "[Capture server] request received.",
                            },
                            {
                                "type": "response.output_item.done",
                                "response_id": resp_id,
                                "output_index": 0,
                                "item": {
                                    "id": item_id,
                                    "object": "realtime.item",
                                    "type": "message",
                                    "status": "completed",
                                    "role": "assistant",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "[Capture server] request received.",
                                        }
                                    ],
                                },
                            },
                            {
                                "type": "response.completed",
                                "response": {
                                    "id": resp_id,
                                    "object": "realtime.response",
                                    "status": "completed",
                                    "usage": {
                                        "total_tokens": 100,
                                        "input_tokens": 50,
                                        "output_tokens": 50,
                                    },
                                },
                            },
                        ]
                        for mock_frame in mock_frames:
                            sock.sendall(
                                make_ws_frame(
                                    0x1, json.dumps(mock_frame).encode("utf-8")
                                )
                            )

        except CaptureLimitError as e:
            print(f"[WS LIMIT] {e}", file=sys.stderr, flush=True)
            try:
                sock.sendall(make_ws_close(1009, "capture payload too large"))
            except Exception:
                pass
        except (socket.timeout, ConnectionError, OSError) as e:
            print(f"[WS CLOSED] {type(e).__name__}: {e}", flush=True)
        except Exception as e:
            print(f"[WS EXCEPTION] {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    def handle_http(self, method: str) -> None:
        try:
            content_len = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "invalid Content-Length"})
            return

        if content_len < 0 or content_len > MAX_CAPTURE_BYTES:
            self.close_connection = True
            self.send_json(
                413,
                {
                    "error": "request too large for capture server",
                    "max_capture_bytes": MAX_CAPTURE_BYTES,
                },
            )
            return

        body = self.rfile.read(content_len) if content_len > 0 else b""

        req_ts = now_str()
        request_path = display_path(self.path)
        safe_path = request_path.replace("/", "_").strip("_") or "root"
        safe_path = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in safe_path
        )[:120]
        dump_dir = self._new_dump_dir(f"http_{req_ts}_{method}_{safe_path}")

        headers_dict = sanitize_headers(self.headers)

        if UNSAFE_FULL_CAPTURE and body:
            with open(os.path.join(dump_dir, "raw_body.bin"), "wb") as f:
                f.write(body)

        parsed_json = None
        if body:
            try:
                parsed_json = json.loads(body.decode("utf-8"))
            except Exception:
                pass

        if parsed_json is not None:
            captured_body = sanitize_json(parsed_json)
            body_text = ""
        elif body:
            captured_body = None
            body_text = (
                body.decode("utf-8", errors="replace")
                if UNSAFE_FULL_CAPTURE
                else f"{SKIPPED} ({len(body)} bytes)"
            )
        else:
            captured_body = None
            body_text = ""

        write_json(
            os.path.join(dump_dir, "request.json"),
            {
                "timestamp": req_ts,
                "method": method,
                "path": request_path,
                "client": safe_client(self.client_address),
                "headers": headers_dict,
                "body_json": captured_body,
                "body_text": body_text,
                "capture_mode": "unsafe-full" if UNSAFE_FULL_CAPTURE else "safe",
            },
        )

        print(
            f"\n{'=' * 90}\n"
            f"[HTTP {method} in Thread {threading.current_thread().name}] "
            f"Path: {request_path} | Bytes: {len(body)} | "
            f"Client: {safe_client(self.client_address)}\n"
            f"{'=' * 90}",
            flush=True,
        )
        print(
            f"Headers:\n{json.dumps(headers_dict, indent=2, ensure_ascii=False)}",
            flush=True,
        )
        if captured_body is not None:
            print(
                f"Body JSON:\n"
                f"{json.dumps(captured_body, indent=2, ensure_ascii=False)[:3000]}\n",
                flush=True,
            )
        elif body_text:
            print(f"Body Text:\n{body_text[:1000]}\n", flush=True)

        if request_path.startswith("/v1/models") or request_path.startswith("/models"):
            resp = {
                "object": "list",
                "data": [
                    {"id": "gpt-5.6-sol", "object": "model", "owned_by": "openai"},
                    {"id": "gpt-5.6-terra", "object": "model", "owned_by": "openai"},
                    {"id": "gpt-5.5", "object": "model", "owned_by": "openai"},
                    {"id": "gpt-5.2", "object": "model", "owned_by": "openai"},
                    {"id": "o3", "object": "model", "owned_by": "openai"},
                ],
            }
            self.send_json(200, resp)
        elif (
            "responses" in request_path
            or "chat/completions" in request_path
            or "conversation" in request_path
        ):
            resp = {
                "id": f"resp_{req_ts}",
                "object": "response",
                "status": "completed",
                "model": "gpt-5.6-sol",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "text",
                                "text": "[Capture server] request received.",
                            }
                        ],
                    }
                ],
                "usage": {
                    "total_tokens": 100,
                    "input_tokens": 50,
                    "output_tokens": 50,
                },
            }
            self.send_json(200, resp)
        else:
            self.send_json(
                200,
                {
                    "status": "ok",
                    "captured_at": req_ts,
                    "path": request_path,
                    "bytes": len(body),
                },
            )

    def send_json(self, status: int, obj) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self._send_cors_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


def is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def configure(args: argparse.Namespace) -> None:
    global DUMP_DIR, HOST, PORT, MAX_CAPTURE_BYTES
    global UNSAFE_FULL_CAPTURE, ALLOW_REMOTE, ENABLE_CORS
    global REDACT_HEADERS, REDACT_FIELDS, SKIP_FIELDS

    DUMP_DIR = args.dump_dir
    HOST = args.host
    PORT = args.port
    MAX_CAPTURE_BYTES = args.max_capture_bytes
    UNSAFE_FULL_CAPTURE = args.unsafe_full_capture or env_bool(
        "UNSAFE_FULL_CAPTURE", False
    )
    ALLOW_REMOTE = args.allow_remote or env_bool("ALLOW_REMOTE", False)
    ENABLE_CORS = args.enable_cors or env_bool("ENABLE_CORS", False)

    REDACT_HEADERS = (
        set(DEFAULT_REDACT_HEADERS)
        | env_csv("REDACT_HEADERS")
        | {normalize_name(x) for x in args.redact_header}
    )
    REDACT_FIELDS = (
        set(DEFAULT_REDACT_FIELDS)
        | env_csv("REDACT_FIELDS")
        | {normalize_name(x) for x in args.redact_field}
    )
    SKIP_FIELDS = (
        set(DEFAULT_SKIP_FIELDS)
        | env_csv("SKIP_FIELDS")
        | {normalize_name(x) for x in args.skip_field}
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--dump-dir", default=DEFAULT_DUMP_DIR)
    p.add_argument(
        "--max-capture-bytes",
        type=int,
        default=DEFAULT_MAX_CAPTURE_BYTES,
        help="maximum HTTP body, WS frame, or assembled WS message size",
    )
    p.add_argument(
        "--redact-header",
        action="append",
        default=[],
        metavar="NAME",
        help="add a header name whose value is redacted; repeatable",
    )
    p.add_argument(
        "--redact-field",
        action="append",
        default=[],
        metavar="NAME",
        help="add a JSON/metadata field whose value is redacted; repeatable",
    )
    p.add_argument(
        "--skip-field",
        action="append",
        default=[],
        metavar="NAME",
        help="add a JSON/metadata field whose contents are replaced with <skipped>",
    )
    p.add_argument(
        "--unsafe-full-capture",
        action="store_true",
        help="disable redaction/skipping and persist raw payloads (unsafe)",
    )
    p.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow binding to a non-loopback host",
    )
    p.add_argument(
        "--enable-cors",
        action="store_true",
        help="send permissive Access-Control-Allow-* headers",
    )
    p.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    return p


def self_test() -> None:
    global UNSAFE_FULL_CAPTURE
    previous = UNSAFE_FULL_CAPTURE
    UNSAFE_FULL_CAPTURE = False
    try:
        assert sanitize_header_value("Authorization", "Bearer secret") == REDACTED
        assert sanitize_header_value("x-random", "ok") == "ok"
        assert display_path("/responses?access_token=secret") == "/responses"

        metadata = json.dumps(
            {
                "session_id": "sess-secret",
                "request_kind": "regular",
                "workspaces": [{"cwd": "/secret/path"}],
            }
        )
        sanitized_metadata = json.loads(
            sanitize_header_value("x-codex-turn-metadata", metadata)
        )
        assert sanitized_metadata["session_id"] == REDACTED
        assert sanitized_metadata["request_kind"] == "regular"
        assert sanitized_metadata["workspaces"] == SKIPPED

        payload = sanitize_json(
            {
                "type": "response.create",
                "client_metadata": {
                    "thread_id": "thread-secret",
                    "x-codex-turn-metadata": metadata,
                },
                "input": [{"role": "user", "content": "top secret"}],
            }
        )
        assert payload["type"] == "response.create"
        assert payload["client_metadata"]["thread_id"] == REDACTED
        body_metadata = json.loads(
            payload["client_metadata"]["x-codex-turn-metadata"]
        )
        assert body_metadata["session_id"] == REDACTED
        assert body_metadata["request_kind"] == "regular"
        assert payload["input"] == SKIPPED
    finally:
        UNSAFE_FULL_CAPTURE = previous
    print("self-test: ok")


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    configure(args)

    if args.self_test:
        self_test()
        return 0

    if MAX_CAPTURE_BYTES <= 0:
        parser.error("--max-capture-bytes must be > 0")

    if not is_loopback_host(HOST) and not ALLOW_REMOTE:
        parser.error(
            "refusing non-loopback bind; use --allow-remote only on a trusted network"
        )

    os.umask(0o077)
    ensure_private_dir(DUMP_DIR)

    mode = "UNSAFE FULL CAPTURE" if UNSAFE_FULL_CAPTURE else "safe redacted capture"
    print(f"[*] Starting threaded Codex capture server on {HOST}:{PORT}")
    print(f"[*] Capture mode: {mode}")
    print(f"[*] Output directory: {DUMP_DIR}")
    print(f"[*] Max captured payload: {MAX_CAPTURE_BYTES} bytes")

    if UNSAFE_FULL_CAPTURE:
        print(
            "[!] WARNING: full capture stores credentials, prompts, metadata, "
            "and raw payloads. Use only with synthetic data.",
            file=sys.stderr,
        )
    if ALLOW_REMOTE and not is_loopback_host(HOST):
        print(
            "[!] WARNING: remote binding is enabled; this debugging server has no auth.",
            file=sys.stderr,
        )

    server = ThreadingHTTPServer((HOST, PORT), MultiThreadedCatchAllHandler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
