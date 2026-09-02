#!/usr/bin/env python3
"""
Multi-Threaded Zero-Filter HTTP & WebSocket Dump Server (Port 8080)
Uses ThreadingHTTPServer so long-lived WebSockets never block incoming HTTP requests.
Captures 100% of all requests, methods, paths, headers, and payloads concurrently.
"""

import base64
import datetime
import hashlib
import json
import os
import socket
import struct
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DUMP_DIR = os.environ.get("DUMP_DIR", "/tmp/codex_dumps")
PORT = int(os.environ.get("PORT", "8080"))

os.makedirs(DUMP_DIR, exist_ok=True)

def now_str():
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')

def parse_ws_frame(buf):
    """Parses a WebSocket frame. Returns (fin, rsv, opcode, payload_bytes, remaining_buf)"""
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
        payload_len = struct.unpack("!H", buf[idx:idx+2])[0]
        idx += 2
    elif payload_len == 127:
        if len(buf) < idx + 8:
            return None, None, None, None, buf
        payload_len = struct.unpack("!Q", buf[idx:idx+8])[0]
        idx += 8

    if masked:
        if len(buf) < idx + 4:
            return None, None, None, None, buf
        mask_key = buf[idx:idx+4]
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

def make_ws_frame(opcode, payload_bytes):
    b0 = 0x80 | (opcode & 0x0F)
    payload_len = len(payload_bytes)
    if payload_len <= 125:
        header = bytes([b0, payload_len])
    elif payload_len <= 65535:
        header = bytes([b0, 126]) + struct.pack("!H", payload_len)
    else:
        header = bytes([b0, 127]) + struct.pack("!Q", payload_len)
    return header + payload_bytes

class MultiThreadedCatchAllHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_all(self, method):
        if self.headers.get('Upgrade', '').lower() == 'websocket':
            self.handle_websocket()
        else:
            self.handle_http(method)

    def do_GET(self): self.do_all('GET')
    def do_POST(self): self.do_all('POST')
    def do_PUT(self): self.do_all('PUT')
    def do_DELETE(self): self.do_all('DELETE')
    def do_PATCH(self): self.do_all('PATCH')
    def do_HEAD(self): self.do_all('HEAD')
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def handle_websocket(self):
        key = self.headers.get('Sec-WebSocket-Key', '')
        guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_key = base64.b64encode(hashlib.sha1((key + guid).encode('utf-8')).digest()).decode('utf-8')

        headers_dict = dict(self.headers)
        ts = now_str()
        session_dir = os.path.join(DUMP_DIR, f"ws_{ts}")
        os.makedirs(session_dir, exist_ok=True)

        print(f"\n{'='*90}\n[WS CONNECT in Thread {threading.current_thread().name}] Path: {self.path} | Client: {self.client_address}\n{'='*90}", flush=True)
        print(f"Headers:\n{json.dumps(headers_dict, indent=2, ensure_ascii=False)}\n", flush=True)

        with open(os.path.join(session_dir, "00_handshake.json"), "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": ts,
                "path": self.path,
                "client": str(self.client_address),
                "headers": headers_dict
            }, f, indent=2, ensure_ascii=False)

        # 101 Handshake without permessage-deflate to force uncompressed JSON
        self.send_response(101, 'Switching Protocols')
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept_key)
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
                    fin, rsv, opcode, frame_data, remaining = parse_ws_frame(recv_buf)
                    if opcode is None:
                        break
                    recv_buf = bytearray(remaining)

                    if opcode == 0x8:  # Close
                        print(f"[WS CLOSE] Client {self.client_address} closed connection.", flush=True)
                        try:
                            sock.sendall(make_ws_frame(0x8, b''))
                        except Exception:
                            pass
                        return
                    elif opcode == 0x9:  # Ping
                        sock.sendall(make_ws_frame(0xA, frame_data))
                        continue
                    elif opcode == 0xA:  # Pong
                        continue
                    elif opcode in (0x1, 0x2):
                        first_op = opcode
                        frag_buf = bytearray(frame_data)
                    elif opcode == 0x0:
                        frag_buf.extend(frame_data)

                    if not fin:
                        continue

                    turn += 1
                    msg_bytes = bytes(frag_buf)
                    msg_opcode = first_op if first_op is not None else 0x1
                    frag_buf = bytearray()
                    first_op = None

                    # Save raw binary
                    with open(os.path.join(session_dir, f"frame_{turn:04d}_raw.bin"), "wb") as f:
                        f.write(msg_bytes)

                    parsed_json = None
                    try:
                        parsed_json = json.loads(msg_bytes.decode('utf-8'))
                    except Exception:
                        pass

                    ev_type = parsed_json.get('type') if isinstance(parsed_json, dict) else 'raw'
                    json_out_path = os.path.join(session_dir, f"frame_{turn:04d}_{ev_type}.json")
                    with open(json_out_path, "w", encoding="utf-8") as f:
                        if parsed_json is not None:
                            json.dump(parsed_json, f, indent=2, ensure_ascii=False)
                        else:
                            f.write(msg_bytes.decode('utf-8', errors='replace'))

                    print(f"\n[WS FRAME #{turn}] Type: {ev_type} | Bytes: {len(msg_bytes)} | Saved: {json_out_path}", flush=True)
                    if parsed_json:
                        print(json.dumps(parsed_json, indent=2, ensure_ascii=False)[:3000], flush=True)

                    if ev_type == "session.update":
                        ack = {"type": "session.updated", "session": {"id": f"sess_{ts}", "object": "realtime.session"}}
                        sock.sendall(make_ws_frame(0x1, json.dumps(ack).encode('utf-8')))
                    elif ev_type == "response.create":
                        resp_id = f"resp_{now_str()}"
                        item_id = f"item_{now_str()}"
                        mock_frames = [
                            {"type": "response.created", "response": {"id": resp_id, "object": "realtime.response", "status": "in_progress", "status_details": None}},
                            {"type": "response.output_item.added", "response_id": resp_id, "output_index": 0, "item": {"id": item_id, "object": "realtime.item", "type": "message", "status": "in_progress", "role": "assistant", "content": []}},
                            {"type": "response.content_part.added", "response_id": resp_id, "item_id": item_id, "output_index": 0, "content_index": 0, "part": {"type": "text", "text": ""}},
                            {"type": "response.text.delta", "response_id": resp_id, "item_id": item_id, "output_index": 0, "content_index": 0, "delta": "[MultiThreaded Catch-All] Full payload captured 100%."},
                            {"type": "response.text.done", "response_id": resp_id, "item_id": item_id, "output_index": 0, "content_index": 0, "text": "[MultiThreaded Catch-All] Full payload captured 100%."},
                            {"type": "response.output_item.done", "response_id": resp_id, "output_index": 0, "item": {"id": item_id, "object": "realtime.item", "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "text", "text": "[MultiThreaded Catch-All] Full payload captured 100%."}]}},
                            {"type": "response.completed", "response": {"id": resp_id, "object": "realtime.response", "status": "completed", "usage": {"total_tokens": 100, "input_tokens": 50, "output_tokens": 50}}}
                        ]
                        for mf in mock_frames:
                            sock.sendall(make_ws_frame(0x1, json.dumps(mf).encode('utf-8')))

        except Exception as e:
            print(f"[WS EXCEPTION] {e}", flush=True)

    def handle_http(self, method):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len) if content_len > 0 else b''

        req_ts = now_str()
        safe_path = self.path.split('?')[0].replace('/', '_').strip('_') or 'root'
        dump_dir = os.path.join(DUMP_DIR, f"http_{req_ts}_{method}_{safe_path}")
        os.makedirs(dump_dir, exist_ok=True)

        headers_dict = dict(self.headers)
        
        if body:
            with open(os.path.join(dump_dir, "raw_body.bin"), "wb") as f:
                f.write(body)

        parsed_json = None
        if body:
            try:
                parsed_json = json.loads(body.decode('utf-8'))
            except Exception:
                pass

        with open(os.path.join(dump_dir, "request.json"), "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": req_ts,
                "method": method,
                "path": self.path,
                "client": str(self.client_address),
                "headers": headers_dict,
                "body_json": parsed_json,
                "body_text": body.decode('utf-8', errors='replace') if body else ""
            }, f, indent=2, ensure_ascii=False)

        print(f"\n{'='*90}\n[HTTP {method} in Thread {threading.current_thread().name}] Path: {self.path} | Bytes: {len(body)} | Client: {self.client_address}\n{'='*90}", flush=True)
        print(f"Headers:\n{json.dumps(headers_dict, indent=2, ensure_ascii=False)}", flush=True)
        if parsed_json:
            print(f"Body JSON:\n{json.dumps(parsed_json, indent=2, ensure_ascii=False)[:3000]}\n", flush=True)
        elif body:
            print(f"Body Text:\n{body[:1000].decode('utf-8', errors='replace')}\n", flush=True)

        if self.path.startswith('/v1/models') or self.path.startswith('/models'):
            resp = {
                "object": "list",
                "data": [
                    {"id": "gpt-5.6-sol", "object": "model", "owned_by": "openai"},
                    {"id": "gpt-5.6-terra", "object": "model", "owned_by": "openai"},
                    {"id": "gpt-5.5", "object": "model", "owned_by": "openai"},
                    {"id": "gpt-5.2", "object": "model", "owned_by": "openai"},
                    {"id": "o3", "object": "model", "owned_by": "openai"}
                ]
            }
            self.send_json(200, resp)
        elif 'responses' in self.path or 'chat/completions' in self.path or 'conversation' in self.path:
            resp = {
                "id": f"resp_{req_ts}",
                "object": "response",
                "status": "completed",
                "model": "gpt-5.6-sol",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "text", "text": "[MultiThreaded Catch-All] Full HTTP payload captured 100%."}]
                    }
                ],
                "usage": {"total_tokens": 100, "input_tokens": 50, "output_tokens": 50}
            }
            self.send_json(200, resp)
        else:
            self.send_json(200, {"status": "ok", "captured_at": req_ts, "path": self.path, "bytes": len(body)})

    def send_json(self, status, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(payload)

def main():
    print(f"[*] Starting Multi-Threaded Zero-Filter Dump Server on 0.0.0.0:{PORT}...")
    print(f"[*] Output directory: {DUMP_DIR}")
    server = ThreadingHTTPServer(('0.0.0.0', PORT), MultiThreadedCatchAllHandler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
