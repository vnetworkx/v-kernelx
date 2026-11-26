"""Minimal stdlib RFC 6455 WebSocket subscriber for Vector Network event streams."""

import base64
import json
import os
import socket
import struct
import threading
import urllib.parse
from typing import Any, Callable, Dict


def subscribe_events_thread(
    base_url: str, on_event: Callable[[Dict[str, Any]], None]
) -> threading.Thread:
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def _run() -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        sock = socket.create_connection((host, port), timeout=10)
        req = (
            f"GET /v1/ws HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(req.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                sock.close()
                return
            buf += chunk
        sock.settimeout(None)
        try:
            while True:
                hdr = sock.recv(2)
                if len(hdr) < 2:
                    break
                b1, b2 = hdr[0], hdr[1]
                opcode = b1 & 0x0F
                length = b2 & 0x7F
                if length == 126:
                    length = struct.unpack("!H", sock.recv(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", sock.recv(8))[0]
                payload = bytearray()
                while len(payload) < length:
                    chunk = sock.recv(length - len(payload))
                    if not chunk:
                        break
                    payload.extend(chunk)
                if opcode == 0x8:
                    break
                if opcode == 0x1:
                    try:
                        on_event(json.loads(payload.decode("utf-8")))
                    except Exception:
                        pass
        finally:
            sock.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t
