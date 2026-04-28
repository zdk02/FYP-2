"""
Active MCP MITM proxy.

Spawns a local HTTP proxy that forwards MCP JSON-RPC traffic to the
real upstream target and records every flow (request headers + body,
response status + headers + body). Attacks can optionally register
request/response tampering callbacks.

This is **not** a full mitmproxy — it's a purpose-built proxy with
zero external dependencies. It handles the common HTTP POST/GET shapes
MCP uses over HTTP and SSE. For stdio / ws targets it's N/A.

Usage:

    proxy = mitm_proxy.spawn(
        upstream_url="https://api.example.com/mcp",
        attack_id="mitm",
        ttl=120,
    )
    # Configure the victim client to use proxy.endpoint
    # ... time passes ...
    flows = mitm_proxy.flows(proxy.token)

Safety:
  - Only HTTP/1.1 (no TLS termination). For HTTPS targets we act as a
    forward proxy — clients set ``proxy.endpoint`` as the URL they call,
    we forward to the upstream. We don't MITM TLS.
  - Bodies capped at 64 KB per direction.
"""

from __future__ import annotations

import json
import os
import random
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen


_PORT_RANGE = (
    int(os.environ.get("MINERVA_MITM_PORT_MIN", "45000")),
    int(os.environ.get("MINERVA_MITM_PORT_MAX", "49000")),
)
_BODY_CAP = 64 * 1024


@dataclass
class ProxyHandle:
    token: str
    endpoint: str
    upstream_url: str
    host: str
    port: int
    created_at: float
    expires_at: float
    attack_id: str | None = None


_active_proxies: dict[str, "_ProxyState"] = {}
_active_lock = threading.Lock()


class _ProxyState:
    def __init__(self, handle: ProxyHandle, upstream: str):
        self.handle = handle
        self.upstream = upstream
        self.flows: list[dict] = []
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.request_tamper = None   # optional callable(req_dict) -> req_dict
        self.response_tamper = None  # optional callable(resp_dict) -> resp_dict


def _make_handler(state: _ProxyState):

    class Handler(BaseHTTPRequestHandler):
        server_version = "MinervaMITM/1.0"

        def log_message(self, *a, **kw):
            pass

        def _forward(self):
            length = int(self.headers.get("content-length") or 0)
            raw_body = self.rfile.read(length) if length > 0 else b""
            body_str = raw_body.decode("utf-8", errors="replace")
            req_record = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body_str[:_BODY_CAP],
            }
            # Parse JSON-RPC if present
            try:
                req_record["jsonrpc"] = json.loads(body_str)
            except Exception:
                pass

            if state.request_tamper:
                try:
                    req_record = state.request_tamper(req_record) or req_record
                    raw_body = (req_record.get("body") or "").encode()
                except Exception as e:
                    req_record["_tamper_error"] = str(e)

            # Forward
            u = urlparse(state.upstream)
            target_url = state.upstream
            if self.path and self.path != "/":
                target_url = (
                    f"{u.scheme}://{u.netloc}"
                    f"{u.path.rstrip('/')}{self.path}"
                )
            fwd_headers = {k: v for k, v in req_record["headers"].items()
                           if k.lower() not in ("host", "content-length")}
            fwd_headers.setdefault("User-Agent", "Minerva-MITM/1.0")
            req = Request(target_url, data=raw_body or None,
                          method=self.command, headers=fwd_headers)
            ctx = None
            if u.scheme == "https":
                ctx = ssl.create_default_context()
                if os.environ.get("MINERVA_MITM_INSECURE") == "1":
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
            t0 = time.time()
            status = 502
            resp_headers: dict = {}
            resp_body = b""
            try:
                with urlopen(req, timeout=30, context=ctx) as r:
                    status = r.status
                    resp_headers = dict(r.headers)
                    resp_body = r.read(_BODY_CAP)
            except Exception as e:
                status = 502
                resp_body = f"upstream error: {e}".encode()

            resp_record = {
                "status": status,
                "headers": resp_headers,
                "body": resp_body.decode("utf-8", errors="replace")[:_BODY_CAP],
                "latency_ms": int((time.time() - t0) * 1000),
            }
            try:
                resp_record["jsonrpc"] = json.loads(resp_record["body"])
            except Exception:
                pass

            if state.response_tamper:
                try:
                    resp_record = state.response_tamper(resp_record) \
                        or resp_record
                    resp_body = (resp_record.get("body") or "").encode()
                    status = resp_record.get("status", status)
                except Exception as e:
                    resp_record["_tamper_error"] = str(e)

            state.flows.append({"request": req_record, "response": resp_record})

            # Return to the victim
            self.send_response(status)
            for k, v in resp_record["headers"].items():
                if k.lower() in ("content-length", "transfer-encoding",
                                 "connection"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("X-Minerva-Mitm", "1")
            self.end_headers()
            self.wfile.write(resp_body)

        def do_GET(self):
            self._forward()

        def do_POST(self):
            self._forward()

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             "Content-Type, Authorization")
            self.end_headers()

    return Handler


def spawn(*, upstream_url: str, attack_id: str | None = None,
          ttl: int = 300,
          bind_host: str | None = None,
          advertise_host: str | None = None) -> ProxyHandle:
    bind = bind_host or os.environ.get("MINERVA_MITM_BIND", "0.0.0.0")
    # Resolve the advertise host: explicit arg → env override → loopback if
    # we're bound to 127.0.0.1 → host.docker.internal as last-resort for
    # docker-compose usage. Never silently use docker.internal on native
    # hosts where it doesn't resolve.
    if advertise_host:
        advertise = advertise_host
    elif os.environ.get("MINERVA_MITM_ADVERTISE"):
        advertise = os.environ["MINERVA_MITM_ADVERTISE"]
    elif os.environ.get("MINERVA_OOB_URL"):
        advertise = (os.environ["MINERVA_OOB_URL"]
                     .replace("http://", "").replace("https://", "")
                     .split(":")[0])
    elif bind in ("127.0.0.1", "localhost"):
        advertise = "127.0.0.1"
    else:
        # Bound to 0.0.0.0 with no override — try to discover a routable IP,
        # falling back to loopback so tests on a non-Docker host still work.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(("8.8.8.8", 80))
                advertise = probe.getsockname()[0]
        except Exception:
            advertise = "127.0.0.1"
    # find a free port
    chosen = None
    last_err = None
    for _ in range(40):
        p = random.randint(*_PORT_RANGE)
        s = socket.socket()
        try:
            s.bind((bind, p))
            s.close()
            chosen = p
            break
        except OSError as e:
            last_err = e
            s.close()
    if chosen is None:
        raise RuntimeError(f"No free MITM port: {last_err}")

    token = uuid.uuid4().hex
    now = time.time()
    handle = ProxyHandle(
        token=token,
        endpoint=f"http://{advertise}:{chosen}",
        upstream_url=upstream_url,
        host=advertise, port=chosen,
        created_at=now, expires_at=now + max(10, ttl),
        attack_id=attack_id,
    )
    state = _ProxyState(handle, upstream_url)
    server = ThreadingHTTPServer((bind, chosen), _make_handler(state))
    state.server = server
    state.thread = threading.Thread(target=server.serve_forever, daemon=True)
    state.thread.start()

    with _active_lock:
        _active_proxies[token] = state

    # Persist
    try:
        from app import db
        from app.models import MITMProxySession
        db.session.add(MITMProxySession(
            token=token, attack_id=attack_id,
            proxy_host=advertise, proxy_port=chosen,
            upstream_url=upstream_url,
            created_at=datetime.utcfromtimestamp(now),
            expires_at=datetime.utcfromtimestamp(handle.expires_at),
            flow_count=0,
        ))
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass

    # Auto-terminate after TTL
    def _terminate():
        time.sleep(max(1, int(ttl)))
        release(token)
    threading.Thread(target=_terminate, daemon=True).start()

    return handle


def flows(token: str) -> list[dict]:
    with _active_lock:
        state = _active_proxies.get(token)
    if not state:
        return []
    return list(state.flows)


def release(token: str) -> None:
    with _active_lock:
        state = _active_proxies.pop(token, None)
    if not state:
        return
    try:
        state.server.shutdown()
    except Exception:
        pass
    try:
        state.server.server_close()
    except Exception:
        pass
    # Persist final flow count
    try:
        from app import db
        from app.models import MITMProxySession
        row = MITMProxySession.query.get(token)
        if row:
            row.flow_count = len(state.flows)
            db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def register_tamper(token: str, *,
                    on_request=None, on_response=None) -> bool:
    """Attach tamper callbacks to an active proxy. Each callback is
    called with the request/response dict and may return a modified
    copy.
    """
    with _active_lock:
        state = _active_proxies.get(token)
    if not state:
        return False
    if on_request:
        state.request_tamper = on_request
    if on_response:
        state.response_tamper = on_response
    return True


__all__ = ["ProxyHandle", "spawn", "flows", "release", "register_tamper"]
