"""
Minerva MCP Client — real JSON-RPC 2.0 client for the Model Context Protocol.

Every pentesting attack imports this instead of hand-rolling raw HTTP. It
speaks the full MCP handshake (initialize → initialized → tools/list → ...)
across four transports (HTTP, SSE, WebSocket, stdio) and applies the user's
Target.auth_config automatically so attack scripts never see credentials.

Design goals
------------
- One line to spin up:  mcp = mcp_client.from_target(target)
- Works against simple (public HTTP), complex (SSE streaming), and
  enterprise (mTLS + OAuth, behind auth, stdio local) MCP deployments.
- Every call returns a structured dict so evidence collection is uniform:
    { "ok": bool, "result": ..., "error": ..., "request": {...},
      "response": {...}, "latency_ms": int, "transport": "http|sse|ws|stdio",
      "status": int|None }
- Fails gracefully. Never raises into attack scripts — they must be able
  to collect evidence of failures too.
"""

from __future__ import annotations

import base64
import itertools
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import uuid
from queue import Queue, Empty
from urllib.parse import urlparse, urlunparse

import requests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_JSONRPC_VERSION = "2.0"
_MCP_PROTOCOL_VERSION = "2024-11-05"
_DEFAULT_CLIENT_INFO = {"name": "minerva-pentest", "version": "1.0.0"}
_DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "User-Agent": "Minerva-MCP-Pentest/1.0",
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _gen_id() -> str:
    return uuid.uuid4().hex[:16]


def _safe_json(data: bytes | str):
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        return json.loads(data)
    except Exception:
        return {"_raw": (data if isinstance(data, str) else str(data))[:4000]}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def apply_auth(headers: dict, auth_config: dict | None) -> dict:
    """Mutate/return a headers dict with Target.auth_config applied.

    Supported auth_config shapes:
      {"type": "none"}
      {"type": "bearer", "token": "..."}
      {"type": "api_key", "header": "X-API-Key", "value": "..."}
      {"type": "basic", "username": "...", "password": "..."}
      {"type": "oauth2", "token": "..."}             # same as bearer
      {"type": "custom", "headers": {"k": "v", ...}}
    """
    h = dict(headers or {})
    if not auth_config:
        return h
    if isinstance(auth_config, str):
        try:
            auth_config = json.loads(auth_config) if auth_config.strip() else {}
        except Exception:
            return h
    if not isinstance(auth_config, dict):
        return h
    atype = str(auth_config.get("type", "none")).lower()
    if atype in ("none", ""):
        return h
    if atype in ("bearer", "oauth2", "jwt"):
        tok = auth_config.get("token") or auth_config.get("value") or ""
        if tok:
            h["Authorization"] = f"Bearer {tok}"
    elif atype in ("api_key", "apikey"):
        name = auth_config.get("header") or "X-API-Key"
        val = auth_config.get("value") or auth_config.get("token") or ""
        if val:
            h[name] = val
    elif atype == "basic":
        u = auth_config.get("username", "")
        p = auth_config.get("password", "")
        enc = base64.b64encode(f"{u}:{p}".encode()).decode()
        h["Authorization"] = f"Basic {enc}"
    elif atype == "custom":
        for k, v in (auth_config.get("headers") or {}).items():
            h[str(k)] = str(v)
    return h


# ---------------------------------------------------------------------------
# Transport base + implementations
# ---------------------------------------------------------------------------

class Transport:
    """Abstract transport. Subclasses implement ``_send`` returning
    (status, body_str, headers_dict). ``send`` wraps it with timing and
    JSON-RPC envelope handling."""

    name = "base"

    def __init__(self, base_url: str, *, auth_config: dict | None = None,
                 timeout: int = 30, verify_tls: bool = True,
                 extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.auth_config = auth_config or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.extra_headers = extra_headers or {}
        self._id_counter = itertools.count(1)

    # Lifecycle --------------------------------------------------------------
    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    # JSON-RPC envelope ------------------------------------------------------
    def _build_request(self, method: str, params: dict | None = None,
                       notification: bool = False) -> dict:
        req = {"jsonrpc": _JSONRPC_VERSION, "method": method}
        if params is not None:
            req["params"] = params
        if not notification:
            req["id"] = next(self._id_counter)
        return req

    def _headers(self) -> dict:
        h = dict(_DEFAULT_HEADERS)
        h.update(self.extra_headers)
        return apply_auth(h, self.auth_config)

    # Core -------------------------------------------------------------------
    def send(self, method: str, params: dict | None = None,
             *, notification: bool = False) -> dict:
        """Send a JSON-RPC request. Always returns a structured dict.

        Network throttle / stealth: before issuing the underlying request
        we honour the per-thread ``runtime.NetworkConfig`` so a pentester
        can pick stealth/balanced/aggressive (or custom delay+jitter+rps)
        without each attack script having to know.
        """
        from app.services import runtime as _rt
        req = self._build_request(method, params, notification=notification)
        start = _now_ms()
        gate = _rt.gate_send()
        try:
            try:
                status, body, resp_headers = self._send(req)
            except Exception as e:
                return {
                    "ok": False,
                    "transport": self.name,
                    "request": req,
                    "response": None,
                    "status": None,
                    "latency_ms": _now_ms() - start,
                    "error": {"type": type(e).__name__, "message": str(e)[:500]},
                    "result": None,
                }
            latency = _now_ms() - start
            parsed = _safe_json(body) if body else {}
            if notification:
                return {
                    "ok": status < 400 if status is not None else True,
                    "transport": self.name,
                    "request": req,
                    "response": parsed,
                    "status": status,
                    "latency_ms": latency,
                    "headers": resp_headers or {},
                    "result": None,
                    "error": None,
                }
            # Standard JSON-RPC response
            result = parsed.get("result") if isinstance(parsed, dict) else None
            rpc_error = parsed.get("error") if isinstance(parsed, dict) else None
            ok = (status is None or status < 400) and rpc_error is None
            return {
                "ok": ok,
                "transport": self.name,
                "request": req,
                "response": parsed,
                "status": status,
                "latency_ms": latency,
                "headers": resp_headers or {},
                "result": result,
                "error": rpc_error,
            }
        finally:
            _rt.release_send(gate)

    # Subclasses override this -----------------------------------------------
    def _send(self, req_obj: dict):
        raise NotImplementedError


class HTTPTransport(Transport):
    """Plain HTTP(S) POST. Works for most public/enterprise MCP servers."""

    name = "http"

    def __init__(self, base_url: str, path: str = "/mcp", **kw):
        super().__init__(base_url, **kw)
        self.path = path if path.startswith("/") else "/" + path
        self._session = requests.Session()

    # Production-grade reliability: retry transient errors with
    # exponential backoff. Respects Retry-After on 429 / 503.
    _MAX_RETRIES = 3
    _RETRY_STATUSES = (429, 500, 502, 503, 504)

    def _do_post(self, url, req_obj, *, verify, timeout):
        return self._session.post(
            url, json=req_obj, headers=self._headers(),
            timeout=timeout, verify=verify, allow_redirects=False,
        )

    def _send(self, req_obj: dict):
        url = self.base_url + self.path
        backoff = 0.5
        last_exc = None
        for attempt in range(self._MAX_RETRIES + 1):
            try:
                resp = self._do_post(url, req_obj,
                                     verify=self.verify_tls,
                                     timeout=self.timeout)
            except requests.exceptions.SSLError:
                # Wrong scheme: retry on http once
                if url.startswith("https://"):
                    http_url = "http://" + url[len("https://"):]
                    resp = self._do_post(http_url, req_obj,
                                         verify=False, timeout=self.timeout)
                    self.base_url = self.base_url.replace(
                        "https://", "http://", 1)
                    url = http_url
                else:
                    raise
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError) as e:
                last_exc = e
                if attempt >= self._MAX_RETRIES:
                    raise
                time.sleep(backoff); backoff *= 2
                continue

            # Rate-limit / transient 5xx → honour Retry-After, backoff + retry
            if (resp.status_code in self._RETRY_STATUSES
                    and attempt < self._MAX_RETRIES):
                retry_after = 0
                try:
                    retry_after = float(resp.headers.get("Retry-After") or 0)
                except Exception:
                    pass
                sleep_for = retry_after if retry_after > 0 else backoff
                time.sleep(min(sleep_for, 10))  # cap so attacks don't stall
                backoff *= 2
                continue

            return resp.status_code, resp.text, dict(resp.headers)
        # fallthrough — shouldn't happen unless retries exhausted on errors
        if last_exc:
            raise last_exc

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass


class SSETransport(Transport):
    """Server-Sent Events transport. POST request, parse `data: ...` stream."""

    name = "sse"

    def __init__(self, base_url: str, path: str = "/sse", **kw):
        super().__init__(base_url, **kw)
        self.path = path if path.startswith("/") else "/" + path
        self._session = requests.Session()

    def _send(self, req_obj: dict):
        url = self.base_url + self.path
        headers = self._headers()
        headers["Accept"] = "text/event-stream"
        resp = self._session.post(
            url,
            json=req_obj,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_tls,
            stream=True,
            allow_redirects=False,
        )
        if resp.status_code >= 400:
            return resp.status_code, resp.text, dict(resp.headers)

        deadline = time.time() + self.timeout
        payload_parts = []
        for line in resp.iter_lines(decode_unicode=True):
            if time.time() > deadline:
                break
            if line is None:
                continue
            if line.startswith("data:"):
                payload_parts.append(line[5:].strip())
            # blank line = end of event
            if line == "" and payload_parts:
                break
        try:
            resp.close()
        except Exception:
            pass
        body = "\n".join(payload_parts) or "{}"
        return resp.status_code, body, dict(resp.headers)


class WebSocketTransport(Transport):
    """Minimal WebSocket JSON-RPC transport. Avoids pulling the full
    `websockets` dep — speaks raw framed text over a socket. For
    pentesting this is enough; production should use `websockets`.
    """

    name = "ws"

    def __init__(self, base_url: str, path: str = "/mcp", **kw):
        super().__init__(base_url, **kw)
        self.path = path if path.startswith("/") else "/" + path
        self._sock: socket.socket | None = None

    # --- RFC6455 lite ------------------------------------------------------
    def _handshake(self):
        u = urlparse(self.base_url + self.path)
        host = u.hostname
        port = u.port or (443 if u.scheme in ("wss", "https") else 80)
        use_tls = u.scheme in ("wss", "https")
        key = base64.b64encode(os.urandom(16)).decode()
        s = socket.create_connection((host, port), timeout=self.timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        path_q = u.path or "/"
        if u.query:
            path_q += "?" + u.query
        req = [
            f"GET {path_q} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in self._headers().items():
            if k.lower() in ("content-type", "accept", "user-agent") or k.lower() == "authorization":
                req.append(f"{k}: {v}")
        s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
        resp = b""
        s.settimeout(self.timeout)
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 16384:
                break
        if b" 101 " not in resp.split(b"\r\n", 1)[0]:
            s.close()
            raise ConnectionError(f"WebSocket upgrade failed: {resp[:200]!r}")
        self._sock = s

    def _frame(self, payload: bytes) -> bytes:
        # text frame, FIN=1, opcode=1, client mask required
        header = bytes([0x81])
        mask_key = os.urandom(4)
        plen = len(payload)
        if plen < 126:
            header += bytes([0x80 | plen])
        elif plen < 65536:
            header += bytes([0x80 | 126]) + plen.to_bytes(2, "big")
        else:
            header += bytes([0x80 | 127]) + plen.to_bytes(8, "big")
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return header + mask_key + masked

    def _recv_text(self) -> str:
        s = self._sock
        if s is None:
            raise ConnectionError("socket closed")
        first = s.recv(2)
        if len(first) < 2:
            raise ConnectionError("short read")
        b0, b1 = first[0], first[1]
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = int.from_bytes(s.recv(2), "big")
        elif length == 127:
            length = int.from_bytes(s.recv(8), "big")
        # server→client frames have no mask
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        if opcode == 0x8:
            raise ConnectionError("websocket close frame")
        return data.decode("utf-8", errors="replace")

    def open(self) -> None:
        if self._sock is None:
            self._handshake()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _send(self, req_obj: dict):
        self.open()
        payload = json.dumps(req_obj).encode("utf-8")
        self._sock.sendall(self._frame(payload))
        # Wait for response with matching id
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                text = self._recv_text()
            except Exception as e:
                return None, "", {"_error": str(e)}
            obj = _safe_json(text)
            if isinstance(obj, dict) and ("result" in obj or "error" in obj) \
                    and obj.get("id") == req_obj.get("id"):
                return 200, text, {}
        return None, "", {"_error": "ws recv timeout"}


class StdioTransport(Transport):
    """Spawn a subprocess and speak JSON-RPC over stdin/stdout (MCP's
    original transport). The caller provides the command to run via
    ``base_url = "stdio:command args"`` or via the ``command`` kwarg.
    """

    name = "stdio"

    def __init__(self, base_url: str, command: list | str | None = None,
                 cwd: str | None = None, env: dict | None = None, **kw):
        super().__init__(base_url, **kw)
        if command is None and base_url.startswith("stdio:"):
            command = base_url[len("stdio:"):].strip()
        if isinstance(command, str):
            import shlex
            command = shlex.split(command, posix=(os.name != "nt"))
        if not command:
            raise ValueError("StdioTransport requires a command to spawn")
        # Windows quirk: `npx`, `yarn`, etc. are .cmd batch wrappers.
        # subprocess.Popen can't find them without the extension unless
        # we resolve via shutil.which(). This makes stdio transports
        # work uniformly across OSes.
        import shutil as _shutil
        resolved = _shutil.which(command[0])
        if resolved:
            command = [resolved] + list(command[1:])
        self.command = command
        self.cwd = cwd
        self.env = {**os.environ, **(env or {})}
        self._proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._queue: Queue = Queue()
        self._stderr: list[str] = []

    def open(self) -> None:
        if self._proc and self._proc.poll() is None:
            return
        # Force UTF-8 on stdin/stdout so stdio MCP servers work on Windows
        # (cp1252 default would crash on non-ASCII bytes in node/rust output).
        _env = dict(self.env)
        _env.setdefault("PYTHONIOENCODING", "utf-8")
        _env.setdefault("LANG", "en_US.UTF-8")
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=_env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._reader_thread = threading.Thread(
            target=self._reader, daemon=True
        )
        self._reader_thread.start()
        threading.Thread(target=self._stderr_reader, daemon=True).start()

    def _reader(self):
        assert self._proc is not None
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            self._queue.put(line)

    def _stderr_reader(self):
        assert self._proc is not None
        for line in self._proc.stderr:
            self._stderr.append(line.rstrip())

    def close(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def _send(self, req_obj: dict):
        self.open()
        assert self._proc is not None and self._proc.stdin is not None
        payload = json.dumps(req_obj) + "\n"
        self._proc.stdin.write(payload)
        self._proc.stdin.flush()
        deadline = time.time() + self.timeout
        target_id = req_obj.get("id")
        while time.time() < deadline:
            try:
                line = self._queue.get(timeout=min(1.0, deadline - time.time()))
            except Empty:
                continue
            obj = _safe_json(line)
            if isinstance(obj, dict) and obj.get("id") == target_id:
                return 200, line, {"_stderr": "\n".join(self._stderr[-10:])}
        return None, "", {"_error": "stdio recv timeout",
                          "_stderr": "\n".join(self._stderr[-20:])}


# ---------------------------------------------------------------------------
# High-level MCP client
# ---------------------------------------------------------------------------

class MCPClient:
    """Convenience wrapper around a Transport that speaks the full MCP
    handshake and exposes helpers for every spec method attacks care about.

    Usage::

        mcp = MCPClient.from_target({
            "host": "api.example.com",
            "port": 443,
            "protocol": "https",
            "base_url": "https://api.example.com",
            "auth_config": {"type": "bearer", "token": "..."}
        })
        mcp.initialize()
        tools = mcp.tools_list()
        call = mcp.tools_call("some_tool", {"arg": "value"})
    """

    def __init__(self, transport: Transport):
        self.transport = transport
        self._initialized = False
        self.server_info: dict | None = None
        self.capabilities: dict = {}
        self.protocol_version: str | None = None
        self._last_error: str | None = None
        # Optional negotiated default — set by from_target() when caller
        # passed protocol_version=...
        self._preferred_protocol_version: str | None = None

    # Construction -----------------------------------------------------------
    @classmethod
    def from_target(cls, target: dict, *, auth_config: dict | None = None,
                    timeout: int = 30, force_transport: str | None = None,
                    verify_tls: bool | None = None,
                    protocol_version: str | None = None,
                    extra_headers: dict | None = None) -> "MCPClient":
        """Build a client from a Target dict. Auto-detects transport
        unless ``force_transport`` is given.

        ``target`` may contain::

            {"host", "port", "protocol", "base_url", "transport",
             "path", "command", "auth_config", "verify_tls",
             "protocol_version", "extra_headers"}

        ``protocol_version`` overrides the default for ``initialize()``.
        Pass an empty string to keep auto (server picks).
        """
        target = target or {}
        auth = auth_config or target.get("auth_config") or {}
        # Accept auth_config as a JSON string too (DB TEXT columns often
        # hand us that shape). Normalise to dict.
        if isinstance(auth, str):
            try:
                auth = json.loads(auth) if auth.strip() else {}
            except Exception:
                auth = {}
        if not isinstance(auth, dict):
            auth = {}
        verify = target.get("verify_tls") if verify_tls is None else verify_tls
        if verify is None:
            verify = True

        protocol = (target.get("protocol") or "").lower()
        transport_hint = (force_transport or target.get("transport") or "").lower()
        base_url = (target.get("base_url") or "").strip()
        if not base_url:
            host = target.get("host", "localhost")
            port = target.get("port", 8080)
            proto_for_url = protocol or "http"
            if proto_for_url in ("ws", "wss"):
                proto_for_url = "https" if proto_for_url == "wss" else "http"
            base_url = f"{proto_for_url}://{host}:{port}"

        # Normalise: if user baked /mcp or /sse into the base_url, split
        # it out so the HTTPTransport path isn't double-prefixed.
        path = target.get("path") or "/mcp"
        if not base_url.startswith("stdio:"):
            from urllib.parse import urlparse as _up
            u = _up(base_url)
            if u.path and u.path not in ("", "/"):
                # Move the path portion out of base_url into `path`
                if not target.get("path"):
                    path = u.path
                base_url = f"{u.scheme}://{u.netloc}"
        base_url = base_url.rstrip("/")

        # Resolve extra headers — caller > target hint > none
        eh = dict(target.get("extra_headers") or {})
        if extra_headers:
            eh.update(extra_headers)

        # Pick transport
        if transport_hint == "stdio" or protocol == "stdio" or base_url.startswith("stdio:"):
            t = StdioTransport(base_url, command=target.get("command"),
                               auth_config=auth, timeout=timeout,
                               verify_tls=verify, extra_headers=eh)
        elif transport_hint in ("ws", "wss") or protocol in ("ws", "wss") \
                or base_url.startswith(("ws://", "wss://")):
            # Normalise to http(s) base so WebSocketTransport can parse it
            u = urlparse(base_url)
            scheme = "https" if u.scheme in ("wss", "https") else "http"
            norm = urlunparse((scheme, u.netloc, u.path, u.params, u.query, u.fragment))
            t = WebSocketTransport(norm, path=path, auth_config=auth,
                                   timeout=timeout, verify_tls=verify,
                                   extra_headers=eh)
        elif transport_hint == "sse" or path.endswith("/sse"):
            t = SSETransport(base_url, path=path, auth_config=auth,
                             timeout=timeout, verify_tls=verify,
                             extra_headers=eh)
        else:
            t = HTTPTransport(base_url, path=path, auth_config=auth,
                              timeout=timeout, verify_tls=verify,
                              extra_headers=eh)

        # Resolve negotiated protocol version: caller > target > module default
        pv = (protocol_version
              if protocol_version is not None
              else target.get("protocol_version"))
        client = cls(t)
        if pv:
            client._preferred_protocol_version = pv
        return client

    # Lifecycle --------------------------------------------------------------
    def close(self) -> None:
        try:
            self.transport.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # MCP methods ------------------------------------------------------------
    def initialize(self, client_info: dict | None = None,
                   capabilities: dict | None = None,
                   protocol_version: str | None = None) -> dict:
        info = client_info or _DEFAULT_CLIENT_INFO
        caps = capabilities or {
            "roots": {"listChanged": True},
            "sampling": {},
        }
        pv = (protocol_version
              or self._preferred_protocol_version
              or _MCP_PROTOCOL_VERSION)
        resp = self.transport.send("initialize", {
            "protocolVersion": pv,
            "capabilities": caps,
            "clientInfo": info,
        })
        if resp.get("ok") and isinstance(resp.get("result"), dict):
            r = resp["result"]
            self.server_info = r.get("serverInfo") or r.get("server_info")
            self.capabilities = r.get("capabilities") or {}
            self.protocol_version = r.get("protocolVersion") or pv
            self._initialized = True
            # Fire the "notifications/initialized" follow-up per spec.
            try:
                self.transport.send("notifications/initialized",
                                    notification=True)
            except Exception:
                pass
        else:
            self._last_error = str(resp.get("error") or resp.get("response"))
        return resp

    def ping(self) -> dict:
        return self.transport.send("ping")

    def tools_list(self, cursor: str | None = None) -> dict:
        params = {"cursor": cursor} if cursor else {}
        return self.transport.send("tools/list", params)

    def tools_call(self, name: str, arguments: dict | None = None,
                   *, meta: dict | None = None) -> dict:
        params: dict = {"name": name, "arguments": arguments or {}}
        if meta:
            params["_meta"] = meta
        return self.transport.send("tools/call", params)

    def resources_list(self, cursor: str | None = None) -> dict:
        params = {"cursor": cursor} if cursor else {}
        return self.transport.send("resources/list", params)

    def resources_read(self, uri: str) -> dict:
        return self.transport.send("resources/read", {"uri": uri})

    def resources_templates_list(self) -> dict:
        return self.transport.send("resources/templates/list")

    def prompts_list(self, cursor: str | None = None) -> dict:
        params = {"cursor": cursor} if cursor else {}
        return self.transport.send("prompts/list", params)

    def prompts_get(self, name: str, arguments: dict | None = None) -> dict:
        return self.transport.send("prompts/get",
                                   {"name": name, "arguments": arguments or {}})

    def logging_set_level(self, level: str) -> dict:
        return self.transport.send("logging/setLevel", {"level": level})

    def completion_complete(self, ref: dict, argument: dict) -> dict:
        return self.transport.send("completion/complete",
                                   {"ref": ref, "argument": argument})

    # High-level helpers -----------------------------------------------------
    def discover(self) -> dict:
        """One-shot discovery: initialize + tools + resources + prompts.
        Returns a rich dict used by many attacks as their first step."""
        out: dict = {
            "initialized": False,
            "transport": self.transport.name,
            "errors": [],
            "tools": [],
            "resources": [],
            "prompts": [],
            "server_info": None,
            "capabilities": {},
            "protocol_version": None,
            "raw": {"initialize": None, "tools_list": None,
                    "resources_list": None, "prompts_list": None},
        }
        init = self.initialize()
        out["raw"]["initialize"] = init
        if not init.get("ok"):
            out["errors"].append({"step": "initialize",
                                  "error": init.get("error"),
                                  "status": init.get("status"),
                                  "latency_ms": init.get("latency_ms")})
            return out
        out["initialized"] = True
        out["server_info"] = self.server_info
        out["capabilities"] = self.capabilities
        out["protocol_version"] = self.protocol_version

        tl = self.tools_list()
        out["raw"]["tools_list"] = tl
        if tl.get("ok") and isinstance(tl.get("result"), dict):
            out["tools"] = tl["result"].get("tools") or []
        else:
            out["errors"].append({"step": "tools/list", "error": tl.get("error")})

        rl = self.resources_list()
        out["raw"]["resources_list"] = rl
        if rl.get("ok") and isinstance(rl.get("result"), dict):
            out["resources"] = rl["result"].get("resources") or []
        # resources is optional per spec; silent on failure

        pl = self.prompts_list()
        out["raw"]["prompts_list"] = pl
        if pl.get("ok") and isinstance(pl.get("result"), dict):
            out["prompts"] = pl["result"].get("prompts") or []

        return out

    def call_tool_safe(self, tool_name: str, args: dict) -> dict:
        """Call a tool without raising. Returns {ok, result, error,
        text_output, request, response, latency_ms}."""
        resp = self.tools_call(tool_name, args)
        result = resp.get("result") or {}
        text = _flatten_tool_output(result) if isinstance(result, dict) else ""
        resp["text_output"] = text
        resp["is_error"] = bool(
            resp.get("error")
            or (isinstance(result, dict) and result.get("isError"))
        )
        return resp

    def tool_schemas(self) -> dict[str, dict]:
        """Return {tool_name: inputSchema} after a tools/list call."""
        tl = self.tools_list()
        out = {}
        if tl.get("ok") and isinstance(tl.get("result"), dict):
            for t in tl["result"].get("tools", []) or []:
                name = t.get("name")
                if name:
                    out[name] = t.get("inputSchema") or {}
        return out


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _flatten_tool_output(result: dict) -> str:
    """MCP tools/call returns {content: [{type, text, ...}, ...]}.
    Squash content into a single string for pattern matching."""
    parts: list[str] = []
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                parts.append(str(item))
                continue
            t = item.get("type")
            if t == "text":
                parts.append(str(item.get("text", "")))
            elif t == "image":
                parts.append(f"[image:{item.get('mimeType','?')}]")
            elif t == "resource":
                parts.append(str(item.get("resource") or item))
            else:
                parts.append(json.dumps(item)[:1000])
    elif isinstance(content, str):
        parts.append(content)
    else:
        parts.append(json.dumps(result)[:2000])
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Auto-detect transport when nothing is specified
# ---------------------------------------------------------------------------

def auto_detect_transport(target: dict, *, timeout: int = 5) -> str:
    """Probe common paths to guess transport. Returns one of
    ``http|sse|ws|stdio``. Cheap heuristic, not authoritative."""
    if target.get("transport"):
        return str(target["transport"]).lower()
    protocol = (target.get("protocol") or "").lower()
    if protocol == "stdio" or str(target.get("base_url", "")).startswith("stdio:"):
        return "stdio"
    if protocol in ("ws", "wss"):
        return "ws"
    # Try HEAD against /sse and /mcp
    base = target.get("base_url")
    if not base:
        host = target.get("host", "localhost")
        port = target.get("port", 8080)
        scheme = protocol or "http"
        base = f"{scheme}://{host}:{port}"
    for path, name in [("/sse", "sse"), ("/mcp", "http")]:
        try:
            r = requests.head(base.rstrip("/") + path, timeout=timeout,
                              allow_redirects=False)
            ct = (r.headers.get("content-type") or "").lower()
            if r.status_code < 500:
                if "event-stream" in ct:
                    return "sse"
                if name == "sse" and r.status_code not in (404, 405):
                    return "sse"
                if name == "http" and r.status_code not in (404, 405):
                    return "http"
        except Exception:
            continue
    return "http"


# ---------------------------------------------------------------------------
# Protocol-version negotiation
# ---------------------------------------------------------------------------

# Known MCP protocol versions, newest first. The downgrade-attack script
# walks this list to find which the server accepts.
KNOWN_PROTOCOL_VERSIONS = (
    "2025-06-18",   # OAuth 2.1 mandate, elicitation/create, structured tool output
    "2025-03-26",   # streamable HTTP, audio content, completions, tool annotations
    "2024-11-05",   # initial public spec
    "2024-10-07",   # pre-public draft (rare in the wild)
    "0.1.0",        # very early SDK builds
)


def negotiate_protocol_version(target: dict, *,
                               versions: list[str] | None = None,
                               timeout: int = 15,
                               force_transport: str | None = None,
                               extra_headers: dict | None = None
                               ) -> dict:
    """Try every version in ``versions`` (or KNOWN_PROTOCOL_VERSIONS) and
    record which the server accepts.

    Returns::

        {"accepted": [...], "rejected": [{version, status, error}], "raw": [...]}

    The caller (e.g. protocol_version_downgrade attack) inspects this to
    decide whether old/insecure protocol versions are still honoured.
    """
    versions = versions or list(KNOWN_PROTOCOL_VERSIONS)
    accepted: list[str] = []
    rejected: list[dict] = []
    raw: list[dict] = []
    for v in versions:
        try:
            mcp = MCPClient.from_target(
                target, timeout=timeout,
                force_transport=force_transport,
                protocol_version=v,
                extra_headers=extra_headers,
            )
        except Exception as e:
            rejected.append({"version": v, "status": None,
                             "error": f"client construction failed: {e!s:.200}"})
            continue
        try:
            r = mcp.initialize(protocol_version=v)
            raw.append({"version": v, "response": r})
            if r.get("ok") and isinstance(r.get("result"), dict):
                # Record what the server actually returned — may differ
                returned = (r["result"] or {}).get("protocolVersion") or v
                accepted.append(returned)
            else:
                rejected.append({"version": v,
                                 "status": r.get("status"),
                                 "error": str(r.get("error"))[:300]})
        finally:
            try:
                mcp.close()
            except Exception:
                pass
    return {"accepted": accepted, "rejected": rejected, "raw": raw}


def call(target: dict, method: str, params: dict | None = None,
         *, timeout: float = 30.0,
         protocol_version: str | None = None,
         force_transport: str | None = None,
         notification: bool = False) -> dict:
    """One-shot JSON-RPC call to an MCP target.

    Convenience wrapper around `MCPClient.from_target(...).send(...)`
    for attack scripts that don't need to keep an MCP session open.
    Always returns a structured response dict (status / request /
    response / latency_ms / error / transport / headers); never raises
    network errors into the caller.

    The attack_runner replaces this with an engagement-aware shim
    that enforces dry-run / kill-switch / quota when a script is
    executing inside a run.
    """
    try:
        client = MCPClient.from_target(
            target, timeout=timeout,
            protocol_version=protocol_version,
            force_transport=force_transport,
        )
    except Exception as e:
        return {
            "transport": (target.get("protocol") if isinstance(target, dict) else None) or "?",
            "request": {"method": method, "params": params or {}},
            "response": None,
            "status": None,
            "latency_ms": 0,
            "headers": {},
            "error": f"client_init_failed: {type(e).__name__}: {e}",
        }
    try:
        return client.send(method, params, notification=notification)
    except Exception as e:
        return {
            "transport": getattr(client, "transport_name", "?"),
            "request": {"method": method, "params": params or {}},
            "response": None,
            "status": None,
            "latency_ms": 0,
            "headers": {},
            "error": f"send_failed: {type(e).__name__}: {e}",
        }
    finally:
        try:
            client.close()
        except Exception:
            pass


# Public surface
__all__ = [
    "MCPClient",
    "HTTPTransport", "SSETransport", "WebSocketTransport", "StdioTransport",
    "apply_auth", "auto_detect_transport", "call",
    "KNOWN_PROTOCOL_VERSIONS", "negotiate_protocol_version",
]
