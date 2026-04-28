"""
Persistent Out-of-Band (OOB) callback service.

Public API is stable:
    token = oob.mint(attack_id="...", ttl=300, metadata={...})
    # attacker payload -> target hits token.url
    hits = oob.wait(token.token, timeout=20)

Storage: SQLAlchemy-backed (``oob_tokens`` + ``oob_hits`` tables). Tokens
survive a Flask restart and can be inspected from the admin UI. An
in-process ``threading.Event`` gives low-latency wake-up during the
normal case; when the signal is missed (e.g. another worker handled the
callback), ``wait`` falls back to polling the DB once per second.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta


_events_guard = threading.Lock()
_events: dict[str, threading.Event] = {}


def _event_for(token: str) -> threading.Event:
    with _events_guard:
        ev = _events.get(token)
        if ev is None:
            ev = threading.Event()
            _events[token] = ev
        return ev


def _base_url() -> str:
    return (os.environ.get("MINERVA_OOB_URL")
            or "http://host.docker.internal:5000")


# ---------------------------------------------------------------------------
# Public dataclass (attack-script visible)
# ---------------------------------------------------------------------------

@dataclass
class CallbackToken:
    token: str
    url: str
    dns_label: str
    created_at: float
    expires_at: float
    attack_id: str | None = None
    metadata: dict | None = None
    # hits is computed on access — kept here for back-compat
    hits: list[dict] | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_token(row) -> CallbackToken:
    try:
        meta = json.loads(row.metadata_json) if row.metadata_json else {}
    except Exception:
        meta = {}
    url = f"{_base_url().rstrip('/')}/api/v1/callbacks/oob/{row.token}"
    return CallbackToken(
        token=row.token,
        url=url,
        dns_label=row.token[:12],
        created_at=row.created_at.timestamp() if row.created_at else time.time(),
        expires_at=row.expires_at.timestamp() if row.expires_at else time.time(),
        attack_id=row.attack_id,
        metadata=meta,
    )


def _hit_to_dict(h) -> dict:
    try:
        headers = json.loads(h.headers_json) if h.headers_json else {}
    except Exception:
        headers = {}
    try:
        query = json.loads(h.query_json) if h.query_json else {}
    except Exception:
        query = {}
    return {
        "id": h.id,
        "timestamp": h.timestamp.timestamp() if h.timestamp else None,
        "iso": h.timestamp.isoformat() + "Z" if h.timestamp else None,
        "source_ip": h.source_ip,
        "method": h.method,
        "path": h.path,
        "headers": headers,
        "query": query,
        "body": h.body or "",
    }


def _gc(session):
    """Drop tokens whose TTL has elapsed. Called best-effort."""
    from app.models import OOBToken
    try:
        now = datetime.utcnow()
        expired = OOBToken.query.filter(OOBToken.expires_at < now).all()
        for t in expired:
            session.delete(t)
            with _events_guard:
                _events.pop(t.token, None)
        if expired:
            session.commit()
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mint(attack_id: str | None = None, *, ttl: int = 300,
         metadata: dict | None = None) -> CallbackToken:
    from app import db
    from app.models import OOBToken

    _gc(db.session)
    token = uuid.uuid4().hex
    now = datetime.utcnow()
    row = OOBToken(
        token=token,
        attack_id=attack_id,
        metadata_json=json.dumps(metadata or {}),
        created_at=now,
        expires_at=now + timedelta(seconds=max(10, ttl)),
    )
    db.session.add(row)
    db.session.commit()
    _event_for(token)  # prime the signal
    return _row_to_token(row)


def record_hit(token: str, *, source_ip: str | None = None,
               method: str | None = None, path: str | None = None,
               headers: dict | None = None, query: dict | None = None,
               body: str | None = None) -> bool:
    from app import db
    from app.models import OOBToken, OOBHit

    row = OOBToken.query.get(token)
    if not row:
        return False
    hit = OOBHit(
        token_id=token,
        source_ip=source_ip,
        method=method,
        path=path,
        headers_json=json.dumps(headers or {})[:8000],
        query_json=json.dumps(query or {})[:4000],
        body=(body or "")[:8000],
    )
    db.session.add(hit)
    db.session.commit()
    ev = _event_for(token)
    ev.set()
    return True


def wait(token: str, *, timeout: float = 30.0) -> list[dict]:
    """Block until ≥1 hit exists for ``token`` or ``timeout`` elapses."""
    from app.models import OOBToken

    row = OOBToken.query.get(token)
    if not row:
        return []
    # Fast path: hits already recorded
    h = sorted(row.hits.all(), key=lambda x: x.timestamp or datetime.min)
    if h:
        return [_hit_to_dict(x) for x in h]

    deadline = time.time() + max(0.1, timeout)
    ev = _event_for(token)
    while time.time() < deadline:
        # Wait in 1-sec slices so a missed signal still recovers via poll
        ev.wait(timeout=min(1.0, deadline - time.time()))
        # Re-query — cheap because it's a primary-key lookup
        from app import db
        db.session.expire_all()
        row = OOBToken.query.get(token)
        if row and row.hits.count():
            break
    row = OOBToken.query.get(token)
    if not row:
        return []
    h = sorted(row.hits.all(), key=lambda x: x.timestamp or datetime.min)
    return [_hit_to_dict(x) for x in h]


def hits(token: str) -> list[dict]:
    from app.models import OOBToken
    row = OOBToken.query.get(token)
    if not row:
        return []
    h = sorted(row.hits.all(), key=lambda x: x.timestamp or datetime.min)
    return [_hit_to_dict(x) for x in h]


def release(token: str) -> None:
    from app import db
    from app.models import OOBToken
    row = OOBToken.query.get(token)
    if row:
        db.session.delete(row)
        db.session.commit()
    with _events_guard:
        _events.pop(token, None)


def all_tokens() -> list[CallbackToken]:
    from app import db
    from app.models import OOBToken
    _gc(db.session)
    rows = OOBToken.query.order_by(OOBToken.created_at.desc()).all()
    return [_row_to_token(r) for r in rows]


__all__ = [
    "CallbackToken",
    "mint", "record_hit", "wait", "hits", "release", "all_tokens",
]
