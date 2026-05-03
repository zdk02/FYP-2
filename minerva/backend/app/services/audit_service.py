"""
Tamper-evident audit log service.

Each entry's `entry_hash` is sha256 over (sequence | timestamp | user_id |
engagement_id | action | resource_type | resource_id | details |
prev_hash). Walking the chain back to the genesis seed reveals any
break — overwriting an entry, deleting one in the middle, or inserting
a forged record will all fail `verify_chain()`.

Required for SOC 2 / ISO 27001 review of operating procedures.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json as _json
from typing import Any, Optional

from flask import has_app_context

from app import db
from app.models import AuditLog


GENESIS_SEED = "minerva-audit-genesis-v1"


def _canonical(payload: dict) -> str:
    return _json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       default=str)


def _hash_entry(seq: int, created_at: _dt.datetime,
                user_id: str | None, engagement_id: str | None,
                action: str, resource_type: str | None,
                resource_id: str | None, details: str | None,
                prev_hash: str) -> str:
    payload = {
        "seq": int(seq or 0),
        "ts": created_at.isoformat() if created_at else "",
        "user_id": user_id or "",
        "engagement_id": engagement_id or "",
        "action": action or "",
        "resource_type": resource_type or "",
        "resource_id": resource_id or "",
        "details": details or "",
        "prev_hash": prev_hash or "",
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _genesis_hash() -> str:
    return hashlib.sha256(GENESIS_SEED.encode("utf-8")).hexdigest()


def _get_last_entry() -> AuditLog | None:
    return (AuditLog.query
            .order_by(AuditLog.sequence.desc().nullslast(),
                      AuditLog.created_at.desc())
            .first())


def append(*, action: str,
           user_id: str | None = None,
           engagement_id: str | None = None,
           resource_type: str | None = None,
           resource_id: str | None = None,
           details: dict | str | None = None,
           ip_address: str | None = None,
           user_agent: str | None = None) -> AuditLog | None:
    """Append a new audit entry, hash-chained.

    Best-effort — never raises into caller. Returns the row on success,
    None on failure.
    """
    if not has_app_context():
        return None
    try:
        if isinstance(details, dict):
            details_str = _json.dumps(details, default=str, sort_keys=True)
        elif details is None:
            details_str = None
        else:
            details_str = str(details)

        last = _get_last_entry()
        if last is None:
            prev_hash = _genesis_hash()
            seq = 1
        else:
            prev_hash = last.entry_hash or _genesis_hash()
            seq = (last.sequence or 0) + 1

        now = _dt.datetime.utcnow()
        entry_hash = _hash_entry(
            seq, now, user_id, engagement_id, action,
            resource_type, resource_id, details_str, prev_hash,
        )

        log = AuditLog(
            user_id=user_id,
            engagement_id=engagement_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details_str,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            sequence=seq,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        db.session.add(log)
        db.session.commit()
        return log
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def verify_chain(limit: int | None = None) -> dict:
    """Walk the chain end-to-end. Returns:
        {
          'ok': bool,
          'verified': N,
          'breaks': [{'sequence': k, 'reason': ...}, ...],
          'first_break_at': k|None,
        }
    """
    q = AuditLog.query.order_by(AuditLog.sequence.asc().nullsfirst(),
                                AuditLog.created_at.asc())
    if limit:
        q = q.limit(limit)
    entries = q.all()

    breaks = []
    verified = 0
    expected_prev = _genesis_hash()
    expected_seq = 1
    for e in entries:
        # Sequence continuity
        if e.sequence is None:
            # Legacy rows pre-chain — note but don't fail
            continue

        # prev_hash linkage
        if (e.prev_hash or "") != expected_prev:
            breaks.append({
                "sequence": e.sequence,
                "reason": "prev_hash mismatch",
                "expected": expected_prev,
                "actual": e.prev_hash,
            })

        # entry_hash recompute
        recomputed = _hash_entry(
            e.sequence, e.created_at, e.user_id, e.engagement_id,
            e.action, e.resource_type, e.resource_id, e.details,
            e.prev_hash or "",
        )
        if recomputed != (e.entry_hash or ""):
            breaks.append({
                "sequence": e.sequence,
                "reason": "entry_hash mismatch",
                "recomputed": recomputed,
                "stored": e.entry_hash,
            })

        # Sequence gap check
        if e.sequence != expected_seq:
            breaks.append({
                "sequence": e.sequence,
                "reason": f"sequence gap (expected {expected_seq})",
            })

        expected_prev = e.entry_hash or expected_prev
        expected_seq = e.sequence + 1
        verified += 1

    return {
        "ok": len(breaks) == 0,
        "verified": verified,
        "breaks": breaks[:50],
        "first_break_at": breaks[0]["sequence"] if breaks else None,
    }


__all__ = ["append", "verify_chain"]
