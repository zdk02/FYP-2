"""
Engagement scope enforcement + safety + quotas + kill switch.

Every attack run goes through `preflight_check` before any payload is
sent. If the target is out-of-scope, the time window is closed, the
budget is exhausted, the kill switch is engaged, or the engagement is
not active, the run is hard-rejected with a clear error.

This is the single chokepoint that turns Minerva from "technically
capable" into "legally usable in a pro context".
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json as _json
import re
from typing import Optional

from app import db
from app.models import Engagement


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class ScopeViolation(Exception):
    """Raised by preflight_check when a run must be rejected.

    The pre-flight gate is hard-fail. There is no override flag inside
    the code — out-of-scope means the engagement contract didn't cover
    this target, and an admin needs to update the engagement (which is
    itself audit-logged) before the run can proceed.
    """

    def __init__(self, reason: str, code: str = "out_of_scope"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


# ---------------------------------------------------------------------------
# Scope checks
# ---------------------------------------------------------------------------

def _normalise_host(host: str | None) -> str:
    if not host:
        return ""
    return host.strip().lower()


def _match_pattern(host: str, pattern: str) -> bool:
    """Match `host` against `pattern`. Pattern may be:

    - exact hostname (case-insensitive)
    - IPv4/IPv6 address
    - CIDR (192.168.0.0/16, 2001:db8::/32)
    - wildcard (*.example.com)
    - "any" / "*"
    """
    pattern = pattern.strip()
    if not pattern:
        return False
    if pattern.lower() in ("*", "any"):
        return True

    p_low = pattern.lower()

    # CIDR — try to interpret host as IP and match in network
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            try:
                return ipaddress.ip_address(host) in net
            except ValueError:
                # Host might be a hostname, not an IP — try resolving lazily
                import socket
                try:
                    resolved = socket.gethostbyname(host)
                    return ipaddress.ip_address(resolved) in net
                except Exception:
                    return False
        except ValueError:
            return False

    # Wildcard
    if "*" in pattern:
        regex = "^" + re.escape(p_low).replace(r"\*", ".*") + "$"
        return bool(re.match(regex, host))

    # Exact match (host or IP literal)
    if p_low == host:
        return True

    # IP exact
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(pattern)
    except ValueError:
        return False


def is_target_authorized(engagement: Engagement, target_host: str) -> bool:
    """Check the host against the engagement's authorized_targets list."""
    host = _normalise_host(target_host)
    if not host:
        return False
    try:
        allow = _json.loads(engagement.authorized_targets or "[]")
    except Exception:
        return False
    if not allow:
        return False
    for pattern in allow:
        try:
            if _match_pattern(host, str(pattern)):
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Pre-flight gate
# ---------------------------------------------------------------------------

def get_engagement(engagement_id: str | None) -> Engagement | None:
    if not engagement_id:
        return None
    return Engagement.query.get(engagement_id)


def get_active_engagement() -> Engagement | None:
    """The engagement marked is_active_default — used as fallback when
    a request omits engagement_id."""
    return (Engagement.query
            .filter_by(is_active_default=True, status='active')
            .first())


def preflight_check(*, engagement_id: str | None, target: dict,
                    requested_safe_mode: bool | None = None,
                    requested_dry_run: bool | None = None) -> dict:
    """Hard-fail any run that breaks the engagement contract.

    Returns a dict with normalised effective settings:
        {
          'engagement': Engagement,
          'safe_mode': bool,
          'dry_run': bool,
          'health_threshold_x': float,
          'remaining_requests': int,
        }

    Raises ScopeViolation on rejection.
    """
    eng = get_engagement(engagement_id) or get_active_engagement()
    if not eng:
        raise ScopeViolation(
            "No active Engagement. Create or activate an engagement before "
            "running attacks.", code="no_engagement")

    if eng.status not in ("active", "draft"):
        raise ScopeViolation(
            f"Engagement '{eng.name}' is {eng.status}; cannot run.",
            code="engagement_inactive")

    if eng.is_killed:
        raise ScopeViolation(
            f"Engagement '{eng.name}' has been killed via the global "
            "kill switch.", code="killed")

    # Time window
    now = _dt.datetime.utcnow()
    if eng.time_window_start and now < eng.time_window_start:
        raise ScopeViolation(
            f"Engagement '{eng.name}' time window opens at "
            f"{eng.time_window_start.isoformat()}.", code="window_not_open")
    if eng.time_window_end and now > eng.time_window_end:
        raise ScopeViolation(
            f"Engagement '{eng.name}' time window closed at "
            f"{eng.time_window_end.isoformat()}.", code="window_closed")

    # Quota
    used = eng.current_requests or 0
    budget = eng.max_requests or 0
    if budget and used >= budget:
        raise ScopeViolation(
            f"Engagement '{eng.name}' request budget exhausted "
            f"({used}/{budget}). Increase the budget to continue.",
            code="quota_exhausted")

    # Scope
    host = (target.get('host') if isinstance(target, dict) else None) or ""
    if not is_target_authorized(eng, host):
        raise ScopeViolation(
            f"Target host '{host}' is NOT in engagement '{eng.name}' "
            f"authorized scope. Run rejected.", code="out_of_scope")

    # Compute effective safe-mode / dry-run
    safe_mode = bool(eng.safe_mode)
    if requested_safe_mode is True:
        safe_mode = True  # operator can opt INTO safe mode but not out

    dry_run = bool(eng.dry_run_default)
    if requested_dry_run is True:
        dry_run = True
    elif requested_dry_run is False and not eng.dry_run_default:
        dry_run = False

    return {
        'engagement': eng,
        'safe_mode': safe_mode,
        'dry_run': dry_run,
        'health_threshold_x': eng.health_threshold_x or 3.0,
        'remaining_requests': max(0, (budget or 0) - used),
    }


# ---------------------------------------------------------------------------
# Quota accounting
# ---------------------------------------------------------------------------

def charge_requests(engagement_id: str, count: int = 1) -> None:
    """Increment the engagement's request counter. Best-effort — never
    raises. Called by attack runner per-MCP-call."""
    if not engagement_id or count <= 0:
        return
    try:
        eng = Engagement.query.get(engagement_id)
        if eng is None:
            return
        eng.current_requests = (eng.current_requests or 0) + int(count)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def quota_remaining(engagement_id: str) -> int:
    eng = Engagement.query.get(engagement_id)
    if not eng or not eng.max_requests:
        return 10**9  # effectively unlimited
    return max(0, eng.max_requests - (eng.current_requests or 0))


def kill(engagement_id: str) -> bool:
    eng = Engagement.query.get(engagement_id)
    if not eng:
        return False
    eng.is_killed = True
    db.session.commit()
    return True


def revive(engagement_id: str) -> bool:
    eng = Engagement.query.get(engagement_id)
    if not eng:
        return False
    eng.is_killed = False
    db.session.commit()
    return True


def reset_quota(engagement_id: str) -> bool:
    eng = Engagement.query.get(engagement_id)
    if not eng:
        return False
    eng.current_requests = 0
    db.session.commit()
    return True


# ---------------------------------------------------------------------------
# Destructive-payload classification (for safe_mode enforcement)
# ---------------------------------------------------------------------------

DESTRUCTIVE_TAGS = {
    'reverse_shell', 'rce', 'pickle_rce', 'dos', 'redos',
    'destructive', 'log4shell', 'amplification',
}

DESTRUCTIVE_ATTACK_NAMES = {
    'remote_code_execution', 'reverse_shell', 'resource_exhaustion',
    'dos', 'insecure_deserialization',
}


def is_destructive_attack(attack_tags: list[str] | None,
                          attack_name: str | None) -> bool:
    if attack_tags:
        for t in attack_tags:
            if str(t).lower() in DESTRUCTIVE_TAGS:
                return True
    if attack_name:
        n = attack_name.lower().replace(' ', '_').replace('-', '_')
        for d in DESTRUCTIVE_ATTACK_NAMES:
            if d in n:
                return True
    return False


__all__ = [
    "ScopeViolation",
    "preflight_check",
    "get_engagement",
    "get_active_engagement",
    "is_target_authorized",
    "charge_requests",
    "quota_remaining",
    "kill",
    "revive",
    "reset_quota",
    "is_destructive_attack",
]
