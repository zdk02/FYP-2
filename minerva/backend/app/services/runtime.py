"""
Per-attack network runtime: stealth, throttling, concurrency.

Every MCP call attacks make goes through ``mcp_client.Transport.send`` —
this module gives that send-loop a thread-local "shaping" config so a
pentester can choose between *aggressive* (speed-test, full-throttle)
and *stealth* (slow + jittered to evade IDS / WAF rate-limits) without
each attack script needing to know.

Public API
----------

    from app.services import runtime

    # Configure for the duration of a "with" block
    with runtime.network_profile(
        profile="stealth",
        request_delay_ms=500,
        jitter_ms=200,
        max_concurrency=2,
        max_rps=2,
    ):
        ...

    # Or use the apply()/clear() pair for non-ContextManager call sites
    runtime.apply(params={...})  # extracts the standard keys
    try:
        ...
    finally:
        runtime.clear()

The fields are deliberately small and orthogonal:

  network_profile : "aggressive" | "balanced" | "stealth" | "custom"
  request_delay_ms: fixed sleep before every transport.send (ms)
  jitter_ms       : random ± uniform jitter on top of request_delay_ms
  max_concurrency : semaphore cap on parallel sends from this thread group
  max_rps         : token-bucket cap on requests per second

If a pentester picks a *named profile* without overriding the numeric
knobs, sane defaults are filled in. ``custom`` means "use exactly the
values supplied — don't fill in defaults."
"""

from __future__ import annotations

import contextlib
import random
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Optional


# ---------------------------------------------------------------------------
# Profile presets
# ---------------------------------------------------------------------------

PROFILES = {
    "aggressive": {
        "request_delay_ms": 0,
        "jitter_ms": 0,
        "max_concurrency": 16,
        "max_rps": 0,           # 0 = unlimited
    },
    "balanced": {
        "request_delay_ms": 50,
        "jitter_ms": 30,
        "max_concurrency": 8,
        "max_rps": 20,
    },
    "stealth": {
        "request_delay_ms": 800,
        "jitter_ms": 400,
        "max_concurrency": 1,
        "max_rps": 2,
    },
    # "custom" is handled specially — caller supplies all knobs
}


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class NetworkConfig:
    profile: str = "aggressive"
    request_delay_ms: int = 0
    jitter_ms: int = 0
    max_concurrency: int = 16
    max_rps: int = 0  # 0 = unlimited

    # Internal — created lazily so unrelated attacks don't share state
    _semaphore: threading.Semaphore = field(default=None, repr=False)
    _rps_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _rps_window_start: float = field(default=0.0, repr=False)
    _rps_count: int = field(default=0, repr=False)

    def acquire(self):
        """Block until concurrency budget is available."""
        if self._semaphore is None:
            self._semaphore = threading.Semaphore(max(1, int(self.max_concurrency)))
        self._semaphore.acquire()

    def release(self):
        if self._semaphore is not None:
            self._semaphore.release()

    def gate_rps(self):
        """Token-bucket: block until we're under max_rps."""
        if not self.max_rps or self.max_rps <= 0:
            return
        with self._rps_lock:
            now = time.time()
            if now - self._rps_window_start >= 1.0:
                self._rps_window_start = now
                self._rps_count = 0
            if self._rps_count >= self.max_rps:
                # sleep to top of next second
                sleep_for = 1.0 - (now - self._rps_window_start)
                if sleep_for > 0:
                    time.sleep(sleep_for)
                self._rps_window_start = time.time()
                self._rps_count = 0
            self._rps_count += 1

    def jitter_sleep(self):
        """Apply request_delay_ms ± jitter_ms before the call."""
        delay_ms = int(self.request_delay_ms or 0)
        jitter = int(self.jitter_ms or 0)
        if delay_ms <= 0 and jitter <= 0:
            return
        # uniform distribution in [delay - jitter, delay + jitter], floored at 0
        low = max(0, delay_ms - jitter)
        high = max(low, delay_ms + jitter)
        if low == high:
            time.sleep(low / 1000.0)
        else:
            time.sleep(random.uniform(low, high) / 1000.0)


# ---------------------------------------------------------------------------
# Thread-local store
# ---------------------------------------------------------------------------

_local = threading.local()


def current() -> NetworkConfig:
    cfg = getattr(_local, "config", None)
    if cfg is None:
        cfg = NetworkConfig()
        _local.config = cfg
    return cfg


def set_config(cfg: Optional[NetworkConfig]) -> None:
    if cfg is None:
        _local.config = NetworkConfig()
    else:
        _local.config = cfg


def clear() -> None:
    _local.config = NetworkConfig()


# ---------------------------------------------------------------------------
# Param-based application
# ---------------------------------------------------------------------------

# Standard knob names every attack's config_schema gets via the seeder.
KNOB_KEYS = (
    "network_profile",
    "request_delay_ms",
    "jitter_ms",
    "max_concurrency",
    "max_rps",
)


def from_params(params: dict | None) -> NetworkConfig:
    """Extract the standard knobs from a params dict and build a config.

    Returns a config even if ``params`` is empty — defaults to "aggressive"
    so attack runs against the demo server / unit tests stay fast.
    """
    p = params or {}
    profile = str(p.get("network_profile") or "aggressive").lower()
    if profile not in PROFILES and profile != "custom":
        profile = "aggressive"

    if profile == "custom":
        # Use whatever the caller supplied; missing keys default to 0/unlimited
        cfg = NetworkConfig(
            profile=profile,
            request_delay_ms=int(p.get("request_delay_ms") or 0),
            jitter_ms=int(p.get("jitter_ms") or 0),
            max_concurrency=int(p.get("max_concurrency") or 16),
            max_rps=int(p.get("max_rps") or 0),
        )
    else:
        base = PROFILES[profile]
        cfg = NetworkConfig(
            profile=profile,
            request_delay_ms=int(p.get("request_delay_ms", base["request_delay_ms"])),
            jitter_ms=int(p.get("jitter_ms", base["jitter_ms"])),
            max_concurrency=int(p.get("max_concurrency", base["max_concurrency"])),
            max_rps=int(p.get("max_rps", base["max_rps"])),
        )
    return cfg


def apply(params: dict | None) -> NetworkConfig:
    """Build a config from params and bind it to the current thread."""
    cfg = from_params(params)
    set_config(cfg)
    return cfg


def strip_knobs(params: dict | None) -> dict:
    """Return a copy of ``params`` with the network knobs removed.

    Useful when you don't want the attack script's own ``timeout`` / etc
    handling to see the runtime knobs.
    """
    if not params:
        return {}
    return {k: v for k, v in params.items() if k not in KNOB_KEYS}


# ---------------------------------------------------------------------------
# Context manager (preferred for tests + nested attacks)
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def network_profile(*, profile: str = "aggressive",
                    request_delay_ms: int | None = None,
                    jitter_ms: int | None = None,
                    max_concurrency: int | None = None,
                    max_rps: int | None = None):
    prev = getattr(_local, "config", None)
    cfg = from_params({
        "network_profile": profile,
        "request_delay_ms": request_delay_ms,
        "jitter_ms": jitter_ms,
        "max_concurrency": max_concurrency,
        "max_rps": max_rps,
    } if any(v is not None for v in (request_delay_ms, jitter_ms,
                                      max_concurrency, max_rps))
       else {"network_profile": profile})
    set_config(cfg)
    try:
        yield cfg
    finally:
        if prev is None:
            clear()
        else:
            set_config(prev)


# ---------------------------------------------------------------------------
# Hook used by mcp_client.Transport.send
# ---------------------------------------------------------------------------

def gate_send():
    """Call this just before issuing an MCP request.

    Applies (in order): RPS gate, concurrency semaphore acquire, jitter
    sleep. Pair with ``release_send`` in a try/finally.
    """
    cfg = current()
    cfg.gate_rps()
    cfg.acquire()
    cfg.jitter_sleep()
    return cfg


def release_send(cfg: NetworkConfig):
    cfg.release()
