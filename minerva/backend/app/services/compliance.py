"""
Compliance mapping lookup service.

Loads `data/compliance_mapping.json` (cached) and exposes helpers to
attach compliance metadata to findings: OWASP LLM Top-10, MITRE ATLAS,
ATT&CK, CWE, NIST AI RMF, NIST 800-53, ISO 27001.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any


_CACHE: dict | None = None
_LOCK = threading.Lock()


def _data_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "data",
                                          "compliance_mapping.json"))


def load(force: bool = False) -> dict:
    """Load (and cache) the mapping JSON."""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE
    with _LOCK:
        if _CACHE is not None and not force:
            return _CACHE
        try:
            with open(_data_path(), "r", encoding="utf-8") as f:
                _CACHE = json.load(f)
        except Exception:
            _CACHE = {"frameworks": {}, "mappings": {}}
    return _CACHE


def for_category(category: str) -> dict:
    """Return the framework→codes dict for a given finding category.
    Falls back to nearest match by prefix."""
    data = load()
    mappings = data.get("mappings") or {}
    cat = (category or "").strip().lower()
    if not cat:
        return {}
    if cat in mappings:
        return dict(mappings[cat])
    # Fallback: prefix / suffix match
    for key, val in mappings.items():
        if cat.startswith(key) or key.startswith(cat) or cat.endswith(key):
            return dict(val)
    return {}


def for_attack_id(attack_id_or_name: str) -> dict:
    """Look up by attack id/name (script-file basename), e.g. tool_poisoning,
    direct_prompt_injection, ws_transport_hardening."""
    if not attack_id_or_name:
        return {}
    key = attack_id_or_name.lower().strip()
    return for_category(key)


def enrich(findings: list[dict]) -> list[dict]:
    """Attach `compliance_map` to each finding (in-place merge)."""
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        c = dict(f)
        cm = for_category(c.get("category") or "")
        if cm:
            c["compliance_map"] = cm
        out.append(c)
    return out


def all_mappings() -> dict:
    """Return the full {category → {framework → codes}} map."""
    return dict((load().get("mappings") or {}))


def frameworks() -> dict:
    return dict((load().get("frameworks") or {}))
