"""
Shared utilities used by every refined attack — keeps each attack
script compact and idiomatic.
"""

from __future__ import annotations

import hashlib as _hashlib
import json as _json


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def string_params(schema: dict) -> list[str]:
    """Return names of string-typed parameters in an MCP tool inputSchema."""
    return [n for n, s in ((schema or {}).get("properties") or {}).items()
            if isinstance(s, dict) and s.get("type") == "string"]


def all_param_names(schema: dict) -> list[str]:
    return list(((schema or {}).get("properties") or {}).keys())


def fill_defaults(schema: dict, *, default_string: str = "test") -> dict:
    """Build a minimally-valid args dict: required fields get a harmless
    default typed to the schema."""
    out = {}
    props = (schema or {}).get("properties") or {}
    for n in ((schema or {}).get("required") or []):
        t = ((props.get(n) or {}).get("type"))
        out[n] = {"string": default_string, "integer": 1, "number": 1,
                  "boolean": False, "array": [], "object": {}}.get(t, "")
    return out


# ---------------------------------------------------------------------------
# Tool selection
# ---------------------------------------------------------------------------

def pick_by_keywords(tools: list[dict], keywords: tuple[str, ...],
                     *, force_names: list[str] | None = None,
                     fallback_all: bool = False) -> list[dict]:
    """Pick tools whose name or description contains any of the keywords.
    Results are scored by number of matching keywords (name-matches count
    double) and returned in descending relevance.
    If ``force_names`` is given, only tools whose name appears there are
    kept (preserving caller order)."""
    if force_names:
        forced = set(force_names)
        return [t for t in tools if t.get("name") in forced]
    scored = []
    for t in tools:
        name = (t.get("name") or "").lower()
        desc = (t.get("description") or "").lower()
        score = 0
        for k in keywords:
            if k in name:
                score += 2    # name hits weigh more
            if k in desc:
                score += 1
        if score > 0:
            scored.append((score, t))
    scored.sort(key=lambda x: -x[0])
    out = [t for _, t in scored]
    if out:
        return out
    return list(tools) if fallback_all else []


def iter_string_param_slots(tools: list[dict], *, max_params_per_tool: int = 3):
    """Iterate (tool, param_name) for every string parameter of every
    tool. This is the 'fuzz all string slots' helper so attacks don't
    stop at the first parameter of each tool.
    ``max_params_per_tool`` caps how many params per tool we yield (keeps
    runs bounded on tools with many inputs)."""
    for t in tools:
        schema = t.get("inputSchema") or {}
        for pname in string_params(schema)[:max_params_per_tool]:
            yield t, pname


def tools_with_string_param(tools: list[dict]) -> list[dict]:
    return [t for t in tools if string_params(t.get("inputSchema") or {})]


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------

def tool_fingerprint(tool: dict) -> str:
    core = {"name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema")}
    return _hashlib.sha256(
        _json.dumps(core, sort_keys=True, default=str).encode()
    ).hexdigest()


def normalize_name(name: str) -> str:
    if not name:
        return ""
    return (str(name).strip().lower()
            .replace("-", "_").replace(" ", "_")
            .replace(".", "_"))


# ---------------------------------------------------------------------------
# Response inspection
# ---------------------------------------------------------------------------

def response_text(resp: dict) -> str:
    return str(resp.get("text_output") or "")


def contains_any(text: str, markers: tuple[str, ...]) -> str | None:
    tl = text.lower()
    for m in markers:
        if m.lower() in tl:
            return m
    return None
