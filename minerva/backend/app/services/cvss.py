"""
CVSS 3.1 scoring + overall risk grading for Minerva findings.

Minerva attacks produce findings with ``severity`` and ``confidence`` but
not raw CVSS vectors. This module derives a reasonable CVSS 3.1 base
score from the attack ``category`` and a few context signals (auth
required, network exposure). Users can override via explicit
``cvss`` / ``cvss_vector`` fields on a finding — we always prefer those
when present.

Also provides:
  - ``risk_grade(findings)``     -> {grade: A|B|C|D|F, score: 0-100}
  - ``dedupe(findings)``         -> stable-ordered de-duplicated list
  - ``classify_ecosystem(findings)`` -> dict by category
"""

from __future__ import annotations

from collections import Counter, OrderedDict


# ---------------------------------------------------------------------------
# CVSS 3.1 base-score table
# ---------------------------------------------------------------------------

# Vector components (per CVSS 3.1 spec):
#   AV = Attack Vector      {N,A,L,P}
#   AC = Attack Complexity  {L,H}
#   PR = Privs Required     {N,L,H}
#   UI = User Interaction   {N,R}
#   S  = Scope              {U,C}
#   C  = Confidentiality    {H,L,N}
#   I  = Integrity          {H,L,N}
#   A  = Availability       {H,L,N}
#
# For each Minerva attack category we assert a canonical vector aligned
# with its impact profile. Users may still override per-finding.

_CATEGORY_VECTORS: dict[str, tuple[str, float]] = {
    # (vector_string, base_score)
    "rce":                           ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "command_injection":             ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "insecure_deserialization":      ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "sql_injection":                 ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  9.8),
    "file_injection_modification":   ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  8.8),
    "file_injection_addition":       ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  8.8),
    "file_injection_deletion":       ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H",  7.5),
    "path_traversal":                ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    "file_injection_retrieval":      ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    "ssrf":                          ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",  8.6),
    "authentication_bypass":         ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",  9.3),
    "credential_theft":              ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "information_disclosure":        ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "server_backdoor":               ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  9.8),

    "prompt_injection":              ("AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L",  8.4),
    "indirect_prompt_injection":     ("AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L",  8.4),
    "llm_jailbreak":                 ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",  6.5),
    "tool_poisoning":                ("AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L",  8.4),
    "tool_shadowing":                ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",  5.8),
    "tool_name_conflict":            ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",  5.8),
    "tool_rebinding":                ("AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",  7.6),
    "tool_coverage_hijacking":       ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  4.8),
    "tool_preference_manipulation":  ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  4.8),
    "multi_tool_cooperation":        ("AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",  8.1),
    "infectious_attack":             ("AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",  8.1),
    "confused_ai":                   ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  4.8),

    "schema_inconsistency":          ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",  5.0),
    "slash_command_overlap":         ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  4.8),
    "vulnerable_client":             ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",  5.0),

    "package_squatting":             ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",  7.5),
    "resource_exhaustion":           ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  7.5),
    "configuration_drift":           ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  5.0),

    "data_in_transit":               ("AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  7.4),
}


_SEVERITY_BY_SCORE = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def _severity_for_score(s: float) -> str:
    for th, name in _SEVERITY_BY_SCORE:
        if s >= th:
            return name
    return "info"


def score_finding(finding: dict) -> dict:
    """Return a dict with ``cvss_score``, ``cvss_vector``,
    ``cvss_severity``. Does not mutate the input."""
    existing_score = finding.get("cvss")
    existing_vector = finding.get("cvss_vector")
    if existing_score is not None and existing_vector:
        try:
            s = float(existing_score)
            return {"cvss_score": s,
                    "cvss_vector": f"CVSS:3.1/{existing_vector.lstrip('CVSS:3.1/')}",
                    "cvss_severity": _severity_for_score(s),
                    "cvss_source": "explicit"}
        except Exception:
            pass

    cat = str(finding.get("category") or "").lower()
    vec, score = _CATEGORY_VECTORS.get(cat, ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 4.0))

    # Adjust for confidence: cap score by confidence
    conf = str(finding.get("confidence") or "low").lower()
    conf_cap = {"confirmed": 10.0, "high": 9.0, "medium": 6.9, "low": 4.9}.get(conf, 10.0)
    adjusted = min(score, conf_cap)

    return {
        "cvss_score": round(adjusted, 1),
        "cvss_vector": f"CVSS:3.1/{vec}",
        "cvss_severity": _severity_for_score(adjusted),
        "cvss_source": "derived-from-category",
    }


def enrich(findings: list[dict]) -> list[dict]:
    """Return a new list where each finding has CVSS fields populated."""
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        copy = dict(f)
        copy.update(score_finding(f))
        out.append(copy)
    return out


# ---------------------------------------------------------------------------
# Dedupe
# ---------------------------------------------------------------------------

def _dedupe_key(f: dict) -> tuple:
    return (
        str(f.get("category") or "").lower(),
        str(f.get("tool") or ""),
        str(f.get("parameter") or ""),
        str(f.get("title") or "")[:80],
    )


def dedupe(findings: list[dict]) -> list[dict]:
    """Collapse duplicate findings (same category + tool + param + title).
    Keeps the highest-confidence/severity instance, merges evidence lists."""
    groups: dict[tuple, dict] = OrderedDict()
    for f in findings:
        if not isinstance(f, dict):
            continue
        k = _dedupe_key(f)
        existing = groups.get(k)
        if existing is None:
            groups[k] = dict(f)
            continue
        # Merge: prefer higher severity, preserve evidence union
        if _rank(f) > _rank(existing):
            merged = dict(f)
            merged["evidence"] = (existing.get("evidence") or []) + (f.get("evidence") or [])
            groups[k] = merged
        else:
            existing["evidence"] = (existing.get("evidence") or []) + (f.get("evidence") or [])
    return list(groups.values())


_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_CONF_RANK = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}


def _rank(f: dict) -> int:
    s = _SEV_RANK.get(str(f.get("severity") or "info").lower(), 1)
    c = _CONF_RANK.get(str(f.get("confidence") or "low").lower(), 1)
    return s * 10 + c


# ---------------------------------------------------------------------------
# Risk grading
# ---------------------------------------------------------------------------

def risk_grade(findings: list[dict]) -> dict:
    """Return an overall risk profile for a set of findings.

    Scoring (0-100, lower = healthier):
      critical hit       = +25
      high     hit       = +10
      medium   hit       = +3
      low      hit       = +1
      confirmed bonus    = +5
    Cap at 100. Grade mapping:
      A  = 0-9 · B = 10-24 · C = 25-49 · D = 50-74 · F = 75+
    """
    score = 0
    counts = Counter()
    conf_counts = Counter()
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        counts[sev] += 1
        conf = str(f.get("confidence") or "low").lower()
        conf_counts[conf] += 1
        score += {"critical": 25, "high": 10, "medium": 3,
                  "low": 1, "info": 0}.get(sev, 0)
        if conf == "confirmed":
            score += 5
    score = min(100, score)

    if score <= 9:    grade = "A"
    elif score <= 24: grade = "B"
    elif score <= 49: grade = "C"
    elif score <= 74: grade = "D"
    else:             grade = "F"

    return {
        "grade": grade,
        "score": score,
        "severity_counts": dict(counts),
        "confidence_counts": dict(conf_counts),
        "total_findings": len(findings),
    }


def classify_by_category(findings: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in findings:
        cat = str(f.get("category") or "uncategorised")
        out.setdefault(cat, []).append(f)
    return out


__all__ = ["score_finding", "enrich", "dedupe", "risk_grade",
           "classify_by_category"]
