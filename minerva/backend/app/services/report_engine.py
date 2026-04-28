"""
Minerva Pro Pentest Report Engine.

Generates professional reports in four formats from a list of findings
(typically one campaign's full output):

- **HTML** — branded, print-ready, embeddable in emails / portals.
- **PDF** — paged, header/footer, via reportlab.
- **JSON** — machine-readable for downstream tooling.
- **SARIF 2.1.0** — industry-standard for IDE / DevSecOps pipelines
  (GitHub code-scanning, Azure DevOps, GitLab SAST, etc.).

Public API:

    rpt = report_engine.build_report(
        title="Q3 MCP Penetration Test",
        client_name="Acme Corp",
        assessor="Minerva Framework v1.0",
        targets=[{"name": "api.acme", "host": "api.acme.com", ...}],
        findings=[...],                       # raw from attack_runner
        campaign_summary={"started_at": ..., "completed_at": ..., ...},
        options={"include_evidence": True, "exec_summary": "..."},
    )
    html = report_engine.render_html(rpt)
    pdf_bytes = report_engine.render_pdf(rpt)
    json_str = report_engine.render_json(rpt)
    sarif = report_engine.render_sarif(rpt)
"""

from __future__ import annotations

import datetime as _dt
import html as _html
import io
import json as _json
from collections import Counter

from app.services import cvss


# ---------------------------------------------------------------------------
# Data-assembly
# ---------------------------------------------------------------------------

def build_report(*, title: str, client_name: str = "",
                 assessor: str = "Minerva Framework",
                 targets: list[dict] | None = None,
                 findings: list[dict] | None = None,
                 campaign_summary: dict | None = None,
                 options: dict | None = None) -> dict:
    opts = options or {}
    findings = findings or []
    enriched = cvss.enrich(findings)
    deduped = cvss.dedupe(enriched)
    deduped.sort(
        key=lambda f: (-_sev_rank(f.get("severity")),
                       -_conf_rank(f.get("confidence")),
                       -(f.get("cvss_score") or 0),
                       str(f.get("title") or "")),
    )
    grade = cvss.risk_grade(deduped)
    by_cat = cvss.classify_by_category(deduped)
    by_target = _group_by_target(deduped)
    exec_summary = opts.get("exec_summary") or _default_exec_summary(
        grade, targets or [], deduped)
    return {
        "meta": {
            "title": title,
            "client_name": client_name,
            "assessor": assessor,
            "generated_at": _dt.datetime.now(
                _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "tool_version": "Minerva 1.0",
        },
        "targets": targets or [],
        "campaign_summary": campaign_summary or {},
        "executive_summary": exec_summary,
        "risk": grade,
        "findings": deduped,
        "by_category": by_cat,
        "by_target": by_target,
        "category_counts": dict(Counter(
            f.get("category", "unknown") for f in deduped)),
        "analytics": _build_analytics(deduped, targets or [],
                                       campaign_summary or {}),
        "options": opts,
    }


# ---------------------------------------------------------------------------
# Analytics — the structured block the dashboard / charts read from
# ---------------------------------------------------------------------------

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_CONF_ORDER = ("confirmed", "high", "medium", "low")


def _build_analytics(findings: list[dict], targets: list[dict],
                     campaign_summary: dict) -> dict:
    """Pre-compute the cross-cuts the report UI wants to chart.

    Everything in here is read from one or more passes over ``findings``
    so the frontend doesn't have to recompute aggregations client-side.
    """
    n = len(findings)

    # Severity & confidence distributions ---------------------------------
    sev_counts = Counter(str(f.get("severity") or "info").lower() for f in findings)
    conf_counts = Counter(str(f.get("confidence") or "low").lower() for f in findings)
    severity_distribution = [
        {"key": k, "count": sev_counts.get(k, 0),
         "pct": round(sev_counts.get(k, 0) / n * 100, 1) if n else 0.0}
        for k in _SEV_ORDER
    ]
    confidence_distribution = [
        {"key": k, "count": conf_counts.get(k, 0),
         "pct": round(conf_counts.get(k, 0) / n * 100, 1) if n else 0.0}
        for k in _CONF_ORDER
    ]

    # Severity × Confidence matrix ----------------------------------------
    matrix = {s: {c: 0 for c in _CONF_ORDER} for s in _SEV_ORDER}
    for f in findings:
        s = str(f.get("severity") or "info").lower()
        c = str(f.get("confidence") or "low").lower()
        if s in matrix and c in matrix[s]:
            matrix[s][c] += 1
    severity_confidence_matrix = [
        {"severity": s, **{c: matrix[s][c] for c in _CONF_ORDER},
         "total": sum(matrix[s].values())}
        for s in _SEV_ORDER
    ]

    # Attack effectiveness ------------------------------------------------
    by_attack: dict[str, dict] = {}
    for f in findings:
        attack_id = f.get("attack_id") or f.get("attack") or "unknown"
        attack_name = f.get("attack_name") or attack_id
        slot = by_attack.setdefault(attack_id, {
            "attack_id": attack_id,
            "attack_name": attack_name,
            "findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "confirmed": 0,
            "max_cvss": 0.0,
        })
        slot["findings"] += 1
        slot[str(f.get("severity") or "info").lower()] = slot.get(
            str(f.get("severity") or "info").lower(), 0) + 1
        if str(f.get("confidence") or "").lower() == "confirmed":
            slot["confirmed"] += 1
        cvss_score = f.get("cvss_score") or 0
        if cvss_score > slot["max_cvss"]:
            slot["max_cvss"] = cvss_score
    attack_effectiveness = sorted(
        by_attack.values(),
        key=lambda x: (-x["critical"], -x["high"], -x["findings"]),
    )

    # Per-tool ranking (MCP-specific) -------------------------------------
    tool_counter = Counter()
    tool_severity = {}
    for f in findings:
        tool = f.get("tool")
        if not tool:
            continue
        tool_counter[tool] += 1
        slot = tool_severity.setdefault(tool, Counter())
        slot[str(f.get("severity") or "info").lower()] += 1
    top_vulnerable_tools = [
        {"tool": tool, "findings": cnt,
         "critical": tool_severity[tool].get("critical", 0),
         "high": tool_severity[tool].get("high", 0),
         "medium": tool_severity[tool].get("medium", 0),
         "low": tool_severity[tool].get("low", 0)}
        for tool, cnt in tool_counter.most_common(15)
    ]

    # Category distribution -----------------------------------------------
    cat_counter = Counter(f.get("category", "unknown") for f in findings)
    category_distribution = [
        {"category": k, "count": v}
        for k, v in cat_counter.most_common()
    ]

    # CWE distribution ----------------------------------------------------
    cwe_counter = Counter()
    for f in findings:
        cwe = f.get("cwe")
        if cwe:
            cwe_counter[str(cwe)] += 1
    cwe_distribution = [
        {"cwe": k, "count": v} for k, v in cwe_counter.most_common(15)
    ]

    # Target ranking ------------------------------------------------------
    target_ranking = []
    by_target = _group_by_target(findings)
    for key, fs in by_target.items():
        sev = Counter(str(f.get("severity") or "info").lower() for f in fs)
        target_ranking.append({
            "target": key,
            "findings": len(fs),
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
            "low": sev.get("low", 0),
            "info": sev.get("info", 0),
        })
    target_ranking.sort(
        key=lambda t: (-t["critical"], -t["high"], -t["findings"]))

    # OOB vs heuristic share ----------------------------------------------
    oob_confirmed = sum(
        1 for f in findings
        if str(f.get("confidence") or "").lower() == "confirmed"
    )
    heuristic = n - oob_confirmed
    confirmation_split = {
        "confirmed": oob_confirmed,
        "heuristic": heuristic,
        "confirmed_pct": round(oob_confirmed / n * 100, 1) if n else 0.0,
    }

    # CVSS score histogram ------------------------------------------------
    cvss_buckets = {"0-2.9": 0, "3-4.9": 0, "5-6.9": 0, "7-8.9": 0, "9-10": 0}
    cvss_scores = []
    for f in findings:
        s = float(f.get("cvss_score") or 0)
        cvss_scores.append(s)
        if s < 3:
            cvss_buckets["0-2.9"] += 1
        elif s < 5:
            cvss_buckets["3-4.9"] += 1
        elif s < 7:
            cvss_buckets["5-6.9"] += 1
        elif s < 9:
            cvss_buckets["7-8.9"] += 1
        else:
            cvss_buckets["9-10"] += 1
    cvss_avg = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0.0
    cvss_max = round(max(cvss_scores), 2) if cvss_scores else 0.0
    cvss_histogram = [{"bucket": k, "count": v} for k, v in cvss_buckets.items()]

    # MITRE ATT&CK coverage from finding metadata -------------------------
    mitre_counter = Counter()
    for f in findings:
        mid = f.get("mitre_id") or (f.get("metadata") or {}).get("mitre_id")
        if mid:
            mitre_counter[str(mid)] += 1
    mitre_coverage = [{"mitre_id": k, "count": v}
                      for k, v in mitre_counter.most_common()]

    # Findings timeline (best-effort: from finding timestamps if present) -
    timeline = []
    for f in findings:
        ts = f.get("timestamp") or f.get("created_at")
        if not ts:
            continue
        # Bucket to the minute so the chart isn't a million points
        try:
            iso = str(ts)[:16]  # 'YYYY-MM-DDTHH:MM'
            timeline.append({
                "ts": iso,
                "severity": str(f.get("severity") or "info").lower(),
            })
        except Exception:
            continue
    # Aggregate by ts × severity
    tl_buckets: dict[tuple, int] = {}
    for entry in timeline:
        key = (entry["ts"], entry["severity"])
        tl_buckets[key] = tl_buckets.get(key, 0) + 1
    findings_timeline = []
    for (ts, sev), count in sorted(tl_buckets.items()):
        findings_timeline.append({"ts": ts, "severity": sev, "count": count})

    # Coverage matrix: attack × target ------------------------------------
    coverage_attack_target = []
    pair_counter: dict[tuple, int] = {}
    for f in findings:
        attack_id = f.get("attack_id") or "unknown"
        t = f.get("target") or {}
        tkey = t.get("base_url") or f"{t.get('host','?')}:{t.get('port','?')}"
        key = (attack_id, tkey)
        pair_counter[key] = pair_counter.get(key, 0) + 1
    for (attack_id, tgt), count in pair_counter.items():
        coverage_attack_target.append({
            "attack_id": attack_id, "target": tgt, "findings": count,
        })

    # Headline KPIs -------------------------------------------------------
    duration_seconds = None
    if campaign_summary.get("started_at") and campaign_summary.get("completed_at"):
        try:
            t0 = _dt.datetime.fromisoformat(
                str(campaign_summary["started_at"]).replace("Z", "+00:00"))
            t1 = _dt.datetime.fromisoformat(
                str(campaign_summary["completed_at"]).replace("Z", "+00:00"))
            duration_seconds = max(0, int((t1 - t0).total_seconds()))
        except Exception:
            duration_seconds = None

    kpis = {
        "total_findings": n,
        "critical": sev_counts.get("critical", 0),
        "high": sev_counts.get("high", 0),
        "confirmed": oob_confirmed,
        "confirmed_pct": confirmation_split["confirmed_pct"],
        "unique_attacks": len(by_attack),
        "unique_tools_affected": len(tool_counter),
        "unique_targets_affected": len(by_target),
        "max_cvss": cvss_max,
        "avg_cvss": cvss_avg,
        "duration_seconds": duration_seconds,
    }

    return {
        "kpis": kpis,
        "severity_distribution": severity_distribution,
        "confidence_distribution": confidence_distribution,
        "severity_confidence_matrix": severity_confidence_matrix,
        "attack_effectiveness": attack_effectiveness,
        "top_vulnerable_tools": top_vulnerable_tools,
        "category_distribution": category_distribution,
        "cwe_distribution": cwe_distribution,
        "target_ranking": target_ranking,
        "confirmation_split": confirmation_split,
        "cvss_histogram": cvss_histogram,
        "mitre_coverage": mitre_coverage,
        "findings_timeline": findings_timeline,
        "coverage_attack_target": coverage_attack_target,
    }


def _sev_rank(s):
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        str(s or "info").lower(), 0)


def _conf_rank(c):
    return {"confirmed": 4, "high": 3, "medium": 2, "low": 1}.get(
        str(c or "low").lower(), 0)


def _group_by_target(findings):
    out = {}
    for f in findings:
        t = f.get("target") or {}
        key = t.get("base_url") or f"{t.get('host','?')}:{t.get('port','?')}"
        out.setdefault(key, []).append(f)
    return out


def _default_exec_summary(grade, targets, findings):
    tgt_count = len(targets)
    crit = grade["severity_counts"].get("critical", 0)
    high = grade["severity_counts"].get("high", 0)
    confirmed = grade["confidence_counts"].get("confirmed", 0)
    paragraphs = [
        (f"Minerva conducted an automated penetration assessment across "
         f"{tgt_count} target{'s' if tgt_count != 1 else ''} using its 44-"
         f"attack MCP pentest pack. The assessment surfaced "
         f"{grade['total_findings']} deduplicated finding"
         f"{'s' if grade['total_findings'] != 1 else ''}, "
         f"of which {confirmed} carry side-channel-confirmed evidence."),
        (f"The overall security posture of the assessed MCP surface is "
         f"graded **{grade['grade']}** (risk score {grade['score']}/100). "
         f"Findings break down as: {crit} critical, {high} high, "
         f"{grade['severity_counts'].get('medium', 0)} medium, "
         f"{grade['severity_counts'].get('low', 0)} low, "
         f"{grade['severity_counts'].get('info', 0)} informational."),
    ]
    if crit > 0:
        paragraphs.append(
            "We recommend immediate remediation of all critical-severity "
            "issues. Each finding in the detailed section below includes a "
            "specific remediation path and referenced CWE/CVE identifiers.")
    else:
        paragraphs.append(
            "No critical-severity issues were confirmed in this run. "
            "Remediate high- and medium-severity findings per the detailed "
            "section.")
    return "\n\n".join(paragraphs)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  :root{{
    --bg:#0b1220;--panel:#131c2f;--ink:#e7eefb;--muted:#98a3bd;
    --accent:#5b9cff;--grid:#223054;
    --crit:#ff3355;--high:#ff8a3c;--med:#f0c041;--low:#5bc0eb;--info:#8f9bb3;
    --ok:#19c37d;
  }}
  *{{box-sizing:border-box}}
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;
        color:var(--ink);background:var(--bg);margin:0;padding:0;line-height:1.55}}
  .page{{max-width:960px;margin:0 auto;padding:40px 50px}}
  header.cover{{padding:60px 50px;background:linear-gradient(160deg,#0b1220,#162746);
    border-bottom:3px solid var(--accent)}}
  header.cover h1{{font-size:38px;margin:0 0 12px;letter-spacing:.2px}}
  header.cover .subtitle{{color:var(--muted);font-size:16px;margin-bottom:20px}}
  .meta-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;
    margin-top:24px;font-size:13px}}
  .meta-grid div{{background:rgba(255,255,255,.05);padding:12px 14px;border-radius:8px}}
  .meta-grid .k{{color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:.5px;margin-bottom:4px}}
  h2{{font-size:24px;margin:36px 0 14px;border-bottom:1px solid var(--grid);
    padding-bottom:6px}}
  h3{{font-size:18px;margin:24px 0 8px}}
  .grade-card{{display:flex;align-items:center;gap:20px;
    background:var(--panel);border:1px solid var(--grid);border-radius:12px;
    padding:24px;margin:20px 0}}
  .grade-letter{{font-size:72px;font-weight:700;line-height:1;width:100px;
    text-align:center;border-radius:12px;padding:10px 0}}
  .grade-A{{background:rgba(25,195,125,.12);color:var(--ok)}}
  .grade-B{{background:rgba(91,192,235,.12);color:var(--low)}}
  .grade-C{{background:rgba(240,192,65,.12);color:var(--med)}}
  .grade-D{{background:rgba(255,138,60,.12);color:var(--high)}}
  .grade-F{{background:rgba(255,51,85,.12);color:var(--crit)}}
  .grade-meta{{flex:1;display:grid;grid-template-columns:repeat(5,1fr);gap:8px}}
  .sev-cell{{background:var(--bg);border:1px solid var(--grid);border-radius:8px;
    padding:10px;text-align:center}}
  .sev-cell .n{{font-size:24px;font-weight:600}}
  .sev-cell .l{{font-size:10px;text-transform:uppercase;color:var(--muted)}}
  .sev-critical .n{{color:var(--crit)}}
  .sev-high .n{{color:var(--high)}}
  .sev-medium .n{{color:var(--med)}}
  .sev-low .n{{color:var(--low)}}
  .sev-info .n{{color:var(--info)}}
  .finding{{background:var(--panel);border:1px solid var(--grid);
    border-radius:10px;padding:18px 20px;margin:14px 0;
    border-left:4px solid var(--grid)}}
  .finding.fc{{border-left-color:var(--crit)}}
  .finding.fh{{border-left-color:var(--high)}}
  .finding.fm{{border-left-color:var(--med)}}
  .finding.fl{{border-left-color:var(--low)}}
  .finding.fi{{border-left-color:var(--info)}}
  .finding .h{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
  .finding .h .title{{font-weight:600;font-size:16px;flex:1;min-width:200px}}
  .badge{{display:inline-block;padding:3px 8px;border-radius:999px;
    font-size:10px;text-transform:uppercase;letter-spacing:.5px}}
  .b-crit{{background:rgba(255,51,85,.18);color:var(--crit)}}
  .b-high{{background:rgba(255,138,60,.18);color:var(--high)}}
  .b-med{{background:rgba(240,192,65,.18);color:var(--med)}}
  .b-low{{background:rgba(91,192,235,.18);color:var(--low)}}
  .b-info{{background:rgba(143,155,179,.18);color:var(--info)}}
  .b-conf{{background:rgba(25,195,125,.18);color:var(--ok)}}
  .b-mono{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
    background:rgba(255,255,255,.06);color:var(--ink)}}
  .finding dl{{display:grid;grid-template-columns:140px 1fr;gap:6px 16px;
    margin:12px 0 0;font-size:13px}}
  .finding dt{{color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:.5px;padding-top:2px}}
  .finding dd{{margin:0;word-break:break-word}}
  .finding code, .finding pre{{font-family:ui-monospace,SFMono-Regular,
    Consolas,monospace;background:var(--bg);border:1px solid var(--grid);
    padding:2px 6px;border-radius:4px;font-size:12px}}
  .finding pre{{padding:10px 12px;white-space:pre-wrap;max-height:220px;
    overflow:auto}}
  .summary-table{{width:100%;border-collapse:collapse;margin:12px 0;
    font-size:13px}}
  .summary-table th,.summary-table td{{text-align:left;padding:8px 10px;
    border-bottom:1px solid var(--grid)}}
  .summary-table th{{color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:.5px;font-weight:600}}
  footer{{color:var(--muted);font-size:11px;text-align:center;padding:20px 0 40px}}
  details{{margin-top:10px}}
  details summary{{color:var(--muted);cursor:pointer;font-size:12px}}
  @media print{{
    body{{background:#fff;color:#000}}
    .page,header.cover{{max-width:none}}
    .finding,.grade-card,.meta-grid div{{page-break-inside:avoid}}
    header.cover{{background:#fff;color:#000;border-bottom:3px solid #000}}
    .grade-letter{{border:1px solid #000}}
  }}
</style>
</head><body>

<header class="cover">
  <h1>{title}</h1>
  <div class="subtitle">{subtitle}</div>
  <div class="meta-grid">
    <div><div class="k">Client</div>{client_name}</div>
    <div><div class="k">Assessor</div>{assessor}</div>
    <div><div class="k">Generated</div>{generated_at}</div>
  </div>
</header>

<div class="page">

<h2>Executive Summary</h2>
<div class="grade-card">
  <div class="grade-letter grade-{grade_letter}">{grade_letter}</div>
  <div class="grade-meta">
    <div class="sev-cell sev-critical"><div class="n">{n_crit}</div><div class="l">Critical</div></div>
    <div class="sev-cell sev-high"><div class="n">{n_high}</div><div class="l">High</div></div>
    <div class="sev-cell sev-medium"><div class="n">{n_med}</div><div class="l">Medium</div></div>
    <div class="sev-cell sev-low"><div class="n">{n_low}</div><div class="l">Low</div></div>
    <div class="sev-cell sev-info"><div class="n">{n_info}</div><div class="l">Info</div></div>
  </div>
</div>
<p>{exec_summary_html}</p>

<h2>Scope</h2>
{scope_html}

<h2>Methodology</h2>
<p>
  Minerva performs black-box pentesting of MCP deployments via real
  Model Context Protocol JSON-RPC 2.0 over HTTP, SSE, WebSocket and stdio
  transports. The attack pack comprises {attack_count} distinct techniques
  across client-side, server-side, and data-in-transit categories. Each
  finding is classified by severity and confidence; confirmed findings
  carry side-channel proof (out-of-band HTTP callback, reverse-shell
  capture, MITM flow, or canary echo). Findings are scored using
  CVSS 3.1 base metrics derived from attack category.
</p>

<h2>Findings Summary</h2>
<table class="summary-table">
  <thead><tr><th>#</th><th>Severity</th><th>Confidence</th><th>CVSS</th>
    <th>Title</th><th>Category</th></tr></thead>
  <tbody>
  {summary_rows}
  </tbody>
</table>

<h2>Detailed Findings</h2>
{finding_blocks}

{recommendations_block}
{notes_block}

<h2>Appendix A — Attack Catalogue Used</h2>
{appendix_attacks}

</div>
<footer>Generated by Minerva Framework — {generated_at}</footer>
</body></html>
"""


def _h(x) -> str:
    return _html.escape(str(x or ""))


def _pre(x, limit=2000) -> str:
    s = _json.dumps(x, indent=2, default=str) if not isinstance(x, str) else x
    if len(s) > limit:
        s = s[:limit] + f"\n... [truncated {len(s) - limit} chars]"
    return _html.escape(s)


def _sev_letter(sev):
    return {"critical": "c", "high": "h", "medium": "m",
            "low": "l", "info": "i"}.get(str(sev or "info").lower(), "i")


def _sev_badge(sev):
    return {"critical": "b-crit", "high": "b-high", "medium": "b-med",
            "low": "b-low", "info": "b-info"}.get(str(sev or "info").lower(),
                                                   "b-info")


def render_html(rpt: dict) -> str:
    meta = rpt["meta"]
    grade = rpt["risk"]
    c = grade["severity_counts"]

    # Scope table
    scope_rows = []
    for t in rpt.get("targets") or []:
        scope_rows.append(
            f"<tr><td>{_h(t.get('name'))}</td>"
            f"<td>{_h(t.get('host'))}:{_h(t.get('port'))}</td>"
            f"<td>{_h(t.get('protocol'))}</td>"
            f"<td>{_h(t.get('target_type'))}</td></tr>"
        )
    if scope_rows:
        scope_html = ("<table class='summary-table'><thead><tr><th>Name</th>"
                      "<th>Endpoint</th><th>Proto</th><th>Type</th></tr></thead>"
                      f"<tbody>{''.join(scope_rows)}</tbody></table>")
    else:
        scope_html = "<p><em>No targets registered.</em></p>"

    # Summary table rows
    rows = []
    for i, f in enumerate(rpt["findings"], 1):
        rows.append(
            f"<tr><td>{i}</td>"
            f"<td><span class='badge {_sev_badge(f.get('severity'))}'>"
            f"{_h(f.get('severity'))}</span></td>"
            f"<td><span class='badge b-conf'>{_h(f.get('confidence'))}</span></td>"
            f"<td>{_h(f.get('cvss_score'))}</td>"
            f"<td>{_h(f.get('title'))}</td>"
            f"<td>{_h(f.get('category'))}</td></tr>"
        )

    # Detailed finding blocks
    blocks = []
    for i, f in enumerate(rpt["findings"], 1):
        sev = str(f.get("severity") or "info").lower()
        ev_html = ""
        if rpt["options"].get("include_evidence", True):
            items = f.get("evidence") or []
            if items:
                parts = []
                for e in items[:10]:
                    parts.append(
                        f"<details><summary>{_h(e.get('type','?'))} — "
                        f"{_h(e.get('summary',''))}</summary>"
                        f"<pre>{_pre(e.get('data'))}</pre></details>")
                ev_html = "".join(parts)
        refs = f.get("references") or []
        ref_html = ""
        if refs:
            ref_html = " · ".join(
                f'<a href="{_h(r)}" target="_blank">{_h(r)}</a>' for r in refs)
        blocks.append(
            f"<article class='finding f{_sev_letter(sev)}'>"
            f"<div class='h'>"
            f"<span class='title'>#{i} {_h(f.get('title'))}</span>"
            f"<span class='badge {_sev_badge(sev)}'>{_h(sev)}</span>"
            f"<span class='badge b-conf'>{_h(f.get('confidence'))}</span>"
            f"<span class='badge b-mono'>CVSS {_h(f.get('cvss_score'))}</span>"
            f"</div>"
            f"<dl>"
            f"<dt>Category</dt><dd>{_h(f.get('category'))}</dd>"
            f"<dt>CWE</dt><dd>{_h(f.get('cwe') or '—')}</dd>"
            f"<dt>Tool</dt><dd>{_h(f.get('tool') or '—')}</dd>"
            f"<dt>Parameter</dt><dd><code>{_h(f.get('parameter') or '—')}</code></dd>"
            f"<dt>Payload</dt><dd><code>{_h((f.get('payload') or '—')[:400])}</code></dd>"
            f"<dt>CVSS vector</dt><dd><code>{_h(f.get('cvss_vector'))}</code></dd>"
            f"<dt>Description</dt><dd>{_h(f.get('description'))}</dd>"
            f"<dt>Impact</dt><dd>{_h(f.get('impact') or '—')}</dd>"
            f"<dt>Remediation</dt><dd>{_h(f.get('remediation') or '—')}</dd>"
            + (f"<dt>References</dt><dd>{ref_html}</dd>" if ref_html else "")
            + "</dl>"
            + (f"<h3 style='font-size:12px;color:var(--muted);"
               f"text-transform:uppercase;letter-spacing:.5px;margin-top:14px'>"
               f"Evidence</h3>{ev_html}" if ev_html else "")
            + "</article>"
        )

    appendix = ("<p>All 44 attacks in the Minerva Pro + Refined pack are "
                "documented in <code>backend/docs/ATTACKS.md</code>. "
                "Category distribution for this assessment: "
                + ", ".join(f"{k}={v}" for k, v in
                            sorted(rpt["category_counts"].items()))
                + ".</p>")

    # Recommendations / notes blocks — populated only when the analyst has
    # actually written something (via the PUT /reports/<id> edit API).
    recs = rpt.get("recommendations_override") or []
    if recs:
        rec_items = "".join(f"<li>{_h(r)}</li>" for r in recs)
        recommendations_block = (
            f"<h2>Recommendations</h2>\n<ol class='recs'>{rec_items}</ol>")
    else:
        recommendations_block = ""

    notes = (rpt.get("notes") or "").strip()
    if notes:
        notes_html = "<p>" + _h(notes).replace("\n\n", "</p><p>")\
                                       .replace("\n", "<br/>") + "</p>"
        notes_block = f"<h2>Analyst Notes</h2>\n{notes_html}"
    else:
        notes_block = ""

    return _HTML_TEMPLATE.format(
        title=_h(meta["title"]),
        subtitle=_h(rpt["campaign_summary"].get("subtitle")
                    or "MCP Security Assessment"),
        client_name=_h(meta["client_name"] or "—"),
        assessor=_h(meta["assessor"]),
        generated_at=_h(meta["generated_at"]),
        grade_letter=grade["grade"],
        n_crit=c.get("critical", 0), n_high=c.get("high", 0),
        n_med=c.get("medium", 0), n_low=c.get("low", 0),
        n_info=c.get("info", 0),
        exec_summary_html=(_h(rpt["executive_summary"])
                           .replace("\n\n", "</p><p>")),
        scope_html=scope_html,
        attack_count=44,
        summary_rows="\n".join(rows) or
            "<tr><td colspan='6'><em>No findings.</em></td></tr>",
        finding_blocks="\n".join(blocks) or
            "<p><em>No detailed findings.</em></p>",
        recommendations_block=recommendations_block,
        notes_block=notes_block,
        appendix_attacks=appendix,
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def render_pdf(rpt: dict) -> bytes:
    """Render a paged PDF with reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                          Table, TableStyle, PageBreak,
                                          KeepTogether)
    except ImportError:
        raise RuntimeError("reportlab not installed. Add reportlab to requirements.txt.")

    meta = rpt["meta"]
    grade = rpt["risk"]
    c = grade["severity_counts"]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm,
                             rightMargin=2 * cm, topMargin=2 * cm,
                             bottomMargin=2 * cm,
                             title=meta["title"], author=meta["assessor"])
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1Minerva", parent=styles["Heading1"],
                               fontSize=22, textColor=HexColor("#0b1220"),
                               spaceAfter=12))
    styles.add(ParagraphStyle(name="H2Minerva", parent=styles["Heading2"],
                               fontSize=15, textColor=HexColor("#1a2840"),
                               spaceBefore=16, spaceAfter=8))
    styles.add(ParagraphStyle(name="H3Minerva", parent=styles["Heading3"],
                               fontSize=11, textColor=HexColor("#334163"),
                               spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle(name="BodyMinerva", parent=styles["BodyText"],
                               fontSize=10, leading=14))
    styles.add(ParagraphStyle(name="Mono", parent=styles["BodyText"],
                               fontName="Courier", fontSize=8.5,
                               leading=11, textColor=HexColor("#334163")))

    flow = []

    # Cover
    flow.append(Paragraph(meta["title"], styles["H1Minerva"]))
    flow.append(Paragraph("MCP Security Assessment Report",
                           styles["BodyMinerva"]))
    flow.append(Spacer(1, 0.4 * cm))
    cover_tbl = Table([
        ["Client", meta["client_name"] or "—"],
        ["Assessor", meta["assessor"]],
        ["Generated", meta["generated_at"]],
        ["Targets", str(len(rpt.get("targets") or []))],
        ["Total findings", str(grade["total_findings"])],
        ["Overall grade", grade["grade"]],
        ["Risk score", f"{grade['score']}/100"],
    ], colWidths=[4 * cm, 12 * cm])
    cover_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#1a2840")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, HexColor("#c8d0e0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    flow.append(cover_tbl)
    flow.append(Spacer(1, 0.6 * cm))

    # Severity box
    sev_tbl = Table([
        ["Critical", "High", "Medium", "Low", "Info"],
        [str(c.get("critical", 0)), str(c.get("high", 0)),
         str(c.get("medium", 0)), str(c.get("low", 0)),
         str(c.get("info", 0))],
    ], colWidths=[3.2 * cm] * 5)
    sev_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (0, 1), HexColor("#ffe5ea")),
        ("BACKGROUND", (1, 0), (1, 1), HexColor("#ffeedd")),
        ("BACKGROUND", (2, 0), (2, 1), HexColor("#fff5d6")),
        ("BACKGROUND", (3, 0), (3, 1), HexColor("#e0f0ff")),
        ("BACKGROUND", (4, 0), (4, 1), HexColor("#eeeeee")),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 1), 8),
    ]))
    flow.append(sev_tbl)

    # Executive summary
    flow.append(Paragraph("Executive Summary", styles["H2Minerva"]))
    for para in (rpt["executive_summary"] or "").split("\n\n"):
        flow.append(Paragraph(para.replace("**", ""), styles["BodyMinerva"]))
        flow.append(Spacer(1, 0.1 * cm))

    # Scope
    flow.append(Paragraph("Scope", styles["H2Minerva"]))
    if rpt.get("targets"):
        rows = [["Name", "Endpoint", "Protocol", "Type"]]
        for t in rpt["targets"]:
            rows.append([t.get("name", ""),
                         f"{t.get('host','?')}:{t.get('port','?')}",
                         t.get("protocol", ""),
                         t.get("target_type", "")])
        tbl = Table(rows, colWidths=[4 * cm, 6 * cm, 2.5 * cm, 3.5 * cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a2840")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#c8d0e0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [HexColor("#ffffff"), HexColor("#f5f7fb")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ]))
        flow.append(tbl)
    else:
        flow.append(Paragraph("<i>No targets registered.</i>",
                               styles["BodyMinerva"]))

    flow.append(PageBreak())

    # Findings
    flow.append(Paragraph("Detailed Findings", styles["H2Minerva"]))
    for i, f in enumerate(rpt["findings"], 1):
        block = [
            Paragraph(f"#{i} — {_h(f.get('title'))}", styles["H3Minerva"]),
            Paragraph(f"<b>{_h(f.get('severity','').upper())}</b> · "
                       f"confidence {_h(f.get('confidence'))} · "
                       f"CVSS {_h(f.get('cvss_score'))}"
                       f" · CWE {_h(f.get('cwe') or '—')}",
                       styles["BodyMinerva"]),
            Paragraph(f"<b>Category:</b> {_h(f.get('category'))}",
                       styles["BodyMinerva"]),
        ]
        if f.get("tool"):
            block.append(Paragraph(f"<b>Tool:</b> {_h(f.get('tool'))}"
                                   + (f" · <b>Parameter:</b> "
                                      f"<font face='Courier'>"
                                      f"{_h(f.get('parameter'))}</font>"
                                      if f.get("parameter") else ""),
                                   styles["BodyMinerva"]))
        if f.get("payload"):
            block.append(Paragraph(f"<b>Payload:</b> <font face='Courier'>"
                                   f"{_h((f.get('payload') or '')[:300])}"
                                   f"</font>", styles["Mono"]))
        block.append(Paragraph(f"<b>Description:</b> {_h(f.get('description'))}",
                               styles["BodyMinerva"]))
        if f.get("impact"):
            block.append(Paragraph(f"<b>Impact:</b> {_h(f.get('impact'))}",
                                   styles["BodyMinerva"]))
        if f.get("remediation"):
            block.append(Paragraph(f"<b>Remediation:</b> "
                                   f"{_h(f.get('remediation'))}",
                                   styles["BodyMinerva"]))
        block.append(Spacer(1, 0.2 * cm))
        flow.append(KeepTogether(block))
        flow.append(Spacer(1, 0.1 * cm))

    # Recommendations (analyst-edited, only when populated)
    recs = rpt.get("recommendations_override") or []
    if recs:
        flow.append(PageBreak())
        flow.append(Paragraph("Recommendations", styles["H2Minerva"]))
        for i, r in enumerate(recs, 1):
            flow.append(Paragraph(f"<b>{i}.</b> {_h(r)}", styles["BodyMinerva"]))
            flow.append(Spacer(1, 0.15 * cm))

    # Analyst notes (free-text, only when populated)
    notes = (rpt.get("notes") or "").strip()
    if notes:
        flow.append(Spacer(1, 0.4 * cm))
        flow.append(Paragraph("Analyst Notes", styles["H2Minerva"]))
        for para in notes.split("\n\n"):
            flow.append(Paragraph(_h(para).replace("\n", "<br/>"),
                                   styles["BodyMinerva"]))
            flow.append(Spacer(1, 0.15 * cm))

    # Appendix
    flow.append(PageBreak())
    flow.append(Paragraph("Appendix — Category Distribution",
                           styles["H2Minerva"]))
    if rpt["category_counts"]:
        rows = [["Category", "Count"]]
        for k in sorted(rpt["category_counts"]):
            rows.append([k, str(rpt["category_counts"][k])])
        tbl = Table(rows, colWidths=[10 * cm, 4 * cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a2840")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#c8d0e0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [HexColor("#ffffff"), HexColor("#f5f7fb")]),
        ]))
        flow.append(tbl)
    flow.append(Spacer(1, 0.4 * cm))
    flow.append(Paragraph("<i>Generated by Minerva Framework. "
                           "All 44 attacks documented in "
                           "backend/docs/ATTACKS.md</i>", styles["Mono"]))

    doc.build(flow)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(rpt: dict) -> str:
    return _json.dumps(rpt, indent=2, default=str, sort_keys=False)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

_SARIF_LEVELS = {"critical": "error", "high": "error",
                 "medium": "warning", "low": "note", "info": "note"}


def render_sarif(rpt: dict) -> str:
    rules = {}
    results = []
    for f in rpt["findings"]:
        cat = str(f.get("category") or "unknown")
        rid = f"minerva.{cat}"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": cat,
                "shortDescription": {"text": cat.replace("_", " ").title()},
                "fullDescription": {"text": f.get("description")
                                    or cat.replace("_", " ")},
                "help": {"text": f.get("remediation") or ""},
                "defaultConfiguration": {
                    "level": _SARIF_LEVELS.get(
                        str(f.get("severity") or "info").lower(), "note")
                },
                "properties": {
                    "security-severity": str(f.get("cvss_score") or 0),
                    "cwe": f.get("cwe"),
                },
            }
        tgt = (f.get("target") or {})
        physical = (tgt.get("base_url")
                    or f"{tgt.get('host','unknown')}:{tgt.get('port','?')}")
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVELS.get(
                str(f.get("severity") or "info").lower(), "note"),
            "message": {"text": f.get("title") or cat},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": physical},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{
                    "name": f.get("tool") or "",
                    "kind": "mcp-tool",
                }],
            }],
            "properties": {
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "cvss_score": f.get("cvss_score"),
                "cvss_vector": f.get("cvss_vector"),
                "payload": f.get("payload"),
                "parameter": f.get("parameter"),
            },
        })
    sarif = {
        "$schema": ("https://json.schemastore.org/sarif-2.1.0-rtm.5.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Minerva",
                    "version": rpt["meta"].get("tool_version") or "1.0",
                    "informationUri": "https://github.com/minerva-mcp",
                    "rules": list(rules.values()),
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": rpt["campaign_summary"].get("started_at"),
                "endTimeUtc": rpt["campaign_summary"].get("completed_at"),
            }],
            "results": results,
        }],
    }
    return _json.dumps(sarif, indent=2, default=str)


__all__ = ["build_report", "render_html", "render_pdf",
           "render_json", "render_sarif"]
