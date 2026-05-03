"""
Pro report templates: executive / technical / compliance / diff.

Each takes the dict produced by `report_engine.build_report` and emits
HTML. Customisable Jinja templates can be dropped in
`backend/data/report_templates/<name>.html.j2` and they win over the
built-ins.
"""

from __future__ import annotations

import datetime as _dt
import html as _html
import json
import os
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    _HAVE_JINJA = True
except Exception:
    _HAVE_JINJA = False


def _data_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "data",
                                          "report_templates"))


def _custom_template(name: str) -> str | None:
    """If `data/report_templates/<name>.html.j2` exists, return its
    rendered output preference."""
    p = os.path.join(_data_dir(), f"{name}.html.j2")
    return p if os.path.exists(p) else None


def _render_jinja(name: str, ctx: dict) -> str | None:
    if not _HAVE_JINJA:
        return None
    p = _custom_template(name)
    if not p:
        return None
    try:
        env = Environment(
            loader=FileSystemLoader(_data_dir()),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        tpl = env.get_template(f"{name}.html.j2")
        return tpl.render(**ctx)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CSS shared across templates
# ---------------------------------------------------------------------------

_BASE_CSS = """
<style>
  body { font: 13px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, sans-serif;
         color: #111; margin: 0; background: #fff; padding: 32px 48px; }
  h1, h2, h3 { font-weight: 600; }
  h1 { font-size: 26px; margin-bottom: 4px; }
  h2 { font-size: 18px; margin-top: 28px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
  h3 { font-size: 14px; margin-top: 16px; }
  .meta { color: #666; font-size: 12px; }
  .grade { display: inline-block; min-width: 30px; padding: 4px 10px;
           border-radius: 4px; color: #fff; font-weight: 700; text-align: center; }
  .g-A { background: #16a34a; } .g-B { background: #65a30d; }
  .g-C { background: #ca8a04; } .g-D { background: #ea580c; }
  .g-F { background: #dc2626; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  td, th { padding: 6px 10px; border: 1px solid #ddd; vertical-align: top; }
  th { background: #f4f6f8; font-weight: 600; text-align: left; }
  .sev-critical { color: #fff; background: #dc2626; padding: 2px 6px; border-radius: 3px; font-weight: 700; }
  .sev-high     { color: #fff; background: #ea580c; padding: 2px 6px; border-radius: 3px; font-weight: 700; }
  .sev-medium   { color: #fff; background: #ca8a04; padding: 2px 6px; border-radius: 3px; font-weight: 700; }
  .sev-low      { color: #fff; background: #16a34a; padding: 2px 6px; border-radius: 3px; font-weight: 700; }
  .sev-info     { color: #fff; background: #0284c7; padding: 2px 6px; border-radius: 3px; font-weight: 700; }
  .confirmed    { color: #16a34a; font-weight: 700; }
  .pill { display: inline-block; padding: 1px 7px; border-radius: 9px;
          font-size: 11px; background: #eef2ff; color: #4338ca;
          margin-right: 4px; margin-bottom: 2px; }
  pre { background: #f6f8fa; padding: 8px; border-radius: 4px;
        font: 11px/1.4 ui-monospace, Menlo, Consolas, monospace;
        white-space: pre-wrap; word-break: break-word;
        max-height: 360px; overflow: auto; }
  .new { background: #fef3c7; }
  .fixed { background: #d1fae5; }
  .regressed { background: #fee2e2; }
  .footer { color: #999; font-size: 11px; margin-top: 40px;
            border-top: 1px solid #eee; padding-top: 8px; }
</style>
"""


def _esc(s: Any) -> str:
    return _html.escape(str(s or ""), quote=True)


def _summary_grade(rpt: dict) -> str:
    risk = rpt.get("risk") or {}
    grade = risk.get("grade") or "—"
    score = risk.get("score") or 0
    return (f"<span class='grade g-{_esc(grade)}'>{_esc(grade)}</span> "
            f"<span class='meta'>(score {score}/100)</span>")


# ---------------------------------------------------------------------------
# 1) Executive summary — 1 page, no tech
# ---------------------------------------------------------------------------

def render_executive(rpt: dict) -> str:
    """1-page summary: who/what/when, grade, top-3 risks, key metrics."""
    j = _render_jinja("executive", {"rpt": rpt})
    if j:
        return j
    meta = rpt.get("meta") or {}
    risk = rpt.get("risk") or {}
    sev = (risk.get("severity_counts") or {})
    findings = rpt.get("findings") or []
    top3 = findings[:3]
    targets = rpt.get("targets") or []

    rows = "\n".join(
        f"<tr><td>{i + 1}</td>"
        f"<td><span class='sev-{_esc(f.get('severity'))}'>"
        f"{_esc(str(f.get('severity', '')).upper())}</span></td>"
        f"<td>{_esc(f.get('title'))}</td>"
        f"<td>{_esc(f.get('tool') or '—')}</td></tr>"
        for i, f in enumerate(top3)
    ) or "<tr><td colspan='4' class='meta'>No findings.</td></tr>"

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Executive Summary — {_esc(meta.get('title'))}</title>{_BASE_CSS}</head><body>
<h1>{_esc(meta.get('title') or 'Executive Summary')}</h1>
<div class="meta">{_esc(meta.get('client_name') or 'Client')}
 · {_esc(meta.get('generated_at') or '')}
 · Assessor: {_esc(meta.get('assessor') or 'Minerva')}</div>

<h2>Overall Risk</h2>
<p style='font-size:18px'>{_summary_grade(rpt)}</p>
<p>The assessment produced <b>{len(findings)}</b> finding(s) across
<b>{len(targets)}</b> target(s).
Severity distribution:
<span class='sev-critical'>{sev.get('critical', 0)} critical</span> ·
<span class='sev-high'>{sev.get('high', 0)} high</span> ·
<span class='sev-medium'>{sev.get('medium', 0)} medium</span> ·
<span class='sev-low'>{sev.get('low', 0)} low</span>.</p>

<h2>Top Findings (priority order)</h2>
<table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Tool</th></tr></thead>
<tbody>{rows}</tbody></table>

<h2>What this means</h2>
<p>{_esc(rpt.get('executive_summary') or '')}</p>

<div class="footer">Generated by Minerva — Professional MCP Pentesting Framework.</div>
</body></html>"""


# ---------------------------------------------------------------------------
# 2) Technical report — full evidence + repro + CVSS
# ---------------------------------------------------------------------------

def render_technical(rpt: dict) -> str:
    j = _render_jinja("technical", {"rpt": rpt})
    if j:
        return j
    meta = rpt.get("meta") or {}
    findings = rpt.get("findings") or []

    body_parts = [
        f"""<!doctype html><html><head><meta charset="utf-8">
<title>Technical Report — {_esc(meta.get('title'))}</title>{_BASE_CSS}</head><body>
<h1>{_esc(meta.get('title') or 'Technical Pentest Report')}</h1>
<div class="meta">{_esc(meta.get('client_name'))} ·
 generated {_esc(meta.get('generated_at'))}</div>
<h2>Risk Profile</h2><p>{_summary_grade(rpt)}</p>
<h2>Findings ({len(findings)})</h2>"""
    ]

    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "info").lower()
        conf = str(f.get("confidence") or "low").lower()
        cwe = f.get("cwe")
        cvss_v31 = f.get("cvss_vector") or f.get("cvss_v31_vector")
        cvss_v40 = f.get("cvss_v40_vector")
        cm = f.get("compliance_map") or {}
        evidence_html = ""
        for ev in (f.get("evidence") or [])[:5]:
            if isinstance(ev, dict):
                evidence_html += (f"<p><b>{_esc(ev.get('type'))}:</b> "
                                  f"{_esc(ev.get('summary'))}</p>"
                                  f"<pre>{_esc(json.dumps(ev.get('data'), indent=2, default=str)[:3000])}</pre>")

        compliance_html = ""
        if cm:
            for fwk, codes in cm.items():
                compliance_html += "".join(
                    f"<span class='pill'>{_esc(fwk)}: {_esc(c)}</span>"
                    for c in codes)

        body_parts.append(f"""
<h3>#{i} <span class='sev-{_esc(sev)}'>{_esc(sev.upper())}</span> ·
<span class='confirmed'>{_esc(conf.upper())}</span> · {_esc(f.get('title'))}</h3>
<table>
<tr><th style='width:160px'>Category</th><td>{_esc(f.get('category'))}</td></tr>
<tr><th>Tool</th><td>{_esc(f.get('tool') or '—')}</td></tr>
<tr><th>Parameter</th><td>{_esc(f.get('parameter') or '—')}</td></tr>
<tr><th>Payload</th><td><pre>{_esc(f.get('payload') or '')}</pre></td></tr>
<tr><th>CWE</th><td>{_esc(cwe or '—')}</td></tr>
<tr><th>CVSS v3.1</th><td><code>{_esc(cvss_v31 or '—')}</code> · score {f.get('cvss_score') or '—'}</td></tr>
<tr><th>CVSS v4.0</th><td><code>{_esc(cvss_v40 or '—')}</code></td></tr>
{f"<tr><th>Compliance</th><td>{compliance_html}</td></tr>" if compliance_html else ""}
<tr><th>Description</th><td>{_esc(f.get('description'))}</td></tr>
<tr><th>Impact</th><td>{_esc(f.get('impact'))}</td></tr>
<tr><th>Remediation</th><td>{_esc(f.get('remediation'))}</td></tr>
{f"<tr><th>Evidence</th><td>{evidence_html}</td></tr>" if evidence_html else ""}
</table>""")

    body_parts.append("<div class='footer'>Generated by Minerva.</div></body></html>")
    return "".join(body_parts)


# ---------------------------------------------------------------------------
# 3) Compliance report — mapped to a chosen framework
# ---------------------------------------------------------------------------

def render_compliance(rpt: dict, *, framework_key: str = "owasp_llm_2025") -> str:
    j = _render_jinja("compliance", {"rpt": rpt, "framework_key": framework_key})
    if j:
        return j
    meta = rpt.get("meta") or {}
    findings = rpt.get("findings") or []
    # Group findings by framework code
    by_code: dict[str, list[dict]] = {}
    coverage_codes: set = set()
    for f in findings:
        cm = f.get("compliance_map") or {}
        codes = cm.get(framework_key) or []
        if not codes:
            by_code.setdefault("Unmapped", []).append(f)
            continue
        for c in codes:
            by_code.setdefault(c, []).append(f)
            coverage_codes.add(c)

    parts = [f"""<!doctype html><html><head><meta charset="utf-8">
<title>Compliance Report — {_esc(framework_key)}</title>{_BASE_CSS}</head><body>
<h1>{_esc(meta.get('title') or 'Compliance Report')}</h1>
<div class="meta">{_esc(meta.get('client_name'))} ·
 framework: <b>{_esc(framework_key)}</b> ·
 generated {_esc(meta.get('generated_at'))}</div>
<h2>Coverage</h2>
<p>{len(coverage_codes)} unique {framework_key} control(s) referenced by
{len(findings)} finding(s). {_summary_grade(rpt)}</p>"""]

    for code, items in sorted(by_code.items()):
        parts.append(f"<h3>{_esc(code)} <span class='meta'>({len(items)} finding(s))</span></h3>")
        parts.append("<table><thead><tr><th>Severity</th><th>Title</th><th>Tool</th></tr></thead><tbody>")
        for f in items:
            parts.append(
                f"<tr><td><span class='sev-{_esc(f.get('severity'))}'>"
                f"{_esc(str(f.get('severity', '')).upper())}</span></td>"
                f"<td>{_esc(f.get('title'))}</td>"
                f"<td>{_esc(f.get('tool') or '—')}</td></tr>"
            )
        parts.append("</tbody></table>")

    parts.append("<div class='footer'>Generated by Minerva — compliance mapping is advisory.</div></body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# 4) Diff report — between two runs in the same engagement
# ---------------------------------------------------------------------------

def render_diff(diff: dict, *, title: str = "Diff Report") -> str:
    j = _render_jinja("diff", {"diff": diff, "title": title})
    if j:
        return j

    def _row(f, cls=""):
        sev = str(f.get("severity") or "info").lower()
        return (f"<tr class='{cls}'><td>"
                f"<span class='sev-{sev}'>{_esc(sev.upper())}</span></td>"
                f"<td>{_esc(f.get('title'))}</td>"
                f"<td>{_esc(f.get('tool') or '—')}</td>"
                f"<td><code>{_esc(f.get('parameter') or '')}</code></td></tr>")

    def _table(items, cls):
        if not items:
            return "<p class='meta'>None.</p>"
        rows = "".join(_row(f, cls) for f in items)
        return ("<table><thead><tr><th>Sev</th><th>Title</th>"
                "<th>Tool</th><th>Param</th></tr></thead><tbody>"
                f"{rows}</tbody></table>")

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{_esc(title)}</title>{_BASE_CSS}</head><body>
<h1>{_esc(title)}</h1>
<div class='meta'>Run A: {_esc((diff.get('run_a') or {}).get('id'))}
({(diff.get('run_a') or {}).get('count')} findings, started
{_esc((diff.get('run_a') or {}).get('started_at'))}) ·
Run B: {_esc((diff.get('run_b') or {}).get('id'))}
({(diff.get('run_b') or {}).get('count')} findings, started
{_esc((diff.get('run_b') or {}).get('started_at'))})</div>

<h2>Summary</h2>
<table><tr>
<th>New</th><th>Fixed</th><th>Regressed</th><th>Unchanged</th>
</tr><tr>
<td>{diff.get('new_count', 0)}</td>
<td>{diff.get('fixed_count', 0)}</td>
<td>{diff.get('regressed_count', 0)}</td>
<td>{diff.get('unchanged_count', 0)}</td>
</tr></table>

<h2>New ({diff.get('new_count', 0)})</h2>{_table(diff.get('new'), 'new')}
<h2>Fixed ({diff.get('fixed_count', 0)})</h2>{_table(diff.get('fixed'), 'fixed')}
<h2>Regressed ({diff.get('regressed_count', 0)})</h2>{_table(diff.get('regressed'), 'regressed')}
<div class='footer'>Generated by Minerva.</div></body></html>"""


__all__ = ["render_executive", "render_technical",
           "render_compliance", "render_diff"]
