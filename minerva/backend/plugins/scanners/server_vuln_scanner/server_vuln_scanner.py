"""
Scanner: MCP Server Vulnerability Scanner v1.0
Target: MCP server endpoints (HTTP / SSE / WS / stdio)
Severity: high
Pillar: Server-Side

Architecture: Multi-Layer Verification
  Layer 1: Fingerprint + version correlation  → confidence: medium/low
  Layer 2: Capability / tool / auth checks    → confidence: high
  Layer 3: Active MCP probes                  → confidence: confirmed

No hardcoded CVE data. Everything loaded from cve_database.yaml.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import time

try:
    import yaml
except ImportError:
    yaml = None  # checked at runtime


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONFIDENCE_ORDER = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}
_CONFIDENCE_LABELS = {
    "confirmed": "CONFIRMED — active MCP probe succeeded",
    "high":      "HIGH — version match + capability/auth confirms exploitability",
    "medium":    "MEDIUM — version match only",
    "low":       "LOW — server detected, version unknown",
}


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE LOADER
# ═══════════════════════════════════════════════════════════════════════════

def _find_db(custom_path=None):
    candidates = [custom_path] if custom_path else []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        os.path.join(script_dir, "cve_database.yaml"),
        os.path.join(os.getcwd(), "cve_database.yaml"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return None


def _load_db(custom_path=None):
    if yaml is None:
        raise RuntimeError("PyYAML required. Install: pip install pyyaml")
    path = _find_db(custom_path)
    if not path:
        raise FileNotFoundError(
            "cve_database.yaml not found. Place it next to the script."
        )
    with open(path, "r", encoding="utf-8") as f:
        db = yaml.safe_load(f)
    if not isinstance(db, dict) or "servers" not in db:
        raise ValueError("Invalid cve_database.yaml: missing 'servers' key.")
    return db, path


# ═══════════════════════════════════════════════════════════════════════════
# VERSION PARSING
# ═══════════════════════════════════════════════════════════════════════════

def _parse_version(v):
    nums = re.findall(r"\d+", str(v))
    return tuple(int(n) for n in nums) if nums else ()


def _version_matches(detected, spec):
    if not detected:
        return True  # unknown version — treat as potentially affected
    spec = str(spec).strip()
    if any(spec.lower().startswith(w) for w in ["all", "known", "default", "partially", "any"]):
        return True
    m = re.match(r"^([<>]=?)\s*(.+)$", spec)
    if not m:
        return True
    op, ref_str = m.group(1), m.group(2)
    d, r_ = _parse_version(detected), _parse_version(ref_str)
    if not d or not r_:
        return True
    ops = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
           ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
    return ops.get(op, lambda a, b: True)(d, r_)


# ═══════════════════════════════════════════════════════════════════════════
# CHECK ENGINE — handles MCP-specific check types defined in YAML
# ═══════════════════════════════════════════════════════════════════════════

class MCPCheckEngine:
    """Executes verification checks defined in YAML against an MCP server.

    Each handler returns (passed: bool, detail: str). Adding a new check
    type = add a `_check_<type>` method.

    Required state passed in by the caller:
      mcp_factory:  callable(**overrides) → MCPClient (so checks can build
                    fresh sessions with mutated auth, protocol, etc.)
      base_url:     for raw HTTP probes that bypass MCP
      capabilities: dict from initialize result
      tools:        list from tools/list
      logs:         list to append progress lines to
    """

    def __init__(self, *, mcp_factory, base_url, capabilities, tools, logs,
                 requests_mod):
        self.mcp_factory = mcp_factory
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.capabilities = capabilities or {}
        self.tools = tools or []
        self.logs = logs
        self.requests = requests_mod

    def run_check(self, check):
        ctype = check.get("type", "")
        handler = getattr(self, f"_check_{ctype}", None)
        if not handler:
            return False, f"Unknown check type: {ctype}"
        try:
            return handler(check)
        except Exception as e:
            return False, f"Check error: {e!s:.200}"

    def run_checks(self, checks_list):
        if not checks_list:
            return False, []
        results = []
        any_passed = False
        for chk in checks_list:
            passed, detail = self.run_check(chk)
            desc = chk.get("description", chk.get("type", "?"))
            results.append({
                "check": desc, "type": chk.get("type", "?"),
                "passed": passed, "detail": detail,
            })
            if passed:
                any_passed = True
                self.logs.append(f"    [✓] {desc}")
            else:
                self.logs.append(f"    [✗] {desc} — {detail}")
        return any_passed, results

    # ─── MCP-specific check types ─────────────────────────────────────────

    def _check_mcp_capability(self, chk):
        """Server declares a specific capability key in its serverCapabilities."""
        cap = chk.get("capability", "")
        if not cap:
            return False, "no capability specified"
        if cap in self.capabilities:
            return True, f"server advertises capability: {cap}"
        return False, f"capability '{cap}' not advertised"

    def _check_mcp_tool_exists(self, chk):
        """A tool with the given name is present in tools/list."""
        wanted = chk.get("tool", "")
        if not wanted:
            return False, "no tool name specified"
        for t in self.tools:
            if (t.get("name") or "").lower() == wanted.lower():
                return True, f"tool '{wanted}' present"
        return False, f"tool '{wanted}' not present"

    def _check_mcp_tool_pattern(self, chk):
        """At least one tool name OR description matches a regex pattern."""
        pattern = chk.get("pattern", "")
        if not pattern:
            return False, "no pattern specified"
        for t in self.tools:
            blob = f"{t.get('name','')} {t.get('description','')}"
            if re.search(pattern, blob, re.IGNORECASE):
                return True, f"matched: {t.get('name')}"
        return False, f"no tool matched pattern '{pattern}'"

    def _check_mcp_unauth_init(self, chk):
        """Build a no-auth client and try to initialize. Pass = unauthenticated initialize succeeded."""
        try:
            mcp = self.mcp_factory(auth_override={"type": "none"})
        except Exception as e:
            return False, f"could not build no-auth client: {e!s:.150}"
        try:
            r = mcp.initialize()
            if r.get("ok"):
                return True, "server allowed initialize without credentials"
            return False, f"server rejected unauth init: status={r.get('status')}"
        finally:
            try:
                mcp.close()
            except Exception:
                pass

    def _check_mcp_protocol_version(self, chk):
        """Server accepts a specific (potentially deprecated) protocol version."""
        version = chk.get("version", "")
        if not version:
            return False, "no version specified"
        try:
            mcp = self.mcp_factory(protocol_version=version)
        except Exception as e:
            return False, f"could not build client: {e!s:.150}"
        try:
            r = mcp.initialize(protocol_version=version)
            if r.get("ok"):
                return True, f"server accepted protocolVersion={version}"
            return False, f"server rejected version {version}"
        finally:
            try:
                mcp.close()
            except Exception:
                pass

    def _check_mcp_response_marker(self, chk):
        """Call a specific tool, look for marker substring in response."""
        tool = chk.get("tool", "")
        args = chk.get("args", {}) or {}
        marker = chk.get("marker", "")
        if not tool or not marker:
            return False, "tool and marker required"
        try:
            mcp = self.mcp_factory()
        except Exception as e:
            return False, f"could not build client: {e!s:.150}"
        try:
            mcp.initialize()
            r = mcp.call_tool_safe(tool, args)
            text = r.get("text_output") or ""
            if marker in text:
                return True, f"marker '{marker}' found in response"
            return False, f"marker not in response (len={len(text)})"
        finally:
            try:
                mcp.close()
            except Exception:
                pass

    def _check_mcp_method_supported(self, chk):
        """Server responds (not -32601) to a given JSON-RPC method."""
        method = chk.get("method", "")
        params = chk.get("params", {}) or {}
        if not method:
            return False, "no method specified"
        try:
            mcp = self.mcp_factory()
        except Exception as e:
            return False, f"could not build client: {e!s:.150}"
        try:
            mcp.initialize()
            r = mcp.transport.send(method, params)
            err = r.get("error") or {}
            code = err.get("code") if isinstance(err, dict) else None
            if code == -32601:
                return False, f"method {method} → -32601 method-not-found (good)"
            if r.get("ok"):
                return True, f"method {method} responded with result"
            return False, f"method {method} → error code={code}"
        finally:
            try:
                mcp.close()
            except Exception:
                pass

    def _check_http_probe(self, chk):
        """Plain-HTTP probe of an arbitrary path under base_url."""
        path = chk.get("path", "/")
        expect = chk.get("expect_status", [200])
        try:
            r = self.requests.get(self.base_url + path, timeout=8,
                                   allow_redirects=False, verify=False)
            if r.status_code in expect:
                return True, f"{path} → {r.status_code}"
            return False, f"{path} → {r.status_code} (expected {expect})"
        except Exception as e:
            return False, str(e)[:200]

    def _check_http_header(self, chk):
        """Server response includes a specific header (optionally matching regex)."""
        path = chk.get("path", "/")
        header = chk.get("header", "")
        pattern = chk.get("pattern", "")
        try:
            r = self.requests.get(self.base_url + path, timeout=8,
                                   allow_redirects=False, verify=False)
            val = r.headers.get(header, "")
            if not val:
                return False, f"header '{header}' missing"
            if pattern and not re.search(pattern, val, re.IGNORECASE):
                return False, f"{header}: {val} (pattern '{pattern}' not matched)"
            return True, f"{header}: {val}"
        except Exception as e:
            return False, str(e)[:200]


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_via_mcp(target, *, mcp_client_mod, transport_override, protocol_version,
                    timeout, logs):
    """Run initialize + tools/list. Return (server_info, capabilities, tools, raw_init)."""
    mcp = mcp_client_mod.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version or None,
        force_transport=transport_override or None,
    )
    try:
        init = mcp.initialize(
            protocol_version=protocol_version or None,
        )
        if not init.get("ok"):
            logs.append(f"  [-] initialize failed: {init.get('error')}")
            return None, None, None, init
        result = init.get("result") or {}
        server_info = result.get("serverInfo") or result.get("server_info") or {}
        capabilities = result.get("capabilities") or {}
        tl = mcp.tools_list()
        tools = []
        if tl.get("ok") and isinstance(tl.get("result"), dict):
            tools = tl["result"].get("tools") or []
        logs.append(f"  [+] serverInfo: {server_info}")
        logs.append(f"  [+] capabilities: {list(capabilities.keys())}")
        logs.append(f"  [+] tools: {len(tools)}")
        return server_info, capabilities, tools, init
    finally:
        try:
            mcp.close()
        except Exception:
            pass


def _fingerprint(server_info, server_db, logs):
    """Match the live serverInfo against database entries.

    Returns list of (key, server_record, score) sorted by score desc.
    """
    matches = []
    name = (server_info or {}).get("name", "")
    version = (server_info or {}).get("version", "")
    nlow = name.lower()
    for key, rec in (server_db or {}).items():
        det = rec.get("detection") or {}
        score = 0
        si_name = (det.get("server_info_name") or "").lower()
        if si_name and si_name == nlow:
            score += 5
        elif si_name and si_name in nlow:
            score += 3
        for kw in det.get("name_keywords") or []:
            if kw.lower() in nlow:
                score += 2
        for kw in det.get("version_keywords") or []:
            if kw.lower() in str(version).lower():
                score += 1
        if score > 0:
            matches.append((key, rec, score))
    matches.sort(key=lambda x: -x[2])
    if matches:
        logs.append(f"  [+] Fingerprint matches: {[(k, s) for k, _, s in matches[:5]]}")
    else:
        logs.append("  [-] No fingerprint match — falling back to generic CVE checks")
    return matches


def _build_mcp_factory(*, mcp_client_mod, target, timeout,
                       transport_override, protocol_version):
    """Returns a callable that mints fresh MCPClient instances. Used by
    the check engine for tests that need a clean / mutated session."""
    def factory(**overrides):
        t = dict(target)
        if "auth_override" in overrides:
            t["auth_config"] = overrides["auth_override"]
        pv = overrides.get("protocol_version", protocol_version) or None
        return mcp_client_mod.MCPClient.from_target(
            t, timeout=timeout,
            protocol_version=pv,
            force_transport=transport_override or None,
        )
    return factory


# ═══════════════════════════════════════════════════════════════════════════
# CONFIDENCE CALCULATION
# ═══════════════════════════════════════════════════════════════════════════

def _calc_confidence(version_known, version_matched, env_confirmed, active_confirmed):
    if active_confirmed:
        return "confirmed"
    if env_confirmed:
        return "high"
    if version_matched and version_known:
        return "medium"
    return "low"


# ═══════════════════════════════════════════════════════════════════════════
# CAPABILITY / AUTH / VERSION GLOBAL AUDITS
# Independent of any specific server fingerprint
# ═══════════════════════════════════════════════════════════════════════════

def _audit_capabilities(capabilities, db, logs, findings):
    rules = db.get("dangerous_capabilities") or []
    for rule in rules:
        cap = rule.get("capability")
        if not cap:
            continue
        if cap in capabilities:
            findings.append({
                "title": f"Server advertises {cap} capability ({rule.get('description', 'misconfigured')})",
                "severity": rule.get("severity", "medium"),
                "confidence": "confirmed",
                "description": (
                    f"Server's serverCapabilities contains '{cap}'. "
                    f"{rule.get('description', '')}"
                ),
                "remediation": rule.get("remediation",
                                          f"Remove '{cap}' from serverCapabilities."),
                "cve": rule.get("related_cve", "config"),
                "category": "server_capability",
            })
            logs.append(f"  [!] Dangerous capability advertised: {cap}")


def _audit_high_risk_tools(tools, db, logs, findings):
    rules = db.get("high_risk_tool_patterns") or []
    for rule in rules:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        for t in tools:
            blob = f"{t.get('name','')} {t.get('description','')}"
            if re.search(pattern, blob, re.IGNORECASE):
                findings.append({
                    "title": f"High-risk tool exposed: {t.get('name')} ({rule.get('description','')})",
                    "severity": rule.get("severity", "medium"),
                    "confidence": "high",
                    "description": (
                        f"Tool '{t.get('name')}' matches the high-risk pattern "
                        f"'{pattern}': {rule.get('description', '')}"
                    ),
                    "remediation": rule.get("remediation",
                                              "Audit the tool implementation. "
                                              "Sandbox or remove if unnecessary."),
                    "cve": rule.get("related_cve", "config"),
                    "category": "high_risk_tool",
                    "tool": t.get("name"),
                })
                logs.append(f"  [!] High-risk tool: {t.get('name')} ({rule.get('description')})")
                break  # one finding per rule per scan


def _audit_protocol_versions(target, *, mcp_client_mod, transport_override,
                              timeout, logs, findings):
    """Probe every known protocol version, flag deprecated ones that succeed."""
    try:
        result = mcp_client_mod.negotiate_protocol_version(
            target, timeout=timeout,
            force_transport=transport_override or None,
        )
    except Exception as e:
        logs.append(f"  [WARN] protocol-version probe failed: {e!s:.150}")
        return
    accepted = result.get("accepted") or []
    KNOWN_OLD = {"2024-11-05", "2024-10-07", "0.1.0"}
    deprecated_accepted = [v for v in accepted if v in KNOWN_OLD]
    if deprecated_accepted:
        findings.append({
            "title": f"Deprecated MCP protocol version(s) accepted: {deprecated_accepted}",
            "severity": "high",
            "confidence": "confirmed",
            "description": (
                f"Server completed initialize at {deprecated_accepted}. "
                "Versions older than 2025-06-18 lack the OAuth 2.1 mandate, "
                "elicitation, and tightened sampling consent. Downgrade is "
                "exploitable."
            ),
            "remediation": ("Reject protocolVersion older than the minimum "
                            "spec your deployment requires."),
            "cve": "downgrade",
            "category": "protocol_version",
        })
        logs.append(f"  [!] Deprecated protocol versions accepted: {deprecated_accepted}")


def _audit_unauthenticated_init(target, *, mcp_client_mod, transport_override,
                                  timeout, logs, findings):
    """If the target has any auth_config configured, try without it."""
    auth_cfg = target.get("auth_config") or {}
    if isinstance(auth_cfg, str):
        try:
            auth_cfg = json.loads(auth_cfg) if auth_cfg.strip() else {}
        except Exception:
            auth_cfg = {}
    if not isinstance(auth_cfg, dict) or auth_cfg.get("type", "none") in ("", "none"):
        logs.append("  [·] No auth configured — skipping no-auth differential.")
        return
    no_auth_target = dict(target)
    no_auth_target["auth_config"] = {"type": "none"}
    try:
        mcp = mcp_client_mod.MCPClient.from_target(
            no_auth_target, timeout=timeout,
            force_transport=transport_override or None,
        )
        try:
            r = mcp.initialize()
            if r.get("ok"):
                findings.append({
                    "title": "MCP server accepts initialize without credentials",
                    "severity": "critical",
                    "confidence": "confirmed",
                    "description": ("Target has auth_config configured, but "
                                     "initialize succeeded without it. "
                                     "Authentication is not enforced at the "
                                     "transport layer."),
                    "remediation": ("Reject requests missing Authorization headers "
                                    "before any JSON-RPC parsing."),
                    "cve": "auth_bypass",
                    "category": "auth_bypass",
                })
                logs.append("  [!] Server allows unauthenticated initialize")
        finally:
            mcp.close()
    except Exception as e:
        logs.append(f"  [WARN] no-auth probe failed: {e!s:.150}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTE
# ═══════════════════════════════════════════════════════════════════════════

def execute(target, params, context):
    scan_start = datetime.datetime.now(datetime.timezone.utc)
    results = {"success": False, "findings": [], "evidence": [], "logs": []}
    L = results["logs"]

    # The framework injects `mcp_client`, `requests` etc. as globals when
    # running attacks/scanners through attack_runner. When run standalone,
    # we import them ourselves.
    g = globals()
    mcp_client_mod = g.get("mcp_client")
    requests_mod = g.get("requests")
    if mcp_client_mod is None:
        try:
            from app.services import mcp_client as _mc
            mcp_client_mod = _mc
        except Exception as e:
            L.append(f"[FATAL] Could not import mcp_client: {e}")
            return results
    if requests_mod is None:
        try:
            import requests as _r
            requests_mod = _r
        except Exception:
            requests_mod = None

    # Params
    timeout = int(params.get("timeout", 30))
    scan_depth = params.get("scan_depth", "full")
    server_hint = params.get("server_hint", "auto")
    audit_capabilities = bool(params.get("audit_capabilities", True))
    audit_tools = bool(params.get("audit_tools", True))
    audit_auth = bool(params.get("audit_auth", True))
    audit_protocol_versions = bool(params.get("audit_protocol_versions", True))
    protocol_version = params.get("protocol_version", "") or ""
    transport_override = params.get("transport_override", "") or ""
    min_severity = params.get("min_severity", "low")
    min_confidence = params.get("min_confidence", "low")
    cve_db_path = params.get("cve_db_path", None)

    base_url = (target.get("base_url") or
                f"{target.get('protocol', 'http')}://"
                f"{target.get('host', 'localhost')}:{target.get('port', 8080)}")

    scan_id = hashlib.sha256(
        f"{scan_start.isoformat()}-{base_url}-{scan_depth}".encode()
    ).hexdigest()[:12]

    L.append("=" * 70)
    L.append("  Minerva — MCP Server Vulnerability Scanner v1.0")
    L.append("  Multi-Layer Verification Engine")
    L.append("=" * 70)
    L.append(f"  Scan ID        : {scan_id}")
    L.append(f"  Started        : {scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    L.append(f"  Target         : {base_url}")
    L.append(f"  Scan depth     : {scan_depth}")
    L.append(f"  Server hint    : {server_hint}")
    L.append(f"  Min severity   : {min_severity}")
    L.append(f"  Min confidence : {min_confidence}")

    # Load DB
    try:
        db, db_path = _load_db(cve_db_path)
        servers_db = db.get("servers", {}) or {}
        total_cves = sum(len(s.get("cves", []) or []) for s in servers_db.values())
        L.append(f"  CVE database   : {db_path}")
        L.append(f"  Loaded         : {len(servers_db)} server profiles, {total_cves} CVEs")
    except Exception as e:
        L.append(f"  [FATAL] {e}")
        return results
    L.append("")

    min_sev_val = _SEVERITY_ORDER.get(min_severity, 0)
    min_conf_val = _CONFIDENCE_ORDER.get(min_confidence, 0)

    # ── Layer 0: live MCP fingerprint ──────────────────────────────────────
    L.append("─" * 60)
    L.append("  PHASE 1 — Live MCP fingerprint")
    L.append("─" * 60)
    server_info, capabilities, tools, init_resp = _detect_via_mcp(
        target,
        mcp_client_mod=mcp_client_mod,
        transport_override=transport_override,
        protocol_version=protocol_version,
        timeout=timeout, logs=L,
    )
    if server_info is None:
        L.append("  [FATAL] Could not complete MCP handshake — aborting.")
        results["evidence"].append({"type": "init_failure", "raw": init_resp})
        return results
    results["evidence"].append({
        "type": "live_fingerprint",
        "server_info": server_info,
        "capabilities": capabilities,
        "tool_count": len(tools or []),
    })

    # ── Layer 0.5: global audits independent of fingerprint ───────────────
    if audit_capabilities:
        L.append("")
        L.append("  PHASE 2A — Capability audit")
        _audit_capabilities(capabilities or {}, db, L, results["findings"])
    if audit_tools:
        L.append("")
        L.append("  PHASE 2B — Tool risk audit")
        _audit_high_risk_tools(tools or [], db, L, results["findings"])
    if audit_protocol_versions and scan_depth in ("standard", "full"):
        L.append("")
        L.append("  PHASE 2C — Protocol-version audit")
        _audit_protocol_versions(
            target,
            mcp_client_mod=mcp_client_mod,
            transport_override=transport_override,
            timeout=timeout, logs=L, findings=results["findings"],
        )
    if audit_auth and scan_depth in ("standard", "full"):
        L.append("")
        L.append("  PHASE 2D — Auth-enforcement audit")
        _audit_unauthenticated_init(
            target,
            mcp_client_mod=mcp_client_mod,
            transport_override=transport_override,
            timeout=timeout, logs=L, findings=results["findings"],
        )

    # ── Phase 3: server-specific CVE walk ──────────────────────────────────
    L.append("")
    L.append("─" * 60)
    L.append("  PHASE 3 — Server fingerprint + CVE walk")
    L.append("─" * 60)

    # Pick scope
    if server_hint == "auto":
        candidates = _fingerprint(server_info, servers_db, L)
        if not candidates:
            # No fingerprint — scan generic profile if present
            if "generic_mcp" in servers_db:
                candidates = [("generic_mcp", servers_db["generic_mcp"], 1)]
        if not candidates:
            L.append("  [-] No server profile to walk. Skipping CVE phase.")
            return _finalize(results, scan_start, scan_id, base_url, scan_depth,
                              db_path, db, server_info, capabilities, tools,
                              fingerprinted=[], min_sev_val=min_sev_val,
                              min_conf_val=min_conf_val,
                              min_severity=min_severity,
                              min_confidence=min_confidence)
    else:
        keys = [k.strip() for k in server_hint.split(",")]
        candidates = [(k, servers_db[k], 5) for k in keys if k in servers_db]
        if not candidates:
            L.append(f"  [WARN] No DB entry matching '{server_hint}'.")

    factory = _build_mcp_factory(
        mcp_client_mod=mcp_client_mod, target=target, timeout=timeout,
        transport_override=transport_override, protocol_version=protocol_version,
    )
    engine = MCPCheckEngine(
        mcp_factory=factory, base_url=base_url,
        capabilities=capabilities, tools=tools, logs=L,
        requests_mod=requests_mod,
    )

    fingerprinted = []
    detected_version = (server_info or {}).get("version", "") or ""

    for skey, srec, score in candidates:
        sname = srec.get("display_name", skey)
        L.append("")
        L.append(f"  [SERVER] {sname} (score={score}, version={detected_version or 'unknown'})")
        matched_cves = 0
        for cve in srec.get("cves", []) or []:
            sev = str(cve.get("severity", "low")).lower()
            if _SEVERITY_ORDER.get(sev, 0) < min_sev_val:
                continue
            cve_id = cve.get("id", "?")
            title = cve.get("title", "?")
            ver_matched = _version_matches(detected_version,
                                            cve.get("affected_versions", ""))
            if not ver_matched:
                L.append(f"    [·] {cve_id} — not affected (have {detected_version or '?'})")
                continue
            L.append(f"    [▸] {cve_id} — {title}")

            env_confirmed = False
            env_results = []
            if scan_depth in ("standard", "full") and cve.get("env_checks"):
                L.append(f"      ── Layer 2: capability/auth checks ──")
                env_confirmed, env_results = engine.run_checks(cve["env_checks"])

            active_confirmed = False
            active_results = []
            if scan_depth == "full" and cve.get("active_checks"):
                L.append(f"      ── Layer 3: active MCP probes ──")
                active_confirmed, active_results = engine.run_checks(cve["active_checks"])

            confidence = _calc_confidence(
                version_known=bool(detected_version),
                version_matched=ver_matched,
                env_confirmed=env_confirmed,
                active_confirmed=active_confirmed,
            )
            if _CONFIDENCE_ORDER.get(confidence, 0) < min_conf_val:
                L.append(f"      → skipped (confidence {confidence} < min {min_confidence})")
                continue

            matched_cves += 1
            L.append(f"      → CONFIDENCE: {confidence.upper()} — {_CONFIDENCE_LABELS[confidence]}")
            results["findings"].append({
                "title": f"{cve_id}: {title}",
                "severity": sev,
                "confidence": confidence,
                "description": (
                    f"[{sname}] {cve.get('description', '')} "
                    f"| CVSS: {cve.get('cvss', 'N/A')} "
                    f"| CWE: {cve.get('cwe', 'N/A')} "
                    f"| Affected: {cve.get('affected_versions', '?')} "
                    f"| Fixed: {cve.get('fixed_version', '?')}"
                ),
                "remediation": cve.get("remediation", "Update to the latest version."),
                "cve": cve_id,
                "cvss": cve.get("cvss"),
                "cwe": cve.get("cwe"),
                "references": cve.get("references", []),
                "server": sname,
                "category": "cve",
                "verification": {
                    "version_known": bool(detected_version),
                    "version_matched": ver_matched,
                    "env_checks": env_results,
                    "active_checks": active_results,
                },
            })
        fingerprinted.append({
            "key": skey, "name": sname, "score": score,
            "matched_cves": matched_cves,
            "total_cves": len(srec.get("cves", []) or []),
        })

    return _finalize(results, scan_start, scan_id, base_url, scan_depth,
                      db_path, db, server_info, capabilities, tools,
                      fingerprinted=fingerprinted,
                      min_sev_val=min_sev_val, min_conf_val=min_conf_val,
                      min_severity=min_severity, min_confidence=min_confidence)


def _finalize(results, scan_start, scan_id, base_url, scan_depth, db_path, db,
              server_info, capabilities, tools, *, fingerprinted,
              min_sev_val, min_conf_val, min_severity, min_confidence):
    L = results["logs"]
    scan_end = datetime.datetime.now(datetime.timezone.utc)
    duration = (scan_end - scan_start).total_seconds()

    sev_counts = {}
    conf_counts = {}
    for f in results["findings"]:
        sev_counts[f.get("severity", "low")] = sev_counts.get(f.get("severity", "low"), 0) + 1
        conf_counts[f.get("confidence", "low")] = conf_counts.get(f.get("confidence", "low"), 0) + 1

    L.append("")
    L.append("═" * 70)
    L.append("  RESULTS SUMMARY")
    L.append("═" * 70)
    L.append(f"  Server detected : {(server_info or {}).get('name', '?')} "
             f"v{(server_info or {}).get('version', '?')}")
    L.append(f"  Capabilities    : {list((capabilities or {}).keys())}")
    L.append(f"  Tools exposed   : {len(tools or [])}")
    if fingerprinted:
        for fp in fingerprinted:
            L.append(f"  Profile {fp['name']}: {fp['matched_cves']}/{fp['total_cves']} CVEs matched")
    L.append("")
    L.append(f"  Total findings  : {len(results['findings'])}")
    L.append(f"  By severity     : "
             f"{sev_counts.get('critical',0)} critical, "
             f"{sev_counts.get('high',0)} high, "
             f"{sev_counts.get('medium',0)} medium, "
             f"{sev_counts.get('low',0)} low")
    L.append(f"  By confidence   : "
             f"{conf_counts.get('confirmed',0)} confirmed, "
             f"{conf_counts.get('high',0)} high, "
             f"{conf_counts.get('medium',0)} medium, "
             f"{conf_counts.get('low',0)} low")
    L.append("")
    L.append(f"  Scan ID         : {scan_id}")
    L.append(f"  Duration        : {duration:.1f}s")
    L.append(f"  Completed       : {scan_end.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    L.append(f"  DB version      : {db.get('schema_version', '?')}")
    L.append("═" * 70)

    results["evidence"].append({
        "type": "scan_report",
        "scan_id": scan_id,
        "started": scan_start.isoformat(),
        "completed": scan_end.isoformat(),
        "duration_seconds": round(duration, 2),
        "target": base_url,
        "scan_depth": scan_depth,
        "db_path": db_path,
        "db_schema_version": db.get("schema_version", "?"),
        "server_info": server_info,
        "capabilities": capabilities,
        "tool_count": len(tools or []),
        "fingerprinted": fingerprinted,
        "total_findings": len(results["findings"]),
        "severity_breakdown": dict(sev_counts),
        "confidence_breakdown": dict(conf_counts),
        "min_severity": min_severity,
        "min_confidence": min_confidence,
    })
    results["success"] = True
    return results


# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    target = {
        "host": sys.argv[1] if len(sys.argv) > 1 else "localhost",
        "port": int(sys.argv[2]) if len(sys.argv) > 2 else 4001,
        "protocol": sys.argv[3] if len(sys.argv) > 3 else "http",
        "base_url": (f"{sys.argv[3] if len(sys.argv) > 3 else 'http'}://"
                     f"{sys.argv[1] if len(sys.argv) > 1 else 'localhost'}:"
                     f"{sys.argv[2] if len(sys.argv) > 2 else 4001}"),
    }
    params = {
        "scan_depth": "full", "server_hint": "auto",
        "min_severity": "low", "min_confidence": "low",
        "audit_capabilities": True, "audit_tools": True,
        "audit_auth": True, "audit_protocol_versions": True,
    }
    out = execute(target, params, {"attack_id": "test"})
    print("\n".join(out["logs"]))
    print("\n" + "─" * 60)
    for f in out["findings"]:
        print(f"  [{f['severity'].upper():8s}] [{f.get('confidence','?').upper():9s}] {f['title']}")
