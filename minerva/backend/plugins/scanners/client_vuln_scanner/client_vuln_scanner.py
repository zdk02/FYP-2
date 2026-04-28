"""
Attack Name: MCP Client Vulnerability Scanner v3.0
CVE: Multiple (loaded from cve_database.yaml)
Target: MCP client applications
Severity: high
Pillar: 3 (Client-Side)

Architecture: Multi-Layer Verification
  Layer 1: Version correlation         → confidence: medium/low
  Layer 2: Environment checks          → confidence: high
  Layer 3: Active verification probes  → confidence: confirmed

No hardcoded CVE data. Everything loaded from cve_database.yaml.
"""

import subprocess
import platform
import os
import re
import json
import time
import socket
import hashlib
import datetime
import requests

try:
    import yaml
    def _load_yaml(path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
except ImportError:
    def _load_yaml(path):
        try:
            import yaml as _y
            with open(path, "r", encoding="utf-8") as f:
                return _y.safe_load(f)
        except ImportError:
            raise RuntimeError(
                f"PyYAML required to load {path}. Install: pip install pyyaml"
            )


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_ORDER  = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONFIDENCE_ORDER = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}
_CONFIDENCE_LABELS = {
    "confirmed": "CONFIRMED — active verification succeeded",
    "high":      "HIGH — version match + environment confirms exploitability",
    "medium":    "MEDIUM — version match only",
    "low":       "LOW — client detected, version unknown",
}


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE LOADER
# ═══════════════════════════════════════════════════════════════════════════

def _find_db(custom_path=None):
    candidates = [custom_path] if custom_path else []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        os.path.join(script_dir, "cve_database.yaml"),
        os.path.join(script_dir, "..", "data", "cve_database.yaml"),
        os.path.join(os.getcwd(), "cve_database.yaml"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return None


def _load_db(custom_path=None):
    path = _find_db(custom_path)
    if not path:
        raise FileNotFoundError(
            "cve_database.yaml not found. Place it next to the script."
        )
    db = _load_yaml(path)
    if not isinstance(db, dict) or "clients" not in db:
        raise ValueError("Invalid cve_database.yaml: missing 'clients' key.")
    return db, path


# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _expand(p):
    return os.path.expandvars(os.path.expanduser(str(p)))


def _parse_version(v):
    nums = re.findall(r"\d+", str(v))
    return tuple(int(n) for n in nums) if nums else ()


def _version_matches(detected, spec):
    if not detected:
        return True
    spec = str(spec).strip()
    if any(spec.lower().startswith(w) for w in ["all", "known", "default", "partially"]):
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
# CHECK EXECUTION ENGINE
# Handles all check types defined in YAML env_checks / active_checks
# ═══════════════════════════════════════════════════════════════════════════

class CheckEngine:
    """Executes verification checks defined in YAML. Each handler returns
    (passed: bool, detail: str). Adding a new check type = add a method."""

    def __init__(self, logs):
        self.logs = logs

    def run_check(self, check):
        """Dispatch a single check dict to the appropriate handler."""
        ctype = check.get("type", "")
        handler = getattr(self, f"_check_{ctype}", None)
        if not handler:
            return False, f"Unknown check type: {ctype}"
        try:
            return handler(check)
        except Exception as e:
            return False, f"Check error: {e}"

    def run_checks(self, checks_list):
        """Run a list of checks. Returns (any_passed, results_list)."""
        if not checks_list:
            return False, []
        results = []
        any_passed = False
        for chk in checks_list:
            passed, detail = self.run_check(chk)
            desc = chk.get("description", chk.get("type", "?"))
            results.append({
                "check": desc,
                "type": chk.get("type", "?"),
                "passed": passed,
                "detail": detail,
            })
            if passed:
                any_passed = True
                self.logs.append(f"    [✓] {desc}")
            else:
                self.logs.append(f"    [✗] {desc} — {detail}")
        return any_passed, results

    # ─── Check type handlers ──────────────────────────────────────────────

    def _check_file_exists(self, chk):
        path = _expand(chk.get("path", ""))
        if os.path.exists(path):
            return True, f"Found: {path}"
        return False, f"Not found: {path}"

    def _check_dir_exists(self, chk):
        path = _expand(chk.get("path", ""))
        if os.path.isdir(path):
            return True, f"Directory exists: {path}"
        return False, f"Directory missing: {path}"

    def _check_file_contains(self, chk):
        path = _expand(chk.get("path", ""))
        pattern = chk.get("pattern", "")
        if not os.path.isfile(path):
            return False, f"File not found: {path}"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if re.search(pattern, content, re.IGNORECASE):
                return True, f"Pattern matched in {path}"
            return False, f"Pattern not found in {path}"
        except Exception as e:
            return False, str(e)

    def _check_file_not_contains(self, chk):
        passed, detail = self._check_file_contains(chk)
        if detail.startswith("File not found"):
            return False, detail
        return not passed, detail.replace("matched", "absent").replace("not found", "present (good)")

    def _check_port_open(self, chk):
        host = chk.get("host", "127.0.0.1")
        port = int(chk.get("port", 0))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                return True, f"{host}:{port} is OPEN"
            return False, f"{host}:{port} is closed"
        except Exception as e:
            return False, str(e)

    def _check_ws_no_auth(self, chk):
        """Try a raw WebSocket upgrade handshake without credentials."""
        host = chk.get("host", "127.0.0.1")
        port = int(chk.get("port", 0))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            # Send minimal WebSocket upgrade request
            upgrade = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            s.send(upgrade.encode())
            resp = s.recv(1024).decode(errors="ignore")
            s.close()
            if "101" in resp and "Upgrade" in resp:
                return True, f"WebSocket accepted WITHOUT AUTH on {host}:{port}"
            if "401" in resp or "403" in resp:
                return False, f"WebSocket requires auth on {host}:{port}"
            return False, f"Unexpected response: {resp[:80]}"
        except socket.timeout:
            return False, f"Connection timeout to {host}:{port}"
        except ConnectionRefusedError:
            return False, f"Connection refused on {host}:{port}"
        except Exception as e:
            return False, str(e)

    def _check_http_probe(self, chk):
        url = chk.get("url", "")
        expect = chk.get("expect_status", [200])
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in expect:
                return True, f"{url} → {resp.status_code}"
            return False, f"{url} → {resp.status_code} (expected {expect})"
        except requests.exceptions.ConnectionError:
            return False, f"Connection refused: {url}"
        except Exception as e:
            return False, str(e)

    def _check_http_header(self, chk):
        url = chk.get("url", "")
        header = chk.get("header", "")
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            val = resp.headers.get(header, "")
            if val:
                return True, f"{header}: {val}"
            return False, f"Header '{header}' not present"
        except Exception as e:
            return False, str(e)

    def _check_command_output(self, chk):
        cmd = chk.get("cmd", "")
        expect = chk.get("expect_pattern", "")
        rc, out, err = _run_cmd(cmd, timeout=10)
        combined = f"{out} {err}"
        if expect and re.search(expect, combined, re.IGNORECASE):
            return True, f"Output matched: {out[:80]}"
        if rc == 0 and not expect:
            return True, f"Command succeeded: {out[:80]}"
        return False, f"No match (rc={rc}): {combined[:80]}"

    def _check_config_json_value(self, chk):
        path = _expand(chk.get("path", ""))
        key = chk.get("key", "")
        expect = chk.get("expect", "")
        if not os.path.isfile(path):
            return False, f"Config not found: {path}"
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Navigate dotted key path
            val = data
            for part in key.split("."):
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
                    break
            if val is None:
                return False, f"Key '{key}' not found in {path}"
            val_str = str(val)
            if re.search(expect, val_str, re.IGNORECASE):
                return True, f"{key} = {val_str}"
            return False, f"{key} = {val_str} (expected pattern: {expect})"
        except json.JSONDecodeError:
            return False, f"Invalid JSON: {path}"
        except Exception as e:
            return False, str(e)

    def _check_npm_installed(self, chk):
        pkg = chk.get("package", "")
        vuln_below = chk.get("vulnerable_below", "")
        rc, out, _ = _run_cmd(f"npm list -g {pkg} --depth=0 2>/dev/null", timeout=15)
        if rc != 0 or not out:
            return False, f"{pkg} not installed globally"
        ver_match = re.search(r"@(\d+\.\d+\.\d+)", out)
        if not ver_match:
            return False, f"{pkg} installed but version not parsed"
        version = ver_match.group(1)
        if vuln_below and _version_matches(version, f"< {vuln_below}"):
            return True, f"{pkg}@{version} < {vuln_below} (VULNERABLE)"
        return False, f"{pkg}@{version} >= {vuln_below} (patched)"

    def _check_process_running(self, chk):
        name = chk.get("name", "")
        if platform.system() == "Windows":
            cmd = f'tasklist /FI "IMAGENAME eq {name}.exe" 2>NUL'
        else:
            cmd = f"pgrep -f '{name}' 2>/dev/null"
        rc, out, _ = _run_cmd(cmd)
        if rc == 0 and out:
            return True, f"Process '{name}' is running"
        return False, f"Process '{name}' not found"

    def _check_tcp_banner(self, chk):
        host = chk.get("host", "127.0.0.1")
        port = int(chk.get("port", 0))
        expect = chk.get("expect", "")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            banner = s.recv(1024).decode(errors="ignore")
            s.close()
            if expect and re.search(expect, banner, re.IGNORECASE):
                return True, f"Banner matched: {banner[:60]}"
            if not expect and banner:
                return True, f"Banner: {banner[:60]}"
            return False, f"No match: {banner[:60]}"
        except Exception as e:
            return False, str(e)


# ═══════════════════════════════════════════════════════════════════════════
# OS-AWARE HELPERS
# ═══════════════════════════════════════════════════════════════════════════

_CURRENT_OS = platform.system().lower()  # "linux", "darwin", "windows"

def _is_path_for_current_os(path_str):
    """Skip paths that clearly belong to another OS."""
    p = str(path_str)
    if _CURRENT_OS != "darwin" and "/Library/Application Support/" in p:
        return False
    if _CURRENT_OS != "windows" and ("%APPDATA%" in p or "%LOCALAPPDATA%" in p):
        return False
    if _CURRENT_OS == "windows" and p.startswith("~/") and "/Library/" not in p:
        return True  # ~ expands on Windows too
    return True


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION (OS-aware, with detection scoring)
# ═══════════════════════════════════════════════════════════════════════════

def _detect_by_process(detection, logs):
    for pname in detection.get("process_names", []):
        cmd = (f'tasklist /FI "IMAGENAME eq {pname}.exe" 2>NUL'
               if _CURRENT_OS == "windows"
               else f"pgrep -f '{pname}' 2>/dev/null")
        rc, out, _ = _run_cmd(cmd)
        if rc == 0 and out:
            logs.append(f"[+] Process detected: {pname}")
            return True
    return False


def _detect_by_config(detection, logs):
    found = []
    for p in detection.get("config_paths", []):
        if not _is_path_for_current_os(p):
            continue
        expanded = _expand(p)
        if os.path.exists(expanded):
            logs.append(f"[+] Config found: {expanded}")
            found.append(expanded)
    return found


def _detect_by_extension(detection, logs):
    """For IDE extensions: verify the specific extension is installed,
    not just that the IDE process is running. This prevents false positives
    when multiple clients share the same process name (e.g. 'code')."""
    indicators = detection.get("indicators", [])
    if not indicators:
        return False

    # VS Code extensions check
    ext_dir = _expand("~/.vscode/extensions/")
    if os.path.isdir(ext_dir):
        try:
            installed = os.listdir(ext_dir)
            for ind in indicators:
                for ext_name in installed:
                    if ind.lower() in ext_name.lower():
                        logs.append(f"[+] Extension confirmed: {ext_name}")
                        return True
        except Exception:
            pass

    # Also try CLI check
    for cmd in detection.get("version_commands", []):
        rc, out, _ = _run_cmd(cmd, timeout=15)
        if rc == 0 and out and any(ind.lower() in out.lower() for ind in indicators):
            logs.append(f"[+] Extension confirmed via CLI: {out[:80]}")
            return True

    return False


def _detect_version(detection, logs):
    for cmd in detection.get("version_commands", []):
        rc, out, _ = _run_cmd(cmd, timeout=15)
        if rc == 0 and out:
            m = re.search(r"(\d+\.\d+\.\d+(?:\.\d+)?)", out)
            if m:
                v = m.group(1)
                logs.append(f"[+] Version: {v} (via: {cmd})")
                return v
    pkg = detection.get("npm_package")
    if pkg:
        rc, out, _ = _run_cmd(f"npm list -g {pkg} --depth=0 2>/dev/null", timeout=15)
        if rc == 0 and out:
            m = re.search(r"@(\d+\.\d+\.\d+)", out)
            if m:
                v = m.group(1)
                logs.append(f"[+] Version (npm): {v}")
                return v
    return None


def _calc_detection_score(process_found, configs_found, version_found, extension_confirmed):
    """Calculate detection confidence: how sure are we this client is actually here?
    Prevents 'code' process from flagging every VS Code extension client."""
    score = 0
    if process_found:
        score += 1
    if configs_found:
        score += 2  # Config files are stronger evidence
    if version_found:
        score += 3  # Version command succeeded = definitive
    if extension_confirmed:
        score += 3  # Extension-level verification = definitive
    return score


# ═══════════════════════════════════════════════════════════════════════════
# REMOTE PROBING
# ═══════════════════════════════════════════════════════════════════════════

def _probe_remote(base_url, timeout, db, logs):
    indicators = {}
    for path in db.get("remote_probe_paths", []):
        try:
            url = f"{base_url}{path}"
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code < 500:
                logs.append(f"[*] Probe {url} → {resp.status_code}")
                for h in db.get("interesting_headers", []):
                    val = resp.headers.get(h, "")
                    if val:
                        indicators[h] = val
                try:
                    body = resp.json()
                    for k in ("version", "name", "serverInfo"):
                        if k in body:
                            indicators[k] = body[k] if isinstance(body[k], str) else str(body[k])
                except Exception:
                    pass
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass
    for port in db.get("websocket_probe_ports", []):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                indicators[f"ws_{port}"] = "open"
                logs.append(f"[!] localhost:{port} open (potential MCP WebSocket)")
            s.close()
        except Exception:
            pass
    return indicators


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG AUDIT
# ═══════════════════════════════════════════════════════════════════════════

def _audit_configs(paths, db, logs):
    patterns = db.get("dangerous_config_patterns", [])
    findings = []
    for p in paths:
        targets = []
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    if f.endswith((".json", ".jsonc", ".yaml", ".yml")):
                        targets.append(os.path.join(root, f))
        elif os.path.isfile(p):
            targets.append(p)
        for filepath in targets:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                for pat in patterns:
                    if re.search(pat.get("pattern", ""), content, re.IGNORECASE):
                        findings.append({
                            "file": filepath,
                            "description": pat.get("description", ""),
                            "severity": pat.get("severity", "medium"),
                            "related_cve": pat.get("related_cve", ""),
                        })
                        logs.append(f"[!] {filepath}: {pat.get('description', '')}")
            except Exception:
                pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# CONFIDENCE CALCULATION
# ═══════════════════════════════════════════════════════════════════════════

def _calc_confidence(version_known, version_matched, env_confirmed, active_confirmed):
    """
    Layer 1 (version):   matched + known    → medium
                         matched + unknown   → low
    Layer 2 (env):       env confirms        → bumps to high
    Layer 3 (active):    active confirms     → bumps to confirmed
    """
    if active_confirmed:
        return "confirmed"
    if env_confirmed:
        return "high"
    if version_matched and version_known:
        return "medium"
    return "low"


# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTE
# ═══════════════════════════════════════════════════════════════════════════

def execute(target, params, context):
    scan_start = datetime.datetime.now(datetime.timezone.utc)
    results = {"success": False, "findings": [], "evidence": [], "logs": []}

    timeout       = params.get("timeout", 30)
    scan_depth    = params.get("scan_depth", "full")
    client_hint   = params.get("client_hint", "auto")
    check_local   = params.get("check_local", True)
    check_remote  = params.get("check_remote", True)
    min_severity  = params.get("min_severity", "low")
    min_confidence = params.get("min_confidence", "low")
    cve_db_path   = params.get("cve_db_path", None)

    base_url = (f"{target.get('protocol', 'http')}://"
                f"{target.get('host', 'localhost')}:{target.get('port', 8080)}")

    # Unique scan ID for audit trail
    scan_id = hashlib.sha256(
        f"{scan_start.isoformat()}-{base_url}-{scan_depth}".encode()
    ).hexdigest()[:12]

    L = results["logs"]
    L.append("=" * 70)
    L.append("  AEGIS — MCP Client Vulnerability Scanner v3.1")
    L.append("  Multi-Layer Verification Engine")
    L.append("=" * 70)
    L.append(f"  Scan ID        : {scan_id}")
    L.append(f"  Started        : {scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    L.append(f"  Target         : {base_url}")
    L.append(f"  Scan depth     : {scan_depth}")
    L.append(f"  Client hint    : {client_hint}")
    L.append(f"  Min severity   : {min_severity}")
    L.append(f"  Min confidence : {min_confidence}")
    L.append(f"  Platform       : {platform.system()} {platform.release()} ({_CURRENT_OS})")

    # Load database
    try:
        db, db_path = _load_db(cve_db_path)
        clients_db = db.get("clients", {})
        total_cves = sum(len(c.get("cves", [])) for c in clients_db.values())
        L.append(f"  CVE database   : {db_path}")
        L.append(f"  Loaded         : {len(clients_db)} clients, {total_cves} CVEs")
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        L.append(f"  [FATAL] {e}")
        return results
    L.append("")

    # Scope
    if client_hint == "auto":
        scope = list(clients_db.keys())
    else:
        hints = [h.strip() for h in client_hint.split(",")]
        scope = [h for h in hints if h in clients_db]
        if not scope:
            for h in hints:
                scope += [k for k in clients_db if h.lower() in k.lower()]
        if not scope:
            L.append(f"  [WARN] No match for '{client_hint}'. Scanning all.")
            scope = list(clients_db.keys())

    min_sev_val = _SEVERITY_ORDER.get(min_severity, 0)
    min_conf_val = _CONFIDENCE_ORDER.get(min_confidence, 0)
    engine = CheckEngine(L)
    summary = {}

    try:
        for ckey in scope:
            client = clients_db[ckey]
            detection = client.get("detection", {})
            dname = client.get("display_name", ckey)
            vendor = client.get("vendor", "?")

            L.append("─" * 60)
            L.append(f"  SCAN: {dname}  ({vendor})")
            L.append("─" * 60)

            detected = False
            version = None
            configs_found = []
            process_found = False
            extension_confirmed = False

            # ── Layer 0: Detection ──────────────────────────────────────
            if check_local:
                process_found = _detect_by_process(detection, L)
                if process_found:
                    detected = True
                cfp = _detect_by_config(detection, L)
                if cfp:
                    configs_found = cfp
                    detected = True
                v = _detect_version(detection, L)
                if v:
                    detected = True
                    version = v
                # Extension-level verification (prevents shared process false positives)
                if detection.get("indicators"):
                    extension_confirmed = _detect_by_extension(detection, L)
                    if extension_confirmed:
                        detected = True

            if check_remote and scan_depth in ("standard", "full"):
                ri = _probe_remote(base_url, timeout, db, L)
                if ri:
                    detected = True
                    if "version" in ri:
                        version = ri["version"]
                    results["evidence"].append({
                        "type": "remote_probe", "client": ckey, "indicators": ri
                    })

            if not detected:
                L.append(f"  [-] Not detected")
                L.append("")
                continue

            # Detection confidence — require stronger evidence for extension clients
            det_score = _calc_detection_score(process_found, configs_found, version, extension_confirmed)
            client_type = client.get("type", "")
            if client_type == "ide_extension" and det_score < 2 and not extension_confirmed:
                L.append(f"  [~] Weak detection (score {det_score}) — process only, extension not confirmed. Skipping.")
                L.append("")
                continue

            ver_label = version or "unknown"
            L.append(f"  [+] Detected (score: {det_score}) — version: {ver_label}")

            # ── Config audit ────────────────────────────────────────────
            if check_local and configs_found and scan_depth in ("standard", "full"):
                cfg_risks = _audit_configs(configs_found, db, L)
                for risk in cfg_risks:
                    results["findings"].append({
                        "title": f"Config Risk — {dname}: {risk['description']}",
                        "severity": risk["severity"],
                        "confidence": "high",
                        "description": f"Pattern in {risk['file']}: {risk['description']}"
                                       + (f" (→ {risk['related_cve']})" if risk.get("related_cve") else ""),
                        "remediation": "Review and sanitize MCP config files.",
                        "cve": risk.get("related_cve", "config"),
                        "client": dname,
                    })

            # ── Per-CVE multi-layer verification ────────────────────────
            matched_count = 0
            for cve in client.get("cves", []):
                sev = str(cve.get("severity", "low")).lower()
                if _SEVERITY_ORDER.get(sev, 0) < min_sev_val:
                    continue

                cve_id = cve.get("id", "?")
                title = cve.get("title", "?")

                # Layer 1: Version correlation
                ver_matched = _version_matches(version, cve.get("affected_versions", ""))
                if not ver_matched:
                    L.append(f"  [·] {cve_id}: Not affected (fixed: {cve.get('fixed_version', '?')}, have: {ver_label})")
                    continue

                L.append(f"  [▸] {cve_id}: {title}")

                # Layer 2: Environment checks
                env_confirmed = False
                env_results = []
                if scan_depth in ("standard", "full") and cve.get("env_checks"):
                    L.append(f"    ── Layer 2: Environment Checks ──")
                    env_confirmed, env_results = engine.run_checks(cve["env_checks"])

                # Layer 3: Active verification
                active_confirmed = False
                active_results = []
                if scan_depth == "full" and cve.get("active_checks"):
                    L.append(f"    ── Layer 3: Active Verification ──")
                    active_confirmed, active_results = engine.run_checks(cve["active_checks"])

                # Calculate confidence
                confidence = _calc_confidence(
                    version_known=bool(version),
                    version_matched=ver_matched,
                    env_confirmed=env_confirmed,
                    active_confirmed=active_confirmed,
                )

                # Filter by min confidence
                if _CONFIDENCE_ORDER.get(confidence, 0) < min_conf_val:
                    L.append(f"    → Skipped (confidence: {confidence} < min: {min_confidence})")
                    continue

                matched_count += 1
                L.append(f"    → CONFIDENCE: {confidence.upper()} — {_CONFIDENCE_LABELS[confidence]}")

                results["findings"].append({
                    "title": f"{cve_id}: {title}",
                    "severity": sev,
                    "confidence": confidence,
                    "description": (
                        f"[{dname}] {cve.get('description', '')} "
                        f"| CVSS: {cve.get('cvss', 'N/A')} "
                        f"| CWE: {cve.get('cwe', 'N/A')} "
                        f"| Affected: {cve.get('affected_versions', '?')} "
                        f"| Fixed: {cve.get('fixed_version', '?')}"
                    ),
                    "remediation": cve.get("remediation", "Update to latest version."),
                    "cve": cve_id,
                    "cvss": cve.get("cvss"),
                    "cwe": cve.get("cwe"),
                    "references": cve.get("references", []),
                    "client": dname,
                    "reported_by": cve.get("reported_by", ""),
                    "disclosure_date": cve.get("disclosure_date", ""),
                    "verification": {
                        "version_known": bool(version),
                        "version_matched": ver_matched,
                        "env_checks": env_results,
                        "active_checks": active_results,
                    },
                })

            results["evidence"].append({
                "type": "client_scan",
                "client": dname,
                "key": ckey,
                "version": version,
                "detection_score": det_score,
                "cves_matched": matched_count,
                "cves_total": len(client.get("cves", [])),
                "configs": configs_found,
            })
            summary[dname] = {"version": ver_label, "matched": matched_count,
                              "total": len(client.get("cves", [])),
                              "det_score": det_score}
            L.append("")

        # ── Summary ─────────────────────────────────────────────────────
        scan_end = datetime.datetime.now(datetime.timezone.utc)
        duration = (scan_end - scan_start).total_seconds()

        L.append("═" * 70)
        L.append("  RESULTS SUMMARY")
        L.append("═" * 70)

        if summary:
            L.append(f"  {'Client':<32s} {'Version':<14s} {'Det':>3s} {'Matched':>7s}  Status")
            L.append("  " + "─" * 66)
            for name, info in summary.items():
                st = "VULNERABLE" if info["matched"] > 0 else "CLEAN"
                L.append(f"  {name:<32s} {info['version']:<14s} "
                         f"{info['det_score']:>3d} "
                         f"{info['matched']}/{info['total']:>5}  [{st}]")
        else:
            L.append("  No MCP clients detected.")

        # Confidence breakdown
        conf_counts = {}
        for f in results["findings"]:
            c = f.get("confidence", "low")
            conf_counts[c] = conf_counts.get(c, 0) + 1

        sev_counts = {}
        for f in results["findings"]:
            s = f.get("severity", "low")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        L.append("")
        L.append(f"  Total findings : {len(results['findings'])}")
        L.append(f"  By severity    : "
                 f"{sev_counts.get('critical',0)} critical, "
                 f"{sev_counts.get('high',0)} high, "
                 f"{sev_counts.get('medium',0)} medium, "
                 f"{sev_counts.get('low',0)} low")
        L.append(f"  By confidence  : "
                 f"{conf_counts.get('confirmed',0)} confirmed, "
                 f"{conf_counts.get('high',0)} high, "
                 f"{conf_counts.get('medium',0)} medium, "
                 f"{conf_counts.get('low',0)} low")
        L.append("")
        L.append(f"  Scan ID        : {scan_id}")
        L.append(f"  Duration       : {duration:.1f}s")
        L.append(f"  Completed      : {scan_end.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        L.append(f"  DB version     : {db.get('schema_version', '?')}")
        L.append("═" * 70)

        # ── Structured scan report (for AEGIS report engine) ────────────
        results["evidence"].append({
            "type": "scan_report",
            "scan_id": scan_id,
            "started": scan_start.isoformat(),
            "completed": scan_end.isoformat(),
            "duration_seconds": round(duration, 2),
            "platform": f"{platform.system()} {platform.release()}",
            "target": base_url,
            "scan_depth": scan_depth,
            "db_path": db_path,
            "db_schema_version": db.get("schema_version", "?"),
            "clients_scanned": len(scope),
            "clients_detected": len(summary),
            "total_findings": len(results["findings"]),
            "severity_breakdown": dict(sev_counts),
            "confidence_breakdown": dict(conf_counts),
            "summary": summary,
        })

        results["success"] = True

    except Exception as e:
        L.append(f"  [FATAL] {e}")
        import traceback
        L.append(traceback.format_exc())

    return results


# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    target = {
        "host": sys.argv[1] if len(sys.argv) > 1 else "localhost",
        "port": sys.argv[2] if len(sys.argv) > 2 else "8080",
        "protocol": sys.argv[3] if len(sys.argv) > 3 else "http",
    }
    params = {"scan_depth": "full", "client_hint": "auto",
              "check_local": True, "check_remote": True,
              "min_severity": "low", "min_confidence": "low"}

    result = execute(target, params, {"attack_id": "test"})

    print("\n".join(result["logs"]))
    print(f"\n{'─' * 60}")
    for f in result["findings"]:
        conf = f.get("confidence", "?").upper()
        print(f"  [{f['severity'].upper():8s}] [{conf:9s}] {f['title']}")
