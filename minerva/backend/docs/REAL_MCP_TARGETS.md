# Minerva — Testing Real MCP Servers

This doc gives you concrete, reproducible commands to stand up real
open-source MCP servers that organisations actually use in production,
then point the Minerva framework at them.

> **Ethics first.** Every server below is either (a) run by you in your
> own sandbox, or (b) your own deployment. **Do not point Minerva at a
> production MCP server you do not own or have written authorisation
> to test.** Unauthorised testing is illegal in most jurisdictions.

---

## Quick reference — servers covered

| Tier | Server | Transport | Typical vulns Minerva finds |
|------|--------|-----------|-----------------------------|
| Anthropic reference | `@modelcontextprotocol/server-filesystem` | stdio | Path traversal (if base-dir escape), arbitrary file write/read |
| Anthropic reference | `@modelcontextprotocol/server-github` | stdio + HTTP | Credential leakage in responses, auth bypass on GitHub token, SSRF via issue fetch |
| Anthropic reference | `@modelcontextprotocol/server-sqlite` | stdio | SQL injection, info disclosure via schema leak |
| Anthropic reference | `@modelcontextprotocol/server-puppeteer` | stdio | SSRF, potential RCE via `evaluate()`, info disclosure |
| Anthropic reference | `@modelcontextprotocol/server-sentry` | HTTP | Token leakage, SSRF |
| Community | `@modelcontextprotocol/server-brave-search` | stdio | API-key leakage, SSRF via webhook |
| Community | `mcp-remote` (proxy for remote MCP) | HTTP → upstream | Acts as a test harness for all Data-in-Transit attacks |
| Custom | Your own Flask / Node MCP server | any | Whatever you built |

---

## Setup prereqs

```bash
# Node + npm
node --version    # 20+
# Python for the Python-implementation servers
python3 --version # 3.11+
# Minerva framework running
cd minerva/backend && python run.py          # :5000
cd minerva/frontend && npm run dev           # :5173
# Optional: public callback URL for OOB attacks
export MINERVA_OOB_URL=https://$(ngrok http 5000 --log=stdout | head)
```

Log in at http://localhost:5173 as `admin@minerva.local / admin123`.

---

## 1. `@modelcontextprotocol/server-filesystem` — stdio

The reference filesystem MCP server. Pentester angle: path traversal
outside the advertised root, write-to-SSH-key style persistence.

```bash
# Pick a sandbox dir
mkdir -p /tmp/mcp-fs-lab
echo "canary" > /tmp/mcp-fs-lab/canary.txt

# Run the server manually to check it works
npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-fs-lab
# It will wait for JSON-RPC on stdin — Ctrl+C to exit
```

Register in Minerva **Targets → + Add Target**:

```json
{
  "name": "fs-server (stdio)",
  "target_type": "mcp_server",
  "host": "localhost",
  "port": 0,
  "protocol": "stdio",
  "base_url": "stdio:npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-fs-lab",
  "auth_type": "none"
}
```

Attacks to run:
- **Path Traversal / LFI (Pro)** — `only_tool_names=["read_file"]`
- **File-Based Injection (Addition / Modification / Deletion)**
- **Tool Poisoning (Pro)** — any zero-width content smuggled in file names?
- **Information Disclosure (Pro)** — verbose stderr leakage?

---

## 2. `@modelcontextprotocol/server-sqlite` — stdio

Exposes a SQLite DB via tools that accept raw SQL. Ideal for demoing
SQL Injection + error disclosure.

```bash
# Create a demo DB
sqlite3 /tmp/mcp-demo.db <<'SQL'
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, pwd TEXT);
INSERT INTO users (name, pwd) VALUES ('alice','hunter2'),('admin','correcthorse');
SQL
```

Register:

```json
{
  "name": "sqlite-mcp (stdio)",
  "target_type": "mcp_server",
  "protocol": "stdio",
  "base_url": "stdio:npx -y @modelcontextprotocol/server-sqlite --db /tmp/mcp-demo.db"
}
```

Attacks: **SQL Injection (Pro)**, **SQL Injection** (refined),
**Information Disclosure**, **Server Code Leakage**.

---

## 3. `@modelcontextprotocol/server-github` — HTTP (or stdio wrapper)

Requires a personal-access token. **Use a token limited to a
throw-away test repo you own.** Never the token from your primary
account.

```bash
export GITHUB_PAT="ghp_yourThrowawayToken"
npx -y @modelcontextprotocol/server-github
```

Register as MCP Target with:

- `auth_type: bearer`
- `token: $GITHUB_PAT`

Attacks to run:
- **Authentication Bypass (Pro)** — confirms the token is required
- **MCP Credential Theft** — can the GitHub token leak back?
- **SSRF (Pro)** — `fetch_issue` often accepts URLs
- **Tool Poisoning (Pro)** — does a malicious issue description inject into the LLM?
- **Indirect Prompt Injection** — same via issue body fetched via resources.

---

## 4. `@modelcontextprotocol/server-puppeteer` — stdio

Headless browser MCP. SSRF + RCE via `page.evaluate()` are the classic
vulnerabilities.

```bash
npx -y @modelcontextprotocol/server-puppeteer
```

Register as stdio target. Attacks:
- **SSRF (Pro)** — cloud metadata probes via `navigate` tool
- **Remote Code Execution (Pro)** — evaluate-on-page sink
- **Information Disclosure (Pro)** — secret leak in browser output

---

## 5. `mcp-remote` — HTTP proxy

Turns any stdio MCP into an HTTP-reachable MCP. Useful when you want
to run Minerva against a server that's normally stdio-only, or to
demonstrate the MITM attacks.

```bash
npx -y mcp-remote --target "npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-fs-lab" --port 4001
```

Register:

```json
{
  "name": "fs-over-http",
  "host": "localhost", "port": 4001, "protocol": "http",
  "base_url": "http://localhost:4001"
}
```

Attacks: **MCP MITM (Pro)** (active + passive), **Data-in-Transit**,
plus everything the underlying stdio server is vulnerable to.

---

## 6. Your Minerva Multi-MCP Lab (offline, closed network)

Minerva ships a 4-server vulnerable lab for offline demos. Run:

```bash
cd minerva/backend
python -m scripts.demo_lab
#   SQL-heavy MCP    http://127.0.0.1:8701/mcp
#   Filesystem MCP   http://127.0.0.1:8702/mcp
#   Runtime MCP      http://127.0.0.1:8703/mcp
#   Protected MCP    http://127.0.0.1:8704/mcp  (needs auth)
```

Register all four as Minerva targets (Admin → Targets), then create
a Campaign with the 44-attack pack against all of them, and
**Generate Report** — the report engine will produce a single
HTML/PDF/JSON/SARIF covering the whole environment.

---

## 7. Real-world targets to test (with permission)

For your startup / FYP demo, these organisations ship production MCP
servers you can responsibly test **if you have authorisation**:

- **Linear MCP** (`https://mcp.linear.app/sse`) — bearer auth
- **Slack MCP** (`https://mcp.slack.com/mcp`) — OAuth2
- **Sentry MCP** (`https://mcp.sentry.dev/mcp`) — bearer
- **Cloudflare MCP** (`https://observability.mcp.cloudflare.com/mcp`) — oauth
- **Square MCP** (via `mcp-remote`) — OAuth2 flow

For a bug-bounty / responsible-disclosure program, check each
vendor's security.txt and scope before running. Start with **read-only
discovery** (Target → "Test Connection" button runs MCP `initialize +
tools/list` only) before running any exploit-class attack.

---

## Attack matrix — which attack for which server?

The framework auto-selects candidates per attack class, but here's
the quick map:

| Server type | High-signal attacks |
|-------------|---------------------|
| Filesystem  | Path Traversal · File-Based Injection (4) · Tool Poisoning |
| SQL / DB    | SQL Injection (Pro + refined) · Information Disclosure · Configuration Drift |
| Code / eval | RCE (Pro + refined) · Insecure Deserialization · Command Injection |
| Browser     | SSRF (Pro) · RCE · Information Disclosure |
| Chat / LLM  | Direct / Indirect Prompt Injection · LLM Jailbreak · Tool Poisoning · Infectious Attack |
| Transit     | MCP MITM (Pro active + posture) · Tool Rebinding |
| Any         | Authentication Bypass · Tool Shadowing · Tool Name Conflict · MCP Server Backdoor Discovery |

---

## Reporting responsibly

If you find a real vulnerability in a production MCP server:

1. **Stop** further exploitation immediately.
2. Save the Minerva report (HTML + SARIF) as timestamped evidence.
3. Check the vendor's `security.txt` / bug-bounty scope.
4. Disclose privately before publishing.

Minerva's report format is designed to double as a responsible-
disclosure artifact: the HTML + PDF contain everything a vendor
security team needs to reproduce and remediate.
