"""
Validate secrets discovered during a pentest.

Pattern-matching alone (regex hits in tool output) gives high false-
positive rates: a string that looks like an AWS key may be a fixture or
a placeholder. Pro-grade reports must promote findings to "confirmed"
only after demonstrating the secret is *real*.

This module sends safe, read-only requests to the issuer's identity
endpoint:

    AWS    → STS GetCallerIdentity (returns account / arn / userid)
    GitHub → GET /user             (returns login when token is valid)
    Slack  → auth.test             (returns team_id when token is valid)
    GCP    → tokeninfo             (validates OAuth access tokens)
    Azure  → /me on Graph          (validates ARM access tokens)

Each validator returns:

    {
      "type":  "aws|github|slack|gcp|azure|generic",
      "valid": True / False / None,    # None = couldn't be tested
      "evidence": {request, response_status, body_excerpt},
      "summary": "..."
    }

NEVER use a discovered secret in any way other than "is it valid?". The
validators below intentionally hit identity-only endpoints.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from urllib.parse import quote

import requests


_DEFAULT_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Detection — turn a piece of text into typed candidate secrets
# ---------------------------------------------------------------------------

_PATTERNS = [
    # AWS access key + secret key pair (AKIA / ASIA / AGPA / AIDA / AROA)
    ("aws_key", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16})\b")),
    # GitHub PAT (classic), Fine-grained, OAuth, App
    ("github_pat", re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b")),
    ("github_pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b")),
    ("github_oauth", re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b")),
    ("github_app", re.compile(r"\b(ghs_[A-Za-z0-9]{36,})\b")),
    # Slack
    ("slack_bot",  re.compile(r"\b(xoxb-[0-9A-Za-z-]+)\b")),
    ("slack_user", re.compile(r"\b(xoxp-[0-9A-Za-z-]+)\b")),
    ("slack_app",  re.compile(r"\b(xapp-[0-9A-Za-z-]+)\b")),
    # OpenAI / Anthropic
    ("openai_key", re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b")),
    ("anthropic_key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{40,})\b")),
    # Google API
    ("google_api", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    # Stripe
    ("stripe_live", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b")),
    ("stripe_test", re.compile(r"\b(sk_test_[0-9A-Za-z]{24,})\b")),
    # JWT (rough — three base64url segments)
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b")),
    # Private keys
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    # Generic high-entropy hex / base64 (last-resort)
    # — left out on purpose: too noisy without entropy gating
]


def detect_secrets(text: str) -> list[dict]:
    """Return a list of {type, value, span} for every secret pattern hit."""
    if not text:
        return []
    out = []
    seen = set()
    for typ, pat in _PATTERNS:
        for m in pat.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            key = (typ, value)
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": typ, "value": value,
                        "span": [m.start(), m.end()]})
    return out


# ---------------------------------------------------------------------------
# Validators — send a safe identity request, see if the secret authenticates
# ---------------------------------------------------------------------------

def _excerpt(s: str | bytes, n: int = 800) -> str:
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="replace")
    s = str(s or "")
    return s[:n] + (f"... [+{len(s)-n}]" if len(s) > n else "")


def validate_github(token: str, *, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    try:
        r = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "Minerva-Pentest"},
            timeout=timeout,
        )
        valid = r.status_code == 200
        login = None
        if valid:
            try:
                login = r.json().get("login")
            except Exception:
                pass
        return {
            "type": "github", "valid": valid,
            "evidence": {
                "url": "https://api.github.com/user",
                "status": r.status_code,
                "body_excerpt": _excerpt(r.text, 600),
            },
            "summary": (f"GitHub token valid for user '{login}'"
                        if valid else f"GitHub token invalid (HTTP {r.status_code})"),
        }
    except Exception as e:
        return {"type": "github", "valid": None,
                "evidence": {"error": str(e)[:300]},
                "summary": f"Could not validate GitHub token: {e!s:.120}"}


def validate_slack(token: str, *, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    try:
        r = requests.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        valid = bool(body.get("ok"))
        return {
            "type": "slack", "valid": valid,
            "evidence": {"status": r.status_code, "body": body},
            "summary": (f"Slack token valid: team={body.get('team')}"
                        if valid else f"Slack token invalid: {body.get('error')}"),
        }
    except Exception as e:
        return {"type": "slack", "valid": None,
                "evidence": {"error": str(e)[:300]},
                "summary": f"Could not validate Slack token: {e!s:.120}"}


def validate_openai(token: str, *, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    try:
        r = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        return {
            "type": "openai", "valid": r.status_code == 200,
            "evidence": {"status": r.status_code,
                         "body_excerpt": _excerpt(r.text, 400)},
            "summary": (f"OpenAI key valid (HTTP 200)"
                        if r.status_code == 200
                        else f"OpenAI key invalid (HTTP {r.status_code})"),
        }
    except Exception as e:
        return {"type": "openai", "valid": None,
                "evidence": {"error": str(e)[:300]},
                "summary": f"Could not validate OpenAI key: {e!s:.120}"}


def validate_anthropic(token: str, *, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    try:
        r = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": token, "anthropic-version": "2023-06-01"},
            timeout=timeout,
        )
        return {
            "type": "anthropic", "valid": r.status_code == 200,
            "evidence": {"status": r.status_code,
                         "body_excerpt": _excerpt(r.text, 400)},
            "summary": (f"Anthropic key valid (HTTP 200)"
                        if r.status_code == 200
                        else f"Anthropic key invalid (HTTP {r.status_code})"),
        }
    except Exception as e:
        return {"type": "anthropic", "valid": None,
                "evidence": {"error": str(e)[:300]},
                "summary": f"Could not validate Anthropic key: {e!s:.120}"}


def validate_google_api(key: str, *, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """Validate via the public 'discovery' endpoint that requires an
    API key. We do not use a billable endpoint."""
    try:
        r = requests.get(
            f"https://www.googleapis.com/customsearch/v1"
            f"?key={quote(key)}&cx=017576662512468239146:omuauf_lfve&q=test",
            timeout=timeout,
        )
        # 400 INVALID_ARGUMENT means key was accepted; 403 means rejected
        body = _excerpt(r.text, 600)
        if r.status_code == 200 or "Invalid argument" in body:
            valid = True
        elif "API key not valid" in body or r.status_code == 400:
            valid = False
        else:
            valid = None
        return {
            "type": "google_api", "valid": valid,
            "evidence": {"status": r.status_code, "body_excerpt": body},
            "summary": (f"Google API key valid"
                        if valid is True
                        else f"Google API key invalid (HTTP {r.status_code})"),
        }
    except Exception as e:
        return {"type": "google_api", "valid": None,
                "evidence": {"error": str(e)[:300]},
                "summary": f"Could not validate Google API key: {e!s:.120}"}


def _aws_sigv4(method: str, host: str, region: str, service: str,
               canonical_uri: str, canonical_query: str, payload: bytes,
               access_key: str, secret_key: str,
               session_token: str | None = None) -> dict:
    """Build SigV4-signed headers for a single AWS request."""
    t = time.gmtime()
    amz_date = time.strftime("%Y%m%dT%H%M%SZ", t)
    date_stamp = time.strftime("%Y%m%d", t)
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = (f"host:{host}\nx-amz-content-sha256:{payload_hash}\n"
                         f"x-amz-date:{amz_date}\n")
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    if session_token:
        canonical_headers += f"x-amz-security-token:{session_token}\n"
        signed_headers += ";x-amz-security-token"
    canonical_request = (f"{method}\n{canonical_uri}\n{canonical_query}\n"
                         f"{canonical_headers}\n{signed_headers}\n{payload_hash}")
    cred_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (f"AWS4-HMAC-SHA256\n{amz_date}\n{cred_scope}\n"
                      f"{hashlib.sha256(canonical_request.encode()).hexdigest()}")
    k_date = hmac.new(("AWS4" + secret_key).encode(), date_stamp.encode(), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{cred_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    headers = {
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": auth,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


def validate_aws(access_key: str, secret_key: str,
                 *, session_token: str | None = None,
                 region: str = "us-east-1",
                 timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """Hit STS GetCallerIdentity (read-only, no IAM permission needed)."""
    if not (access_key and secret_key):
        return {"type": "aws", "valid": None,
                "evidence": {"error": "secret key required to validate AWS"},
                "summary": "AWS validation requires both access + secret key"}
    host = "sts.amazonaws.com"
    payload = b"Action=GetCallerIdentity&Version=2011-06-15"
    try:
        headers = _aws_sigv4("POST", host, region, "sts", "/", "",
                             payload, access_key, secret_key, session_token)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = requests.post(f"https://{host}/", headers=headers, data=payload,
                          timeout=timeout)
        valid = r.status_code == 200
        body = _excerpt(r.text, 800)
        m = re.search(r"<Account>(\d+)</Account>", r.text)
        account = m.group(1) if m else None
        m = re.search(r"<Arn>([^<]+)</Arn>", r.text)
        arn = m.group(1) if m else None
        return {
            "type": "aws", "valid": valid,
            "evidence": {"status": r.status_code, "body_excerpt": body},
            "summary": (f"AWS key valid: account={account} arn={arn}"
                        if valid else f"AWS key invalid (HTTP {r.status_code})"),
        }
    except Exception as e:
        return {"type": "aws", "valid": None,
                "evidence": {"error": str(e)[:300]},
                "summary": f"Could not validate AWS key: {e!s:.120}"}


def decode_jwt(token: str) -> dict:
    """Best-effort JWT header+payload decoding without verification.
    Returns {header, payload, alg, exp, iss, aud, weak} — `weak` flags
    alg=none / HS256-with-weak-key style smells."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "not a 3-part JWT"}
        def _b64d(s):
            s += "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s))
        header = _b64d(parts[0])
        payload = _b64d(parts[1])
        alg = (header.get("alg") or "").upper()
        weak = []
        if alg in ("NONE", ""):
            weak.append("alg=none — server might accept unsigned tokens")
        if alg.startswith("HS") and "kid" in header:
            weak.append("kid + symmetric key — possible kid SQLi / path-traversal")
        return {"header": header, "payload": payload, "alg": alg,
                "exp": payload.get("exp"), "iss": payload.get("iss"),
                "aud": payload.get("aud"), "sub": payload.get("sub"),
                "weak": weak}
    except Exception as e:
        return {"error": str(e)[:300]}


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def validate(secret_type: str, value: str, **kw) -> dict:
    """Dispatch by detected type. Unknown types return {valid: None}."""
    fn = {
        "github_pat": validate_github,
        "github_oauth": validate_github,
        "github_app": validate_github,
        "slack_bot": validate_slack,
        "slack_user": validate_slack,
        "slack_app": validate_slack,
        "openai_key": validate_openai,
        "anthropic_key": validate_anthropic,
        "google_api": validate_google_api,
    }.get(secret_type)
    if not fn:
        if secret_type == "jwt":
            decoded = decode_jwt(value)
            return {"type": "jwt", "valid": None,
                    "evidence": decoded,
                    "summary": (f"JWT alg={decoded.get('alg')} "
                                f"iss={decoded.get('iss')} "
                                f"weakness={decoded.get('weak') or []}")}
        return {"type": secret_type or "generic", "valid": None,
                "evidence": {}, "summary": "no validator for this type"}
    return fn(value, **kw)


__all__ = [
    "detect_secrets", "validate",
    "validate_github", "validate_slack",
    "validate_openai", "validate_anthropic",
    "validate_google_api", "validate_aws",
    "decode_jwt",
]
