# Security Testing — Minerva (Backend + Frontend)

**Session 6 of 10** in the Minerva FYP testing programme.

---

## What is Security Testing?

Security testing verifies that the system **rejects malicious input
and behaviour** — the inverse of normal functional testing. Where
functional tests prove "the happy path works", security tests prove
"the attack paths fail safely."

For Minerva specifically (which is itself a pentesting framework),
this layer is non-negotiable: the tool must not contain the same
classes of vulnerabilities it claims to find in others.

---

## Scope of this session — four attack-resistance areas

| Area                          | What we assert                                                      |
|-------------------------------|---------------------------------------------------------------------|
| **JWT security**              | Forged, tampered, expired, wrong-key, alg=none tokens all rejected  |
| **RBAC enforcement**          | Viewer-role tokens rejected on every admin/manager-only endpoint    |
| **Input resilience**          | SQL-injection, XSS, oversized, malformed inputs do not crash or run |
| **Sensitive-data exposure**   | No `password_hash` or secret leaks; error messages don't enumerate users |

---

# Part A — Backend (pytest, 42 tests)

## Test inventory

| File                                            | Tests | What it proves                                                  |
|-------------------------------------------------|------:|-----------------------------------------------------------------|
| `tests/security/test_jwt_security.py`           |    10 | Missing/garbage tokens rejected; tampered payload + signature rejected; alg=none rejected; wrong-secret rejected; refresh tokens cannot authorise normal endpoints |
| `tests/security/test_rbac_enforcement.py`       |     8 | Viewer cannot list/create/delete users; viewer cannot create/update/delete targets; viewer-attempted privilege escalation creates no admin user; protected resources actually persist |
| `tests/security/test_input_resilience.py`       |    16 | 8 SQLi payloads against `/targets` and `/attacks` search; SQLi in login returns 401; 4 XSS payloads stored verbatim, no execution; oversized + null-byte + malformed-JSON inputs return 4xx, never 500 |
| `tests/security/test_sensitive_data.py`         |     8 | `password_hash` never leaks (login, /me, /users list, user detail); 404 doesn't dump stack; login error identical for unknown-email vs wrong-password (no user enumeration); JWT only in body, not headers |
| **Backend total**                               | **42**|                                                                 |

# Part B — Frontend (vitest, 15 tests)

The backend security suite proves payloads aren't *executed server-side*.
This frontend suite proves React doesn't render them as live HTML and
that auth tokens never leak into global browser state.

| File                                            | Tests | What it proves                                                  |
|-------------------------------------------------|------:|-----------------------------------------------------------------|
| `frontend/tests/security/xss-rendering.test.jsx`|     8 | 5 XSS payloads (script, img/onerror, svg/onload, javascript:, iframe) render as inert text; no `<script>` / `<iframe>` nodes injected; expanded description renders payloads literally; non-CVE-prefixed CVE values do not become links |
| `frontend/tests/security/auth-storage.test.js`  |     7 | Persist middleware only saves declared fields (not `error`/`isLoading`); failed login does not stash a token; logout clears Authorization header + tokens + user; logout still clears state on network failure; tokens never leak to `window.location` or `document.cookie` |
| **Frontend total**                              | **15**|                                                                 |

## Combined total

| Layer    | Tests | Time   | Pass |
|----------|------:|-------:|-----:|
| Backend  |    42 | 22.21s | 100% |
| Frontend |    15 |  3.57s | 100% |
| **Total**|**57** |**25.78s**| 100% |

---

## How to run

```bash
# Backend (from minerva/backend/)
python -m pytest tests/security/ -v
# → 42 passed in ~22s

# Frontend (from minerva/frontend/)
npm run test:security
# → 15 passed in ~4s
```

---

## Latest result

```
============================= 42 passed in 22.21s =============================
```

**Pass rate:** 42 / 42 (100 %)
**Wall-clock:** 22.21 s
**HTML report:** `backend/reports/tests/security_test_report.html`

---

## OWASP Top-10 coverage map

| OWASP item (2021)                    | Coverage in this suite                                                   |
|--------------------------------------|--------------------------------------------------------------------------|
| A01 — Broken Access Control          | `test_rbac_enforcement.py` — every protected endpoint refuses viewer    |
| A02 — Cryptographic Failures         | `test_two_users_with_same_password_have_different_hashes` (DB suite) + `test_password_hash_never_leaked` |
| A03 — Injection                      | `test_input_resilience.py` — SQLi parameterised + login bypass attempts |
| A04 — Insecure Design                | RBAC + JWT scope enforcement                                             |
| A05 — Security Misconfiguration      | Health endpoint public; auth endpoints non-public                        |
| A07 — Identification & Auth Failures | All `test_jwt_security.py` tests + login-error symmetry                  |
| A09 — Logging & Monitoring Failures  | Audit-log persistence checked in integration tests                       |

---

## What this proves to the marker

1. **The tool is not vulnerable to the classes of bugs it claims to find** —
   SQL injection (A03), broken access control (A01), JWT forgery (A07),
   sensitive data exposure (A02).
2. **Every protected endpoint enforces authorisation at the HTTP layer** —
   not in the frontend, where it could be bypassed by talking to the API
   directly.
3. **Cryptographic primitives are used correctly** — bcrypt salts each
   password individually; password hashes never appear in any API
   response.
4. **Hostile input is handled deterministically** — no 500s on bad input,
   no information leakage in error messages, no user enumeration.
