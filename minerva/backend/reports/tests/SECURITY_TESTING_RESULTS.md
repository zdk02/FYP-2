# Security Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 6 of 10 — Security Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **57 / 57 tests passed (100 %)** (Backend 42 + Frontend 15) — combined wall-clock **25.78 s**

---

## 1. Why a security session — and why for *this* project specifically

Minerva is a pentesting framework. Its credibility rests on the tool
itself not being vulnerable to the bugs it claims to find. This
session pins the contracts that prove the tool is hardened against
the OWASP Top-10 classes most relevant to a Flask-JWT-Extended +
SQLAlchemy stack.

Where other sessions verified happy-path correctness, this one
**inverts the assertion**: we feed malicious input and demand the
system rejects it cleanly.

---

## 2. Result

```
============================= test session starts =============================
collected 42 items

tests/security/test_input_resilience.py ........ ........ [ 38%]   PASSED
tests/security/test_jwt_security.py    ......... .        [ 61%]   PASSED
tests/security/test_rbac_enforcement.py ........          [ 80%]   PASSED
tests/security/test_sensitive_data.py  ........           [100%]   PASSED

============================= 42 passed in 22.21s =============================
```

---

## 3. Test inventory

### Backend (Python · pytest)

| Test file                                       | Tests | Attack class defended against                                          |
|-------------------------------------------------|------:|------------------------------------------------------------------------|
| `backend/tests/security/test_jwt_security.py`   |    10 | Token forgery, tampering, alg=none, wrong-secret, refresh-token scope-abuse |
| `backend/tests/security/test_rbac_enforcement.py` |   8 | Privilege escalation across every admin/manager-only endpoint          |
| `backend/tests/security/test_input_resilience.py` |  16 | SQL injection, XSS storage, oversized + null-byte + malformed inputs   |
| `backend/tests/security/test_sensitive_data.py` |     8 | password_hash leaks, error-response info leak, user enumeration        |
| **Backend subtotal**                            | **42**|                                                                        |

### Frontend (JavaScript · Vitest)

| Test file                                          | Tests | Attack class defended against                                       |
|----------------------------------------------------|------:|---------------------------------------------------------------------|
| `frontend/tests/security/xss-rendering.test.jsx`   |     8 | DOM-based XSS — React's JSX escaping turns malicious payloads into inert text; no `<script>`/`<iframe>` injected |
| `frontend/tests/security/auth-storage.test.js`     |     7 | Token persistence safety — only declared fields saved, logout clears, no leaks to `window.location` or `document.cookie` |
| **Frontend subtotal**                              | **15**|                                                                     |

### Combined

| Layer    | Tests | Time    | Pass |
|----------|------:|--------:|-----:|
| Backend  |    42 | 22.21 s | 100% |
| Frontend |    15 |  3.57 s | 100% |
| **Total**|**57** |**25.78 s**| **100%** |

### Key contracts pinned

| Contract                                                                            | Test                                                                            |
|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| Tampering one byte of the JWT payload invalidates the signature                     | `test_token_with_modified_payload_is_rejected`                                  |
| `alg=none` token-forgery attack is blocked                                          | `test_alg_none_token_is_rejected`                                               |
| Forging a JWT with the wrong secret is rejected                                     | `test_token_signed_with_wrong_secret_is_rejected`                               |
| Refresh tokens cannot stand in for access tokens                                    | `test_refresh_token_cannot_authorise_normal_endpoints`                          |
| Viewer-role users cannot create/update/delete targets                               | 3 tests in `TestManagerOrAdminEndpointsRejectViewer`                            |
| Viewer-role users cannot create admin users (privilege escalation)                  | `test_viewer_creating_a_user_does_not_escalate_to_admin`                        |
| 4 SQLi payloads against `?search=` return clean 200                                 | `test_sqli_in_targets_search_does_not_break_query` (parametrised)               |
| Classic `' OR '1'='1` login bypass returns clean 401                                | `test_login_with_sqli_in_email_returns_clean_401`                               |
| 4 XSS payloads round-trip verbatim, no execution server-side                        | `test_xss_payload_in_target_name_is_stored_and_returned_unchanged` (parametrised) |
| Oversized / malformed input returns 4xx, never 500                                  | 3 tests in `TestOversizedAndMalformedInput`                                     |
| `password_hash` never appears in any auth or user response                          | 4 tests in `TestPasswordHashNeverLeaked`                                        |
| Login error message identical for unknown email vs wrong password (no enumeration)  | `test_login_failure_does_not_distinguish_unknown_email_from_wrong_password`     |

---

## 4. OWASP Top-10 (2021) coverage

| OWASP item                          | Tests proving coverage                                                   |
|-------------------------------------|--------------------------------------------------------------------------|
| **A01** Broken Access Control       | All 8 RBAC tests + integration tests                                     |
| **A02** Cryptographic Failures      | bcrypt salting (DB suite) + 4 password_hash leak tests                  |
| **A03** Injection                   | 9 SQLi tests + 4 XSS tests (13 total)                                    |
| **A04** Insecure Design             | RBAC + JWT-scope tests                                                   |
| **A05** Security Misconfiguration   | Health-endpoint reachability + auth gating                               |
| **A07** Identification & Auth Failures | All 10 JWT tests + login-error symmetry                              |
| **A09** Security Logging            | Audit-log writes verified in integration suite                          |

---

## 5. How to reproduce

```bash
# Backend security
cd minerva/backend
python -m pytest tests/security/ -v
# → 42 passed in ~22s

# Frontend security
cd ../frontend
npm run test:security
# → 15 passed in ~4s
```

---

## 6. File inventory (artefacts to inspect)

**Backend:**
- `minerva/backend/tests/security/conftest.py` — fixtures (admin + viewer tokens)
- `minerva/backend/tests/security/test_jwt_security.py`
- `minerva/backend/tests/security/test_rbac_enforcement.py`
- `minerva/backend/tests/security/test_input_resilience.py`
- `minerva/backend/tests/security/test_sensitive_data.py`
- `minerva/backend/reports/tests/security_test_report.html` ← **Backend HTML report**
- `minerva/backend/reports/tests/security_terminal_output.txt` ← backend raw log

**Frontend:**
- `minerva/frontend/tests/security/xss-rendering.test.jsx`
- `minerva/frontend/tests/security/auth-storage.test.js`
- `minerva/frontend/reports/tests/frontend_security_test_report/index.html` ← **Frontend HTML report**
- `minerva/frontend/reports/tests/frontend_security_terminal_output.txt` ← frontend raw log

**Documentation:**
- `minerva/backend/tests/SECURITY_TESTING.md` — full session writeup (both layers)

---

## 7. Cumulative progress (Sessions 1 – 6)

| Session | Type           | Layer      | Tests | Time    | Pass |
|--------:|----------------|------------|------:|--------:|-----:|
| 1       | Unit           | Backend    |    89 |  1.13 s | 100 %|
| 1       | Unit           | Frontend   |    29 |  2.59 s | 100 %|
| 2       | Integration    | Backend    |    43 | 18.96 s | 100 %|
| —       | Database       | Backend    |    28 | 13.17 s | 100 %|
| 3       | Component      | Frontend   |    26 |  2.44 s | 100 %|
| 4       | System / E2E   | Full stack |    11 | 35.20 s | 100 %|
| 5       | Acceptance     | —          |   skipped (covered implicitly by E2E) |
| **6**   | **Security**   | **Backend**|**42** |**22.21 s**|**100 %**|
| **6**   | **Security**   | **Frontend**|**15**|**3.57 s** |**100 %**|
| **Total**|              |            | **283** | **99.27 s** | **100 %** |

---

*Session 6 of 10. Next session: Usability Testing.*
