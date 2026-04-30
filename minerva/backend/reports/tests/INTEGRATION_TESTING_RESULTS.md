# Integration Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Session 2 of 10 — Integration Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **43 / 43 tests passed (100%)** — wall-clock **18.96 s**

---

## 1. What integration testing means here

Integration tests verify that **multiple components cooperate
correctly**. Each test issues a real HTTP request against a freshly-
built Flask app backed by an **in-memory SQLite database**. The full
vertical is exercised:

```
HTTP request
   → Flask blueprint + route
       → @jwt_required decoder (Flask-JWT-Extended)
           → @require_role permission check
               → SQLAlchemy ORM query
                   → SQLite (in-memory)
               ← ORM result
           ← Permission OK / 403
       ← JWT decoded / 401
   ← JSON response
```

No external services (Redis, real Postgres, live MCP target servers)
are involved — purely backend-internal integration.

---

## 2. Result

```
============================= test session starts =============================
platform win32 -- Python 3.13 -- pytest-9.0.3
collected 43 items

tests/integration/test_attacks_listing.py ........ [ 18%]   PASSED
tests/integration/test_auth_flow.py    ........ ........  [ 55%]   PASSED
tests/integration/test_health.py       ..               [ 60%]   PASSED
tests/integration/test_targets_crud.py ........ ........ [100%]   PASSED

============================= 43 passed in 18.96s =============================
```

---

## 3. Test inventory

| Test file                                | Tests | Vertical exercised                                            |
|------------------------------------------|------:|---------------------------------------------------------------|
| `tests/integration/test_health.py`       |     2 | App boot, blueprint registration, 404 JSON handler            |
| `tests/integration/test_auth_flow.py`    |    16 | Login, JWT issue, `/auth/me`, refresh token, logout, change-password |
| `tests/integration/test_targets_crud.py` |    17 | Targets CRUD, validation rules, role-based delete             |
| `tests/integration/test_attacks_listing.py` |  8 | Attacks list + filters + metadata catalogues, all JWT-gated   |
| **Total**                                | **43**|                                                               |

### Key contracts pinned by these tests

| Contract                                                            | Test that proves it                                                          |
|---------------------------------------------------------------------|------------------------------------------------------------------------------|
| Login returns access + refresh tokens                               | `test_login_with_correct_credentials_returns_tokens`                         |
| Wrong password returns 401, not 500                                 | `test_login_with_wrong_password_returns_401`                                  |
| `/auth/me` requires a valid JWT                                     | `test_me_without_token_returns_401`                                           |
| Refresh tokens cannot be used as access tokens                      | `test_refresh_with_access_token_is_rejected`                                  |
| Password change persists across logins                              | `test_change_password_succeeds_with_correct_current_password`                 |
| Targets created via API are retrievable via API                     | `test_created_target_appears_in_list`                                         |
| Validation rules enforce required fields                            | `test_create_target_without_name_returns_400`                                 |
| Protocol-specific validation works                                  | `test_stdio_target_requires_base_url`                                         |
| `viewer` role cannot delete targets (RBAC at HTTP layer)             | `test_viewer_cannot_delete_target`                                            |
| Every `/attacks` endpoint requires authentication                   | `test_unauthenticated_request_is_rejected`                                    |

---

## 4. How to reproduce

From `minerva/backend/`:

```bash
# Activate venv (Windows PowerShell)
..\..\venv312\Scripts\Activate.ps1

# Run all integration tests + HTML report
python -m pytest tests/integration/ -m integration -v \
  --html=reports/tests/integration_test_report.html --self-contained-html
```

Expected output: `43 passed in ~19s`.

---

## 5. File inventory (artefacts to inspect)

- `minerva/backend/tests/integration/conftest.py` — fixtures (app, client, admin_token, viewer_user)
- `minerva/backend/tests/integration/test_health.py`
- `minerva/backend/tests/integration/test_auth_flow.py`
- `minerva/backend/tests/integration/test_targets_crud.py`
- `minerva/backend/tests/integration/test_attacks_listing.py`
- `minerva/backend/reports/tests/integration_test_report.html` ← **HTML report**
- `minerva/backend/reports/tests/integration_terminal_output.txt` ← raw run log
- `minerva/backend/tests/INTEGRATION_TESTING.md` — full session writeup

---

## 6. Cumulative progress (Sessions 1 + 2)

| Session | Type        | Layer    | Tests | Time    | Pass |
|--------:|-------------|----------|------:|--------:|-----:|
| 1       | Unit        | Backend  |    89 |  1.13 s | 100% |
| 1       | Unit        | Frontend |    29 |  2.59 s | 100% |
| 2       | Integration | Backend  |    43 | 18.96 s | 100% |
| **Total** |           |          | **161** | **22.68 s** | **100%** |

---

*Session 2 of 10 in the Minerva FYP testing programme. Next session: Component Testing.*
