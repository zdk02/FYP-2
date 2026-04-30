# Database Testing — Completion Report

**Project:** Minerva — MCP Pentesting Framework (Final Year Project)
**Test phase:** Bonus session — Database Testing
**Date executed:** 2026-04-30
**Outcome:** ✅ **28 / 28 tests passed (100 %)** — wall-clock **13.17 s**

---

## 1. Why a separate database session?

Integration tests (Session 2) already exercise the database through the
API. But the question *"did you test the database itself?"* deserves a
direct answer. This session proves the **schema-level contracts** —
constraints, defaults, relationships, cascades — independent of any
HTTP routing.

```
Test  →  SQLAlchemy ORM  →  in-memory SQLite  →  IntegrityError on violation
```

---

## 2. Result

```
============================= test session starts =============================
platform win32 -- Python 3.13 -- pytest-9.0.3
collected 28 items

tests/database/test_relationships.py ...... [ 21%]   PASSED
tests/database/test_target_model.py ........ [ 50%]   PASSED
tests/database/test_user_model.py ......... ..... [100%]   PASSED

============================= 28 passed in 13.17s =============================
```

---

## 3. Test inventory

| Test file                                       | Tests | Schema contracts pinned                                                 |
|-------------------------------------------------|------:|-------------------------------------------------------------------------|
| `tests/database/test_user_model.py`             |    14 | UNIQUE on username + email; NOT NULL on username/email/password_hash; default `role='operator'`; default `is_active=True`; auto `created_at`; nullable `last_login`; bcrypt hashing + salting |
| `tests/database/test_target_model.py`           |     8 | NOT NULL on name + target_type; default `is_active=True`; auto `created_at`; `updated_at` bumps on UPDATE; JSON text round-trip for `auth_config` and `tags` |
| `tests/database/test_relationships.py`          |     6 | User → AuditLog (action NOT NULL, user_id nullable); Target → DiscoveredEndpoint cascade delete; endpoint requires target_id |
| **Total**                                       | **28**|                                                                         |

### Key contracts pinned by these tests

| Contract                                                                            | Test that proves it                                                              |
|-------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| Two users cannot share a username                                                   | `test_duplicate_username_raises_integrity_error`                                 |
| Two users cannot share an email                                                     | `test_duplicate_email_raises_integrity_error`                                    |
| Inserting a user without password_hash is rejected                                  | `test_missing_password_hash_raises_integrity_error`                              |
| Passwords are never stored in plaintext                                             | `test_set_password_does_not_store_plaintext`                                     |
| Bcrypt salts each password individually (same plaintext → different hashes)         | `test_two_users_with_same_password_have_different_hashes`                        |
| Deleting a Target removes all of its DiscoveredEndpoint rows (no orphans)           | `test_deleting_target_cascades_to_its_endpoints`                                 |
| `updated_at` auto-bumps on every UPDATE                                             | `test_updated_at_changes_on_update`                                              |
| JSON-encoded `auth_config` survives a round-trip through the database               | `test_auth_config_json_persists_and_parses_back`                                 |
| System-generated audit logs (no user) are allowed                                   | `test_audit_log_user_id_is_optional`                                             |

---

## 4. How to reproduce

From `minerva/backend/`:

```bash
# Activate venv (Windows PowerShell)
..\..\venv312\Scripts\Activate.ps1

# Run all DB tests + HTML report
python -m pytest tests/database/ -v \
  --html=reports/tests/database_test_report.html --self-contained-html
```

Expected output: `28 passed in ~13s`.

---

## 5. File inventory (artefacts to inspect)

- `minerva/backend/tests/database/conftest.py` — fixtures (app + session)
- `minerva/backend/tests/database/test_user_model.py`
- `minerva/backend/tests/database/test_target_model.py`
- `minerva/backend/tests/database/test_relationships.py`
- `minerva/backend/reports/tests/database_test_report.html` ← **HTML report**
- `minerva/backend/reports/tests/database_terminal_output.txt` ← raw run log
- `minerva/backend/tests/DATABASE_TESTING.md` — full session writeup

---

## 6. Cumulative progress (Sessions 1 – 4 + DB bonus)

| Session | Type           | Layer      | Tests | Time    | Pass |
|--------:|----------------|------------|------:|--------:|-----:|
| 1       | Unit           | Backend    |    89 |  1.13 s | 100 %|
| 1       | Unit           | Frontend   |    29 |  2.59 s | 100 %|
| 2       | Integration    | Backend    |    43 | 18.96 s | 100 %|
| —       | **Database**   | **Backend**|**28** |**13.17 s**|**100 %**|
| 3       | Component      | Frontend   |    26 |  2.44 s | 100 %|
| 4       | System / E2E   | Full stack |    11 | 35.20 s | 100 %|
| **Total** |              |            | **226** | **73.49 s** | **100 %** |

---

*Bonus DB testing session complete. Resuming the 10-session programme at Session 5: Acceptance Testing.*
