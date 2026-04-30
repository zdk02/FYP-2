# Integration Testing — Minerva Backend

**Session 2 of 10** in the Minerva FYP testing programme.

---

## What is Integration Testing?

Integration testing verifies that **multiple components work correctly
together**. Where unit tests isolate a single function, an integration
test exercises a vertical slice through the system: an HTTP request
hits Flask routing, traverses the JWT decoder, runs a SQLAlchemy ORM
query against a real (in-memory) SQLite database, and produces a
response.

These tests catch a different class of bugs than unit tests:
- Wrong route methods or URL prefixes
- Broken auth decorators
- Schema/model mismatches
- Missing or wrong status codes
- Validation rules that don't match what the model accepts
- Permission checks that don't match the documented role rules

---

## Scope of this session

| Vertical                | What's exercised                                                         |
|-------------------------|--------------------------------------------------------------------------|
| Health endpoints        | App boots, blueprint is registered, 404 handler returns JSON             |
| Auth flow               | Login, JWT mint, /me, refresh token, logout, password change             |
| Targets CRUD            | Create, list, get, update, delete; role-based permission enforcement     |
| Attacks listing         | Listing, severity / search filters, metadata catalogues                  |

Each test runs against a **freshly-built Flask app** with an
**in-memory SQLite database** seeded by `initialize_default_data()`
(creates the admin user and attack categories). No external services
(Redis, Postgres, MCP target server) are required.

---

## Test inventory (43 tests)

| File                                          | Tests | What it proves                                                  |
|-----------------------------------------------|------:|-----------------------------------------------------------------|
| `tests/integration/test_health.py`            |     2 | Test app boots; 404 handler returns valid JSON                  |
| `tests/integration/test_auth_flow.py`         |    16 | Login, /me, refresh, logout, change-password — all paths        |
| `tests/integration/test_targets_crud.py`      |    17 | Targets CRUD + viewer role can't delete                         |
| `tests/integration/test_attacks_listing.py`   |     8 | List + filters + metadata endpoints all require JWT             |
| **Total**                                     | **43** |                                                                |

---

## How to run

From `minerva/backend/`:

```bash
# Run all integration tests + HTML report
python -m pytest tests/integration/ -m integration \
  --html=reports/tests/integration_test_report.html --self-contained-html

# Run a single suite
python -m pytest tests/integration/test_auth_flow.py -v

# Quiet warnings (deprecation noise from datetime.utcnow in third-party code)
python -m pytest tests/integration/ -W ignore::DeprecationWarning
```

---

## Latest result

```
============================= 43 passed in 18.96s =============================
```

**Pass rate:** 43 / 43 (100 %)
**Wall-clock:** ~19 seconds (each test rebuilds the app + DB, hence slower than unit)
**HTML report:** `backend/reports/tests/integration_test_report.html`

---

## Why this is harder than unit testing

Each test:

1. Builds a fresh Flask app (`create_app('testing')`)
2. Creates an in-memory SQLite database
3. Runs `initialize_default_data()` to seed the admin user and categories
4. Issues real HTTP requests via the Flask test client
5. Asserts on real ORM-generated JSON responses
6. Tears the database down so the next test starts clean

This means the tests catch failures that only appear when components
are wired together — for example:

- **`test_viewer_cannot_delete_target`** — proves the
  `@require_role('admin', 'manager')` decorator on `DELETE /targets/<id>`
  actually rejects viewer-role JWTs with HTTP 403, not just at the
  Python level.
- **`test_change_password_succeeds_with_correct_current_password`**
  — performs a write to the User model, then logs in again with the
  new password to prove the password hash was actually persisted.
- **`test_stdio_target_requires_base_url`** — proves the
  protocol-specific validation branch in `create_target` is wired up.

---

## What this proves to the marker

1. **End-to-end correctness of every API surface tested** — login,
   targets CRUD, attacks listing — works with the real database, real
   ORM, real JWT layer.
2. **Role-based access control is enforced at the HTTP layer**, not
   only in the frontend (the seeded viewer can't delete targets).
3. **Validation is wired correctly** — missing required fields produce
   the documented HTTP 400, not a 500 stacktrace.
4. **Auth boundaries hold** — every protected endpoint refuses
   un-authenticated requests; refresh tokens cannot be used as access
   tokens.
5. **Standards-based stack** — `pytest` + Flask test client + SQLAlchemy
   in-memory SQLite. The same setup used by every Flask team in
   industry.
