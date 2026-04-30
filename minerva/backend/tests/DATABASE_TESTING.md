# Database Testing — Minerva Backend

**Bonus session** in the Minerva FYP testing programme — explicit
proof that the *database schema itself* is correct, independent of the
Flask API or HTTP layer that uses it.

---

## What is Database Testing?

Database testing pins schema-level contracts: NOT NULL constraints,
UNIQUE constraints, default values, foreign-key relationships, and
cascade rules. These tests bypass HTTP entirely — they go straight
against the SQLAlchemy ORM and an in-memory SQLite database.

Where integration tests prove "the API works", these tests prove
"the database itself is correct" — a different (and complementary)
claim.

```
Test
  ↓ creates/updates ORM object
SQLAlchemy session
  ↓ INSERT / UPDATE / DELETE
SQLite (in-memory)
  ↓ enforces constraints
IntegrityError on violation  /  successful commit on valid input
```

---

## Scope of this session

| Model               | Contracts pinned                                                         |
|---------------------|---------------------------------------------------------------------------|
| `User`              | UNIQUE on username + email, NOT NULL on username/email/password_hash, defaults (`role='operator'`, `is_active=True`, `created_at` auto), bcrypt hashing (no plaintext, salted hashes, correct check_password) |
| `Target`            | NOT NULL on name + target_type, defaults (`is_active=True`, timestamps), JSON-text round-trip for `auth_config` and `tags`, `updated_at` auto-bump on UPDATE |
| Relationships       | User ↔ AuditLog (one-to-many, action NOT NULL, user_id nullable for system actions), Target ↔ DiscoveredEndpoint (cascade delete), endpoint requires target_id |

---

## Test inventory (28 tests)

| File                                                | Tests | What it proves                                                  |
|-----------------------------------------------------|------:|-----------------------------------------------------------------|
| `tests/database/test_user_model.py`                 |    14 | User uniqueness, required fields, defaults, password hashing    |
| `tests/database/test_target_model.py`               |     8 | Target required fields, defaults, JSON column round-trip        |
| `tests/database/test_relationships.py`              |     6 | User↔AuditLog FK, Target→DiscoveredEndpoint cascade delete      |
| **Total**                                           | **28**|                                                                 |

---

## How to run

From `minerva/backend/`:

```bash
# Run all DB tests + HTML report
python -m pytest tests/database/ -v \
  --html=reports/tests/database_test_report.html --self-contained-html

# Run a single class
python -m pytest tests/database/test_user_model.py::TestPasswordHashing -v
```

---

## Latest result

```
============================= 28 passed in 13.17s =============================
```

**Pass rate:** 28 / 28 (100 %)
**Wall-clock:** 13.17 s (each test rebuilds the in-memory DB from scratch)
**HTML report:** `backend/reports/tests/database_test_report.html`

---

## Why this layer matters

These tests catch a class of bugs that integration tests *cannot*:

- **`test_duplicate_email_raises_integrity_error`** — proves the
  `unique=True` constraint on `User.email` is actually committed to
  the schema, not just declared in the model. If someone removed
  `unique=True`, this fails immediately.
- **`test_two_users_with_same_password_have_different_hashes`** —
  proves bcrypt is salting hashes correctly. Without salting, a
  password leak would compromise every user with that password.
- **`test_deleting_target_cascades_to_its_endpoints`** — proves the
  `cascade='all, delete-orphan'` setting actually cleans up child
  rows. A regression here would leak orphan rows across every target
  delete.
- **`test_updated_at_changes_on_update`** — proves the
  `onupdate=datetime.utcnow` trigger fires on every UPDATE — relied
  on by audit reports.

---

## What this proves to the marker

1. **The database schema enforces its own contracts** — even if the
   API layer is bypassed (direct DB access, future migrations,
   replacement frontend), data integrity is still guaranteed.
2. **Authentication is cryptographically correct** — passwords are
   hashed with bcrypt and individually salted; no plaintext leaks
   into storage.
3. **Cascade rules and foreign keys behave as documented** — no
   orphan rows on delete, no broken references.
4. **Defaults are wired** — every NOT NULL column with a default
   actually has that default applied at insert time.
