"""
Database-level tests for the User model.

Asserts on schema-level guarantees: NOT NULL, UNIQUE, default values,
auto-generated IDs, password hashing, and timestamp population. These
are the contracts the *database* enforces — independent of any HTTP
or service-layer validation.
"""

from __future__ import annotations

import datetime as dt
import pytest
from sqlalchemy.exc import IntegrityError

from app import db as _db
from app.models.models import User


pytestmark = pytest.mark.integration  # runs in same suite tier as integration


def _make_user(**kwargs):
    password = kwargs.pop('password', 'secret-pw')
    user = User(
        username=kwargs.pop('username', 'alice'),
        email=kwargs.pop('email', 'alice@example.com'),
        role=kwargs.pop('role', 'operator'),
        **kwargs,
    )
    user.set_password(password)
    return user


class TestUserUniqueness:
    def test_duplicate_username_raises_integrity_error(self, session):
        session.add(_make_user(username='dup', email='a@x.com'))
        session.commit()

        session.add(_make_user(username='dup', email='b@x.com'))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_duplicate_email_raises_integrity_error(self, session):
        session.add(_make_user(username='u1', email='same@x.com'))
        session.commit()

        session.add(_make_user(username='u2', email='same@x.com'))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


class TestUserRequiredFields:
    def test_missing_username_raises_integrity_error(self, session):
        u = User(email='nouser@x.com', role='operator')
        u.set_password('p')
        session.add(u)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_missing_email_raises_integrity_error(self, session):
        u = User(username='no-email', role='operator')
        u.set_password('p')
        session.add(u)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_missing_password_hash_raises_integrity_error(self, session):
        u = User(username='no-pw', email='no-pw@x.com', role='operator')
        # Deliberately do NOT call set_password.
        session.add(u)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


class TestUserDefaults:
    def test_id_is_auto_assigned_uuid_string(self, session):
        u = _make_user()
        session.add(u)
        session.commit()
        assert isinstance(u.id, str)
        assert len(u.id) == 36  # uuid4 string is 36 chars
        assert u.id.count('-') == 4

    def test_role_defaults_to_operator_when_omitted(self, session):
        u = User(username='no-role', email='no-role@x.com')
        u.set_password('p')
        session.add(u)
        session.commit()
        assert u.role == 'operator'

    def test_is_active_defaults_to_true(self, session):
        u = _make_user(username='actv', email='actv@x.com')
        session.add(u)
        session.commit()
        assert u.is_active is True

    def test_created_at_is_auto_populated(self, session):
        before = dt.datetime.utcnow()
        u = _make_user(username='ts', email='ts@x.com')
        session.add(u)
        session.commit()
        after = dt.datetime.utcnow()
        assert isinstance(u.created_at, dt.datetime)
        assert before <= u.created_at <= after

    def test_last_login_is_nullable(self, session):
        u = _make_user(username='ll', email='ll@x.com')
        session.add(u)
        session.commit()
        assert u.last_login is None


class TestPasswordHashing:
    def test_set_password_does_not_store_plaintext(self, session):
        u = _make_user(password='supersecret')
        session.add(u)
        session.commit()
        assert u.password_hash != 'supersecret'
        assert 'supersecret' not in u.password_hash

    def test_check_password_returns_true_for_correct_password(self, session):
        u = _make_user(password='correct-horse-battery-staple')
        session.add(u)
        session.commit()
        assert u.check_password('correct-horse-battery-staple') is True

    def test_check_password_returns_false_for_wrong_password(self, session):
        u = _make_user(password='right')
        session.add(u)
        session.commit()
        assert u.check_password('wrong') is False

    def test_two_users_with_same_password_have_different_hashes(self, session):
        u1 = _make_user(username='a', email='a@x.com', password='same')
        u2 = _make_user(username='b', email='b@x.com', password='same')
        session.add_all([u1, u2])
        session.commit()
        # bcrypt salts each hash, so identical passwords must hash differently
        assert u1.password_hash != u2.password_hash
