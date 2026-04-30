"""
Integration-test fixtures for Minerva.

These tests exercise multiple components together — Flask routing,
SQLAlchemy ORM, JWT auth, request validation — against an in-memory
SQLite database. No external services (Redis, real Postgres, MCP
targets) are involved.

Each test gets a freshly-built Flask app and an empty in-memory
database, so tests cannot leak state into each other.

Fixtures provided:
    app           -> Flask app configured with TestingConfig
    client        -> app.test_client() for issuing requests
    admin_token   -> JWT access token for the seeded admin user
    auth_headers  -> {"Authorization": "Bearer <admin_token>"}
    viewer_user   -> a freshly-created user with role=viewer + their JWT
"""

from __future__ import annotations

import pytest

from app import create_app, db as _db
from app.models.models import User


@pytest.fixture()
def app():
    """Build a fresh Flask app + in-memory DB per test.

    `create_app('testing')` triggers `initialize_default_data()` which
    seeds the admin user (admin@minerva.local / admin123) and the
    default attack categories.
    """
    flask_app = create_app('testing')
    yield flask_app
    # Drop everything so the next test starts clean.
    with flask_app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    """Flask test client — issues requests without a real network."""
    return app.test_client()


@pytest.fixture()
def admin_token(client):
    """Log in as the seeded admin and return the access token."""
    resp = client.post(
        '/api/v1/auth/login',
        json={'email': 'admin@minerva.local', 'password': 'admin123'},
    )
    assert resp.status_code == 200, f'admin login failed: {resp.data!r}'
    return resp.get_json()['access_token']


@pytest.fixture()
def auth_headers(admin_token):
    """Authorization header for the admin user."""
    return {'Authorization': f'Bearer {admin_token}'}


@pytest.fixture()
def viewer_user(app, client):
    """Create a viewer-role user and return (user_dict, access_token).

    Used to assert that role-based access control rejects insufficient
    privileges (e.g. viewers cannot delete targets).
    """
    with app.app_context():
        user = User(
            username='viewer1',
            email='viewer1@minerva.local',
            role='viewer',
            is_active=True,
        )
        user.set_password('viewer-pass')
        _db.session.add(user)
        _db.session.commit()
        info = user.to_dict()

    resp = client.post(
        '/api/v1/auth/login',
        json={'email': 'viewer1@minerva.local', 'password': 'viewer-pass'},
    )
    assert resp.status_code == 200, f'viewer login failed: {resp.data!r}'
    return info, resp.get_json()['access_token']
