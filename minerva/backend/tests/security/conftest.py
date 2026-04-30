"""
Fixtures for the security test suite.

Security tests focus on attack-resistance — JWT tampering, RBAC
bypass attempts, injection-resilience, sensitive-data exposure. They
use the same in-memory Flask app as integration tests but the
assertions are inverted: we expect the system to *reject* malicious
input, not to accept it.

Reuses the integration-style fixtures (admin/viewer tokens) and adds
helpers for crafting tampered JWTs.
"""

from __future__ import annotations

import pytest

from app import create_app, db as _db
from app.models.models import User


@pytest.fixture()
def app():
    """Build a fresh Flask app + in-memory DB per test."""
    flask_app = create_app('testing')
    yield flask_app
    with flask_app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_token(client):
    resp = client.post('/api/v1/auth/login',
                       json={'email': 'admin@minerva.local', 'password': 'admin123'})
    assert resp.status_code == 200
    return resp.get_json()['access_token']


@pytest.fixture()
def admin_headers(admin_token):
    return {'Authorization': f'Bearer {admin_token}'}


@pytest.fixture()
def viewer_token(app, client):
    """Create a viewer-role user and return their JWT."""
    with app.app_context():
        user = User(username='viewer-sec', email='viewer-sec@minerva.local',
                    role='viewer', is_active=True)
        user.set_password('viewer-pass')
        _db.session.add(user)
        _db.session.commit()

    resp = client.post('/api/v1/auth/login',
                       json={'email': 'viewer-sec@minerva.local',
                             'password': 'viewer-pass'})
    assert resp.status_code == 200
    return resp.get_json()['access_token']


@pytest.fixture()
def viewer_headers(viewer_token):
    return {'Authorization': f'Bearer {viewer_token}'}
