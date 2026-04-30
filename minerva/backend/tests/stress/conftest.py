"""
Fixtures for stress tests — module-scoped so we pay the create_app
cost once per file, not per test.

Stress tests deliberately push the system past normal load. The
assertion isn't "everything succeeds"; it's "the system doesn't
catastrophically collapse" — degraded throughput is acceptable, but
crashes, hangs, or data corruption are not.
"""

from __future__ import annotations

import pytest

from app import create_app, db as _db


@pytest.fixture(scope='module')
def app():
    flask_app = create_app('testing')
    yield flask_app
    with flask_app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='module')
def client(app):
    return app.test_client()


@pytest.fixture(scope='module')
def auth_headers(client):
    resp = client.post('/api/v1/auth/login',
                       json={'email': 'admin@minerva.local',
                             'password': 'admin123'})
    assert resp.status_code == 200
    return {'Authorization': f'Bearer {resp.get_json()["access_token"]}'}
