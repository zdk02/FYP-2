"""
Fixtures for performance tests.

These tests measure response-time percentiles (p50, p95) over N
repeated requests against the in-memory test app. Slow runs would
indicate either a regression or a test environment problem — we
assert against generous-but-meaningful thresholds.
"""

from __future__ import annotations

import statistics
import time

import pytest

from app import create_app, db as _db


@pytest.fixture(scope='module')
def app():
    """Module-scoped app + DB. Performance tests don't mutate state, so
    we share the app across all tests in a module to avoid paying the
    create_app cost per-test."""
    flask_app = create_app('testing')
    yield flask_app
    with flask_app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='module')
def client(app):
    return app.test_client()


@pytest.fixture(scope='module')
def admin_token(client):
    resp = client.post('/api/v1/auth/login',
                       json={'email': 'admin@minerva.local',
                             'password': 'admin123'})
    assert resp.status_code == 200
    return resp.get_json()['access_token']


@pytest.fixture(scope='module')
def auth_headers(admin_token):
    return {'Authorization': f'Bearer {admin_token}'}


def measure(fn, n=50):
    """Run fn() n times, return dict of timing percentiles in ms."""
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)  # ms
    samples.sort()
    return {
        'n': n,
        'min_ms': round(samples[0], 2),
        'p50_ms': round(statistics.median(samples), 2),
        'p95_ms': round(samples[int(n * 0.95) - 1], 2),
        'max_ms': round(samples[-1], 2),
        'mean_ms': round(statistics.mean(samples), 2),
    }


def report(label, stats, threshold_ms):
    """Pretty-print one line for the run log."""
    verdict = 'OK' if stats['p95_ms'] <= threshold_ms else 'SLOW'
    print(
        f'[perf] {label:<30} '
        f'p50={stats["p50_ms"]:>7.2f}ms '
        f'p95={stats["p95_ms"]:>7.2f}ms '
        f'max={stats["max_ms"]:>7.2f}ms '
        f'(threshold {threshold_ms}ms) {verdict}'
    )
