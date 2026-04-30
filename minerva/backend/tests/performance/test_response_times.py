"""
Backend API response-time tests.

For each major endpoint, hit it N=50 times and assert that the p95
latency is below a documented threshold. The thresholds are
generous on purpose — they catch order-of-magnitude regressions
(e.g. an N+1 query, a missing index, a sync call to a slow
service) without flapping on small variance.

These tests run against the Flask test client (no real network), so
they isolate Flask + SQLAlchemy + SQLite latency from disk/network
effects. They are not a replacement for production load testing.
"""

from __future__ import annotations

import pytest

from .conftest import measure, report


pytestmark = pytest.mark.performance


# Documented service-level thresholds (p95, in milliseconds).
# Bcrypt-using endpoints get a generous budget because bcrypt is
# *intentionally* slow — that's a security feature, not a bug.
THRESHOLDS = {
    'health':              50,
    'login_with_bcrypt':  500,
    'me':                 100,
    'list_targets_empty':  50,
    'list_targets_seeded': 100,
    'list_attacks':        50,
    'attacks_metadata':    20,
}


class TestEndpointResponseTimes:
    def test_health_endpoint_is_fast(self, client):
        stats = measure(lambda: client.get('/api/v1/health/ready'), n=50)
        report('GET /health/ready', stats, THRESHOLDS['health'])
        assert stats['p95_ms'] <= THRESHOLDS['health']

    def test_login_under_500ms_p95_despite_bcrypt(self, client):
        stats = measure(
            lambda: client.post('/api/v1/auth/login',
                                json={'email': 'admin@minerva.local',
                                      'password': 'admin123'}),
            n=20,  # bcrypt is slow, 20 samples is enough
        )
        report('POST /auth/login', stats, THRESHOLDS['login_with_bcrypt'])
        assert stats['p95_ms'] <= THRESHOLDS['login_with_bcrypt']

    def test_me_endpoint_under_100ms_p95(self, client, auth_headers):
        stats = measure(
            lambda: client.get('/api/v1/auth/me', headers=auth_headers),
            n=50,
        )
        report('GET /auth/me', stats, THRESHOLDS['me'])
        assert stats['p95_ms'] <= THRESHOLDS['me']

    def test_list_targets_empty_under_50ms_p95(self, client, auth_headers):
        stats = measure(
            lambda: client.get('/api/v1/targets', headers=auth_headers),
            n=50,
        )
        report('GET /targets (empty)', stats, THRESHOLDS['list_targets_empty'])
        assert stats['p95_ms'] <= THRESHOLDS['list_targets_empty']

    def test_list_attacks_under_50ms_p95(self, client, auth_headers):
        stats = measure(
            lambda: client.get('/api/v1/attacks', headers=auth_headers),
            n=50,
        )
        report('GET /attacks', stats, THRESHOLDS['list_attacks'])
        assert stats['p95_ms'] <= THRESHOLDS['list_attacks']

    def test_attacks_metadata_endpoints_are_fast(self, client, auth_headers):
        for path, label in [
            ('/api/v1/attacks/severities', 'GET /attacks/severities'),
            ('/api/v1/attacks/types',      'GET /attacks/types'),
            ('/api/v1/attacks/languages',  'GET /attacks/languages'),
        ]:
            stats = measure(
                lambda p=path: client.get(p, headers=auth_headers),
                n=50,
            )
            report(label, stats, THRESHOLDS['attacks_metadata'])
            assert stats['p95_ms'] <= THRESHOLDS['attacks_metadata']


class TestSeededDatabaseScalesLinearly:
    """Insert 50 targets, then re-measure the list endpoint. The p95
    should still come in under a relaxed threshold — no N+1 queries."""

    def test_listing_50_targets_still_fast(self, client, auth_headers):
        # Seed 50 targets via the real API.
        for i in range(50):
            r = client.post(
                '/api/v1/targets', headers=auth_headers,
                json={'name': f'perf-target-{i:03d}',
                      'host': '127.0.0.1',
                      'port': 8000 + i,
                      'protocol': 'http'},
            )
            assert r.status_code == 201

        stats = measure(
            lambda: client.get('/api/v1/targets', headers=auth_headers),
            n=30,
        )
        report('GET /targets (50 rows)', stats, THRESHOLDS['list_targets_seeded'])
        assert stats['p95_ms'] <= THRESHOLDS['list_targets_seeded']
