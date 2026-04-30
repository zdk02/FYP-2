"""
Integration tests for the health/readiness endpoints — also serves as
a sanity check that `create_app('testing')` boots cleanly with an
in-memory SQLite database.
"""

import pytest


pytestmark = pytest.mark.integration


class TestHealthEndpoints:
    def test_readiness_endpoint_returns_200(self, client):
        resp = client.get('/api/v1/health/ready')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['status'] == 'ready'
        assert body['service'] == 'aegis-backend'

    def test_unknown_route_returns_404(self, client):
        resp = client.get('/api/v1/this/does/not/exist')
        assert resp.status_code == 404
        assert resp.get_json()['error'] == 'Not found'
