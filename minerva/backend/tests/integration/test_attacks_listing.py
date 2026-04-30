"""
Integration tests for /api/v1/attacks — listing + filtering + auth.

The attacks catalogue is normally seeded via `python -m
scripts.seed_pro_attacks`, but our test app only runs
`initialize_default_data()`, which creates categories and
subcategories but no concrete attack rows. We therefore assert the
*shape* of the responses (200 + JSON list) and the auth/filter
behaviour, without depending on specific attack content.
"""

import pytest


pytestmark = pytest.mark.integration


class TestListAttacks:
    def test_unauthenticated_request_is_rejected(self, client):
        resp = client.get('/api/v1/attacks')
        assert resp.status_code == 401

    def test_authenticated_request_returns_200_and_a_list(
        self, client, auth_headers
    ):
        resp = client.get('/api/v1/attacks', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert isinstance(body, list)

    def test_severity_filter_is_accepted(self, client, auth_headers):
        resp = client.get('/api/v1/attacks?severity=critical',
                          headers=auth_headers)
        assert resp.status_code == 200
        # Whatever subset is returned must be a list.
        assert isinstance(resp.get_json(), list)

    def test_search_filter_is_accepted(self, client, auth_headers):
        resp = client.get('/api/v1/attacks?search=injection',
                          headers=auth_headers)
        assert resp.status_code == 200

    def test_unknown_attack_id_returns_404(self, client, auth_headers):
        resp = client.get('/api/v1/attacks/does-not-exist',
                          headers=auth_headers)
        assert resp.status_code == 404


class TestAttackMetadataEndpoints:
    def test_severities_endpoint_returns_list(self, client, auth_headers):
        resp = client.get('/api/v1/attacks/severities', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert isinstance(body, list)
        # Should contain at least the standard CVSS-style buckets
        assert any('critical' in str(item).lower() for item in body)

    def test_types_endpoint_returns_list(self, client, auth_headers):
        resp = client.get('/api/v1/attacks/types', headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_languages_endpoint_returns_list(self, client, auth_headers):
        resp = client.get('/api/v1/attacks/languages', headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)
