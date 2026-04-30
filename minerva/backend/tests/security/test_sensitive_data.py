"""
Sensitive-data exposure tests.

Verifies that no API response leaks sensitive fields that should
never leave the server: bcrypt password hashes, internal secrets,
raw stack traces, etc.
"""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.security


SENSITIVE_FIELD_NAMES = ('password', 'password_hash', 'secret_key', 'jwt_secret_key')


def _scan_for_sensitive_fields(payload):
    """Recursively walk a JSON-shaped value and return any keys that
    look like they belong on a hidden internal column."""
    found = []

    def visit(node, path=''):
        if isinstance(node, dict):
            for k, v in node.items():
                lk = str(k).lower()
                if lk in SENSITIVE_FIELD_NAMES:
                    found.append(f'{path}.{k}')
                visit(v, f'{path}.{k}')
        elif isinstance(node, list):
            for i, v in enumerate(node):
                visit(v, f'{path}[{i}]')

    visit(payload)
    return found


class TestPasswordHashNeverLeaked:
    def test_login_response_contains_no_password_hash(self, client):
        resp = client.post('/api/v1/auth/login',
                           json={'email': 'admin@minerva.local',
                                 'password': 'admin123'})
        assert resp.status_code == 200
        leaked = _scan_for_sensitive_fields(resp.get_json())
        assert leaked == [], f'sensitive fields leaked: {leaked}'

    def test_me_response_contains_no_password_hash(self, client, admin_headers):
        resp = client.get('/api/v1/auth/me', headers=admin_headers)
        assert resp.status_code == 200
        leaked = _scan_for_sensitive_fields(resp.get_json())
        assert leaked == [], f'sensitive fields leaked: {leaked}'

    def test_users_list_contains_no_password_hash(self, client, admin_headers):
        resp = client.get('/api/v1/users', headers=admin_headers)
        assert resp.status_code == 200
        leaked = _scan_for_sensitive_fields(resp.get_json())
        assert leaked == [], f'sensitive fields leaked: {leaked}'

    def test_user_detail_contains_no_password_hash(self, client, admin_headers):
        # Get the admin user's own id, then fetch their detail.
        me = client.get('/api/v1/auth/me', headers=admin_headers).get_json()
        resp = client.get(f"/api/v1/users/{me['id']}", headers=admin_headers)
        assert resp.status_code == 200
        leaked = _scan_for_sensitive_fields(resp.get_json())
        assert leaked == [], f'sensitive fields leaked: {leaked}'


class TestErrorResponsesDoNotLeakInternals:
    def test_404_response_is_short_json(self, client):
        resp = client.get('/api/v1/this/does/not/exist')
        assert resp.status_code == 404
        body = resp.get_json()
        # Body should be a small dict like {"error": "Not found"}, not a
        # stack trace or environment dump.
        assert isinstance(body, dict)
        assert all(len(str(v)) < 200 for v in body.values())

    def test_login_failure_does_not_distinguish_unknown_email_from_wrong_password(
        self, client
    ):
        """The error message should be the same whether the email was
        unknown or the password was wrong — otherwise attackers can
        enumerate valid emails."""
        wrong_pw = client.post('/api/v1/auth/login',
                               json={'email': 'admin@minerva.local',
                                     'password': 'WRONG'}).get_json()
        unknown = client.post('/api/v1/auth/login',
                              json={'email': 'nobody@nowhere.com',
                                    'password': 'anything'}).get_json()
        assert wrong_pw.get('error') == unknown.get('error')


class TestAuthHeaderHandling:
    def test_health_endpoint_does_not_require_auth(self, client):
        # Health check should be public — used by Docker/k8s liveness probes.
        resp = client.get('/api/v1/health/ready')
        assert resp.status_code == 200

    def test_auth_endpoints_present_no_auth_token_in_response_body(self, client):
        """Tokens go in the JSON body deliberately — confirm they don't
        also leak into headers (which could be cached by proxies)."""
        resp = client.post('/api/v1/auth/login',
                           json={'email': 'admin@minerva.local',
                                 'password': 'admin123'})
        # No Authorization or Set-Cookie containing the token in response.
        for header in ('Authorization', 'Set-Cookie'):
            value = resp.headers.get(header, '')
            assert 'eyJ' not in value, (
                f'{header} appears to contain a JWT — should be in body only'
            )
