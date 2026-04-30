"""
Role-based access control (RBAC) enforcement tests.

For every endpoint that is supposed to be admin-only or
manager+admin-only, prove that a viewer-role token is rejected with
HTTP 403. This is the contract that prevents privilege escalation.
"""

from __future__ import annotations

import json

import pytest


pytestmark = pytest.mark.security


def _expect_forbidden(resp):
    """Helper: assert the response is a clear 'forbidden' (403) result."""
    assert resp.status_code == 403, (
        f'expected 403 Forbidden but got {resp.status_code}: '
        f'{resp.get_json()}'
    )


class TestAdminOnlyEndpointsRejectViewer:
    """Admin-only endpoints must return 403 to anyone who is not admin."""

    def test_viewer_cannot_list_all_users(self, client, viewer_headers):
        # /users requires manager_or_admin
        resp = client.get('/api/v1/users', headers=viewer_headers)
        _expect_forbidden(resp)

    def test_viewer_cannot_create_user(self, client, viewer_headers):
        resp = client.post(
            '/api/v1/users', headers=viewer_headers,
            json={'username': 'attacker', 'email': 'a@x.com',
                  'password': 'p', 'role': 'admin'},
        )
        _expect_forbidden(resp)

    def test_viewer_cannot_delete_user(self, client, viewer_headers):
        resp = client.delete('/api/v1/users/some-id', headers=viewer_headers)
        _expect_forbidden(resp)


class TestManagerOrAdminEndpointsRejectViewer:
    """Endpoints requiring manager+ should reject viewer tokens."""

    def _create_target_with_admin(self, client, admin_headers, name='proto'):
        return client.post('/api/v1/targets', headers=admin_headers,
                           json={'name': name, 'host': '127.0.0.1',
                                 'port': 8765, 'protocol': 'http'})

    def test_viewer_cannot_create_target(self, client, viewer_headers):
        resp = client.post('/api/v1/targets', headers=viewer_headers,
                           json={'name': 'attempt', 'host': '127.0.0.1',
                                 'port': 8765, 'protocol': 'http'})
        _expect_forbidden(resp)

    def test_viewer_cannot_update_target(self, client, admin_headers, viewer_headers):
        created = self._create_target_with_admin(client, admin_headers).get_json()
        target_id = created['target']['id']

        resp = client.put(f'/api/v1/targets/{target_id}',
                          headers=viewer_headers,
                          json={'name': 'hijacked'})
        _expect_forbidden(resp)

    def test_viewer_cannot_delete_target(self, client, admin_headers, viewer_headers):
        created = self._create_target_with_admin(client, admin_headers).get_json()
        target_id = created['target']['id']

        resp = client.delete(f'/api/v1/targets/{target_id}',
                             headers=viewer_headers)
        _expect_forbidden(resp)


class TestPrivilegeEscalation:
    """Direct attempts to escalate via the API."""

    def test_viewer_creating_a_user_does_not_escalate_to_admin(
        self, client, viewer_headers, app
    ):
        """Even if create-user accepted role='admin' in the body, the
        endpoint must reject the call entirely because the caller is a
        viewer. We verify the call returns 403 and NO admin user was
        added."""
        from app.models.models import User
        with app.app_context():
            admin_count_before = User.query.filter_by(role='admin').count()

        resp = client.post(
            '/api/v1/users', headers=viewer_headers,
            json={'username': 'escalated', 'email': 'esc@x.com',
                  'password': 'p', 'role': 'admin'},
        )
        _expect_forbidden(resp)

        with app.app_context():
            admin_count_after = User.query.filter_by(role='admin').count()
        assert admin_count_after == admin_count_before, (
            'viewer-created admin user leaked into the database'
        )

    def test_admin_only_targets_remain_safe_with_viewer_token(
        self, client, admin_headers, viewer_headers, app
    ):
        """Make sure that even when a target exists, a viewer cannot
        delete it — and the row really is still there afterwards."""
        from app.models.models import Target
        created = client.post(
            '/api/v1/targets', headers=admin_headers,
            json={'name': 'protected-asset', 'host': '127.0.0.1',
                  'port': 8765, 'protocol': 'http'},
        ).get_json()
        target_id = created['target']['id']

        resp = client.delete(f'/api/v1/targets/{target_id}',
                             headers=viewer_headers)
        _expect_forbidden(resp)

        # The target must still exist.
        with app.app_context():
            assert Target.query.get(target_id) is not None
