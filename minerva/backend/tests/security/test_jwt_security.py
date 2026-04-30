"""
JWT-related security tests.

Verifies that the auth layer rejects every common token-forgery
technique: missing header, malformed header, tampered payload,
algorithm-confusion attacks (alg=none), and tokens signed with the
wrong key.
"""

from __future__ import annotations

import base64
import json

import jwt as pyjwt
import pytest


pytestmark = pytest.mark.security


PROTECTED = '/api/v1/auth/me'


class TestMissingOrMalformedToken:
    def test_no_authorization_header_is_rejected(self, client):
        resp = client.get(PROTECTED)
        assert resp.status_code == 401

    def test_authorization_without_bearer_prefix_is_rejected(self, client, admin_token):
        # Just the raw token, no "Bearer " prefix.
        resp = client.get(PROTECTED, headers={'Authorization': admin_token})
        assert resp.status_code in (401, 422)

    def test_garbage_token_is_rejected(self, client):
        resp = client.get(PROTECTED,
                          headers={'Authorization': 'Bearer not-a-real-token'})
        assert resp.status_code in (401, 422)

    def test_empty_bearer_token_is_rejected(self, client):
        resp = client.get(PROTECTED, headers={'Authorization': 'Bearer '})
        assert resp.status_code in (401, 422)

    def test_random_base64_in_bearer_is_rejected(self, client):
        # A well-formed-looking but bogus JWT.
        bogus = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip('=')
        resp = client.get(PROTECTED,
                          headers={'Authorization': f'Bearer {bogus}.{bogus}.{bogus}'})
        assert resp.status_code in (401, 422)


class TestTamperedToken:
    def test_token_with_modified_payload_is_rejected(self, client, admin_token):
        # Flip one character in the middle (payload) section — signature breaks.
        parts = admin_token.split('.')
        assert len(parts) == 3, 'JWT should have 3 dot-separated parts'

        payload_b64 = parts[1]
        # Swap the first character of the payload to invalidate the signature.
        tampered_payload = ('A' if payload_b64[0] != 'A' else 'B') + payload_b64[1:]
        tampered = '.'.join([parts[0], tampered_payload, parts[2]])

        resp = client.get(PROTECTED,
                          headers={'Authorization': f'Bearer {tampered}'})
        assert resp.status_code in (401, 422)

    def test_token_with_swapped_signature_is_rejected(self, client, admin_token):
        parts = admin_token.split('.')
        bad_sig = parts[2][::-1]  # reverse signature
        forged = '.'.join([parts[0], parts[1], bad_sig])
        resp = client.get(PROTECTED,
                          headers={'Authorization': f'Bearer {forged}'})
        assert resp.status_code in (401, 422)


class TestAlgorithmConfusion:
    def test_alg_none_token_is_rejected(self, client, app):
        """Classic 'alg=none' attack: forge a token with no signature.
        A correctly-configured JWT layer must reject this."""
        with app.app_context():
            # We need a real user_id — log in to get one.
            login = client.post('/api/v1/auth/login',
                                json={'email': 'admin@minerva.local',
                                      'password': 'admin123'})
            user_id = login.get_json()['user']['id']

        # Craft a fake "alg=none" token by hand.
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {'sub': user_id, 'identity': user_id}
        h = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        p = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        forged = f'{h}.{p}.'  # empty signature

        resp = client.get(PROTECTED,
                          headers={'Authorization': f'Bearer {forged}'})
        assert resp.status_code in (401, 422)

    def test_token_signed_with_wrong_secret_is_rejected(self, client, app):
        with app.app_context():
            login = client.post('/api/v1/auth/login',
                                json={'email': 'admin@minerva.local',
                                      'password': 'admin123'})
            user_id = login.get_json()['user']['id']

        # Sign a forged token with the WRONG secret.
        forged = pyjwt.encode(
            {'sub': user_id, 'identity': user_id},
            'definitely-not-the-real-secret',
            algorithm='HS256',
        )
        if isinstance(forged, bytes):  # PyJWT < 2 returns bytes
            forged = forged.decode()
        resp = client.get(PROTECTED,
                          headers={'Authorization': f'Bearer {forged}'})
        assert resp.status_code in (401, 422)


class TestRefreshTokenScope:
    def test_refresh_token_cannot_authorise_normal_endpoints(self, client):
        login = client.post('/api/v1/auth/login',
                            json={'email': 'admin@minerva.local',
                                  'password': 'admin123'}).get_json()
        refresh = login['refresh_token']
        # Refresh token must NOT be accepted on /auth/me (which requires access token).
        resp = client.get(PROTECTED,
                          headers={'Authorization': f'Bearer {refresh}'})
        assert resp.status_code in (401, 422)
