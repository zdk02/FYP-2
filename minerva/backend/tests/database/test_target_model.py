"""
Database-level tests for the Target model.

Pins schema contracts: NOT NULL on `name` and `target_type`, default
`is_active=True`, auto `created_at` / `updated_at`, JSON-text round-trip.
"""

from __future__ import annotations

import datetime as dt
import json
import time
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.models import Target


pytestmark = pytest.mark.integration


class TestTargetRequiredFields:
    def test_missing_name_raises_integrity_error(self, session):
        t = Target(target_type='mcp_server', host='127.0.0.1')
        session.add(t)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_missing_target_type_raises_integrity_error(self, session):
        t = Target(name='no-type', host='127.0.0.1')
        session.add(t)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


class TestTargetDefaults:
    def test_id_is_auto_assigned_uuid(self, session):
        t = Target(name='auto-id', target_type='mcp_server', host='127.0.0.1')
        session.add(t)
        session.commit()
        assert isinstance(t.id, str)
        assert len(t.id) == 36

    def test_is_active_defaults_to_true(self, session):
        t = Target(name='default-active', target_type='mcp_server', host='127.0.0.1')
        session.add(t)
        session.commit()
        assert t.is_active is True

    def test_created_at_is_auto_populated(self, session):
        before = dt.datetime.utcnow()
        t = Target(name='ts', target_type='mcp_server', host='127.0.0.1')
        session.add(t)
        session.commit()
        after = dt.datetime.utcnow()
        assert before <= t.created_at <= after

    def test_updated_at_changes_on_update(self, session):
        t = Target(name='upd', target_type='mcp_server', host='127.0.0.1')
        session.add(t)
        session.commit()
        original = t.updated_at

        # Sleep a touch so the timestamps are distinguishable.
        time.sleep(0.01)
        t.host = '10.0.0.1'
        session.commit()

        assert t.updated_at >= original


class TestTargetJsonRoundTrip:
    def test_auth_config_json_persists_and_parses_back(self, session):
        cfg = {'type': 'bearer', 'token': 'abc123'}
        t = Target(
            name='auth-target',
            target_type='mcp_server',
            host='127.0.0.1',
            auth_config=json.dumps(cfg),
        )
        session.add(t)
        session.commit()

        # Re-fetch and parse.
        fetched = session.get(Target, t.id)
        assert json.loads(fetched.auth_config) == cfg

    def test_tags_json_array_round_trips(self, session):
        tags = ['production', 'mcp', 'demo']
        t = Target(
            name='tag-target',
            target_type='mcp_server',
            host='127.0.0.1',
            tags=json.dumps(tags),
        )
        session.add(t)
        session.commit()

        fetched = session.get(Target, t.id)
        assert json.loads(fetched.tags) == tags
