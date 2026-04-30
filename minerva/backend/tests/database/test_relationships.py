"""
Database-level tests for relationships between models.

Pins:
  - User -> AuditLog (one-to-many, FK on AuditLog.user_id)
  - Target -> DiscoveredEndpoint (one-to-many, cascade='all, delete-orphan')
  - AuditLog requires `action` (NOT NULL)
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.models import User, Target, DiscoveredEndpoint, AuditLog


pytestmark = pytest.mark.integration


class TestUserAuditLogRelationship:
    def test_user_can_have_multiple_audit_logs(self, session):
        user = User(username='u1', email='u1@x.com', role='admin')
        user.set_password('p')
        session.add(user)
        session.commit()

        for action in ('login', 'create', 'update', 'logout'):
            session.add(AuditLog(user_id=user.id, action=action))
        session.commit()

        assert user.audit_logs.count() == 4

    def test_audit_log_action_is_required(self, session):
        user = User(username='u2', email='u2@x.com', role='admin')
        user.set_password('p')
        session.add(user)
        session.commit()

        # Missing `action` violates NOT NULL.
        session.add(AuditLog(user_id=user.id))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_audit_log_user_id_is_optional(self, session):
        # The FK is nullable in the model — system actions can have no user.
        log = AuditLog(action='system-task', resource_type='cron')
        session.add(log)
        session.commit()
        assert log.id is not None
        assert log.user_id is None


class TestTargetEndpointCascade:
    def test_endpoints_can_be_attached_to_a_target(self, session):
        target = Target(name='t1', target_type='mcp_server', host='127.0.0.1')
        session.add(target)
        session.commit()

        for path in ('/api/foo', '/api/bar', '/api/baz'):
            session.add(DiscoveredEndpoint(target_id=target.id,
                                           endpoint_path=path,
                                           method='GET'))
        session.commit()

        assert target.discovered_endpoints.count() == 3

    def test_deleting_target_cascades_to_its_endpoints(self, session):
        target = Target(name='gone', target_type='mcp_server', host='127.0.0.1')
        session.add(target)
        session.commit()

        for path in ('/a', '/b'):
            session.add(DiscoveredEndpoint(target_id=target.id,
                                           endpoint_path=path,
                                           method='GET'))
        session.commit()

        target_id = target.id
        assert session.query(DiscoveredEndpoint)\
                      .filter_by(target_id=target_id).count() == 2

        # SQLAlchemy ORM cascade='all, delete-orphan' on the relationship
        # removes the children when the parent is deleted.
        session.delete(target)
        session.commit()

        assert session.query(DiscoveredEndpoint)\
                      .filter_by(target_id=target_id).count() == 0

    def test_endpoint_requires_a_target_id(self, session):
        # target_id is NOT NULL.
        ep = DiscoveredEndpoint(endpoint_path='/orphan', method='GET')
        session.add(ep)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
