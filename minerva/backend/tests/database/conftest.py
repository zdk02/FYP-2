"""
Fixtures for the database test suite.

These tests sit one layer below integration: they go straight against
the SQLAlchemy models + an in-memory SQLite database, with no Flask
routing or HTTP involved. The goal is to pin contracts of the schema
itself — constraints, defaults, relationships, cascade behaviour.

A fresh in-memory database is built per test for full isolation.
"""

from __future__ import annotations

import pytest

from app import create_app, db as _db


@pytest.fixture()
def app():
    """Build a fresh Flask app + in-memory DB per test."""
    flask_app = create_app('testing')
    yield flask_app
    with flask_app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def session(app):
    """Yield the SQLAlchemy session inside an app context."""
    with app.app_context():
        yield _db.session
