"""
Shared pytest fixtures and path setup for Minerva test suites.

Adds the backend/ directory to sys.path so tests can do
`from app.services import ...` without environment tweaks.
"""

from __future__ import annotations

import os
import sys


BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
