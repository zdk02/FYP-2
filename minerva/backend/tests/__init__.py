"""Minerva backend test package.

Sets MINERVA_BYPASS_PREFLIGHT=1 so unit tests that exercise
attack_runner with synthetic targets aren't gated by the engagement
preflight (which is correctly enforced in real demos via the FYP Demo
engagement allowlist).
"""

import os

os.environ.setdefault("MINERVA_BYPASS_PREFLIGHT", "1")
