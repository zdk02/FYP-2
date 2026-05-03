"""
Seed the default "FYP Demo" engagement.

Idempotent. Run after seed_pro_attacks.py to make the existing demo
flow keep working through the new engagement scope-gate:

    python -m scripts.seed_default_engagement

This creates an engagement with:
- name: FYP Demo
- authorized_targets: 127.0.0.1, localhost, ::1, 10.0.0.0/8, 192.168.0.0/16
- max_requests: 100000
- safe_mode: False (demo runs include destructive PoCs)
- is_active_default: True
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from datetime import datetime, timedelta


def _here():
    return os.path.dirname(os.path.abspath(__file__))


def _ensure_app():
    backend_dir = os.path.dirname(_here())
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    try:
        from flask import current_app
        _ = current_app._get_current_object()
        return None
    except Exception:
        pass
    from app import create_app
    app = create_app(os.environ.get("FLASK_ENV", "development"))
    app.app_context().push()
    return app


def main():
    _ensure_app()
    from app import db
    from app.models import Engagement, User

    # Find the admin user to attribute creation to
    owner = User.query.filter_by(username='admin').first()
    owner_id = owner.id if owner else None

    existing = Engagement.query.filter_by(name='FYP Demo').first()
    if existing:
        print(f"  [exists] FYP Demo engagement {existing.id}")
        # Always demote others, promote this one
        Engagement.query.filter(
            Engagement.id != existing.id,
            Engagement.is_active_default == True  # noqa: E712
        ).update({'is_active_default': False})
        existing.is_active_default = True
        existing.status = 'active'
        db.session.commit()
        print("  [+] re-activated FYP Demo as default")
        return

    eng = Engagement(
        name='FYP Demo',
        client_name='Final Year Project Demonstration',
        description=(
            'Default engagement for the Minerva FYP demo. Allowlists '
            'localhost + RFC1918 ranges so all built-in demo flows run '
            'through the same preflight gate as a real engagement.'
        ),
        signed_off_by='Minerva FYP author (self-authorised demo)',
        rules_of_engagement=(
            'Demo only. Use against the bundled demo_mcp_server or your '
            'own deliberately-vulnerable lab targets. Do NOT widen the '
            'authorized_targets allowlist for live demos.'
        ),
        authorized_targets=json.dumps([
            '127.0.0.1', 'localhost', '::1',
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        ]),
        time_window_start=datetime.utcnow() - timedelta(hours=1),
        time_window_end=datetime.utcnow() + timedelta(days=365),
        max_requests=1000000,
        max_wall_seconds=86400,
        max_concurrent=8,
        safe_mode=False,
        dry_run_default=False,
        webhook_secret=secrets.token_hex(16),
        notify_min_severity='high',
        status='active',
        is_active_default=True,
        health_threshold_x=5.0,  # demo target may be slow; 5x baseline
        created_by=owner_id,
    )
    # Demote any other defaults
    Engagement.query.filter(
        Engagement.is_active_default == True  # noqa: E712
    ).update({'is_active_default': False})

    db.session.add(eng)
    db.session.commit()
    print(f"  [+] Created FYP Demo engagement {eng.id} (active default).")
    print(f"      Allowlist: 127.0.0.1, localhost, ::1, 10.0.0.0/8, "
          "172.16.0.0/12, 192.168.0.0/16")


if __name__ == '__main__':
    main()
