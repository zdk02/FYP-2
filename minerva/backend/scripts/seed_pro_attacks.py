"""
Seed Minerva's pro-grade MCP attack pack into the database.

Reads every ``.py`` file referenced by ``backend/data/pro_attacks/_manifest.json``,
upserts an ``attacks`` row per entry, attaches it to the right
sub-category (creating it if missing), and marks them ``is_verified=True``.

Also runs the payload library seeder so attack scripts that call
``payloads.get(...)`` immediately have data.

Run from a Flask app context:

    # Native:
    cd backend
    python -m scripts.seed_pro_attacks

    # Docker:
    docker exec -it aegis-backend python -m scripts.seed_pro_attacks
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime


def _here():
    return os.path.dirname(os.path.abspath(__file__))


def _ensure_app():
    """Ensure we have a Flask app context; run standalone-friendly."""
    backend_dir = os.path.dirname(_here())
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    # Test for an existing context cheaply. If this raises, we need one.
    try:
        from flask import current_app
        _ = current_app._get_current_object()  # force resolution
        return None
    except Exception:
        pass
    from app import create_app
    app = create_app(os.environ.get("FLASK_ENV", "development"))
    app.app_context().push()
    return app


def load_manifest(subdir="pro_attacks"):
    mpath = os.path.join(os.path.dirname(_here()), "data",
                         subdir, "_manifest.json")
    with open(mpath, "r", encoding="utf-8") as f:
        return json.load(f), os.path.dirname(mpath)


def load_script(base_dir, filename):
    p = os.path.join(base_dir, filename)
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def ensure_subcategory(db, MainCategory, SubCategory, name):
    sub = SubCategory.query.filter_by(name=name).first()
    if sub:
        return sub
    # Fall back to the first "MCP Attacks" main cat if present, else create it
    main = (MainCategory.query.filter_by(name="MCP Attacks").first()
            or MainCategory.query.first())
    if not main:
        main = MainCategory(
            name="MCP Attacks",
            description="Model Context Protocol security testing",
            icon="server", color="#ef4444", is_active=True,
        )
        db.session.add(main)
        db.session.flush()
    sub = SubCategory(
        name=name,
        description=f"{name} (auto-created by pro attack seeder)",
        main_category_id=main.id,
        is_active=True,
    )
    db.session.add(sub)
    db.session.flush()
    return sub


NETWORK_KNOBS_SCHEMA = {
    "network_profile": {
        "type": "string",
        "title": "Network profile",
        "default": "aggressive",
        "enum": ["aggressive", "balanced", "stealth", "custom"],
        "description": (
            "How loud to be. aggressive=fastest (no delay, full concurrency); "
            "balanced=light pacing; stealth=slow + jittered + low rps to evade "
            "rate-limits and IDS; custom=use the numeric overrides below."
        ),
    },
    "request_delay_ms": {
        "type": "integer", "title": "Request delay (ms)", "default": 0,
        "minimum": 0, "maximum": 60000,
        "description": "Sleep before every MCP call. Override the profile default.",
    },
    "jitter_ms": {
        "type": "integer", "title": "Jitter (± ms)", "default": 0,
        "minimum": 0, "maximum": 60000,
        "description": "Uniform random jitter added on top of request_delay_ms.",
    },
    "max_concurrency": {
        "type": "integer", "title": "Max concurrent calls", "default": 16,
        "minimum": 1, "maximum": 256,
        "description": "Cap on parallel MCP requests this attack may issue.",
    },
    "max_rps": {
        "type": "integer", "title": "Max requests / sec", "default": 0,
        "minimum": 0, "maximum": 5000,
        "description": "Token-bucket cap. 0 = unlimited.",
    },
}

NETWORK_KNOBS_DEFAULTS = {
    "network_profile": "aggressive",
    # The numeric knobs default to 0 / 16 — meaning "let the profile decide"
    # unless explicitly overridden by the user.
    "request_delay_ms": 0,
    "jitter_ms": 0,
    "max_concurrency": 16,
    "max_rps": 0,
}


def _merge_network_knobs(spec: dict) -> tuple[dict, dict]:
    schema = dict(spec.get("config_schema") or {})
    defaults = dict(spec.get("default_config") or {})
    # Don't overwrite if a manifest entry has already declared one of these.
    for k, v in NETWORK_KNOBS_SCHEMA.items():
        schema.setdefault(k, v)
    for k, v in NETWORK_KNOBS_DEFAULTS.items():
        defaults.setdefault(k, v)
    return schema, defaults


def upsert_attack(db, Attack, spec, subcategory_id, script_content):
    existing = Attack.query.filter_by(name=spec["name"]).first()
    now = datetime.utcnow()
    config_schema, default_config = _merge_network_knobs(spec)
    fields = dict(
        name=spec["name"],
        description=spec.get("description", ""),
        severity=spec.get("severity", "medium"),
        attack_type=spec.get("attack_type"),
        mitre_id=spec.get("mitre_id"),
        cve_ids=json.dumps(spec.get("cve_ids", [])),
        script_path=f"data/pro_attacks/{spec['file']}",
        script_content=script_content,
        script_language="python",
        config_schema=json.dumps(config_schema),
        default_config=json.dumps(default_config),
        requires_authentication=False,
        timeout=spec.get("timeout", 300),
        parallel_safe=False,
        author="Minerva Pro Attack Pack v1",
        version="1.0.0",
        tags=json.dumps(spec.get("tags") or []),
        references=json.dumps(spec.get("references") or []),
        is_active=True,
        is_verified=True,
        subcategory_id=subcategory_id,
        updated_at=now,
    )
    if existing:
        # Preserve is_active on updates — if an admin has disabled an
        # attack (e.g. via the dedupe sweep), the seeder must not silently
        # re-enable it on every run.
        preserved_active = existing.is_active
        for k, v in fields.items():
            setattr(existing, k, v)
        existing.is_active = preserved_active
        return existing, "updated"
    attack = Attack(id=str(uuid.uuid4()), created_at=now, **fields)
    db.session.add(attack)
    return attack, "inserted"


def main():
    _ensure_app()
    from app import db
    from app.models import Attack, MainCategory, SubCategory

    total_inserted = total_updated = total_failed = 0
    for subdir in ("pro_attacks", "refined_attacks"):
        mpath = os.path.join(os.path.dirname(_here()), "data",
                             subdir, "_manifest.json")
        if not os.path.exists(mpath):
            print(f"  [skip] {subdir}: no manifest")
            continue
        print(f"\n=== Seeding from {subdir}/ ===")
        manifest, base_dir = load_manifest(subdir)
        specs = manifest.get("attacks", [])
        for spec in specs:
            try:
                script = load_script(base_dir, spec["file"])
            except Exception as e:
                print(f"  [x] Could not read {spec['file']}: {e}")
                total_failed += 1
                continue
            sub = ensure_subcategory(db, MainCategory, SubCategory,
                                     spec["subcategory"])
            _, action = upsert_attack(db, Attack, spec, sub.id, script)
            print(f"  [+] {action:8s} {spec['name']} -> {spec['subcategory']}")
            if action == "inserted":
                total_inserted += 1
            elif action == "updated":
                total_updated += 1
        db.session.commit()
    inserted, updated, failed = total_inserted, total_updated, total_failed

    # Seed payload library as well
    from app.services.payload_library import seed_payload_library
    pl = seed_payload_library()
    print(f"\n  Payload library: inserted={pl['inserted']}, "
          f"updated={pl['updated']}, skipped={pl['skipped']}, "
          f"total_seed={pl['total_seed']}")

    print(f"\n Attacks: inserted={inserted}, updated={updated}, failed={failed}")
    print("Done. Restart not required; the next attack run picks up the new scripts.")


if __name__ == "__main__":
    main()
