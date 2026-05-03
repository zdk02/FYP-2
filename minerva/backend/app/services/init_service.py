"""
Initialization service for default data
"""
from app import db
from app.models import User, MainCategory, SubCategory, SystemSettings
from sqlalchemy import inspect, text
from datetime import datetime
import json


def sync_schema_additions():
    """Idempotently add columns we've added to models since the DB was first created.

    SQLAlchemy's ``db.create_all()`` only creates *missing tables*. If the table
    already exists in an older SQLite database, newly-added columns won't show
    up and any API touching them will 500. We patch that here for the columns
    we know we've added.
    """
    inspector = inspect(db.engine)
    additions = {
        'system_settings': [
            ('category', "VARCHAR(50) DEFAULT 'general'"),
            ('is_secret', 'BOOLEAN DEFAULT 0'),
            ('updated_by', 'VARCHAR(36)'),
        ],
        'scan_jobs': [
            ('error_message', 'TEXT'),
        ],
        'attack_executions': [
            ('notes', 'TEXT'),
            ('engagement_id', 'VARCHAR(36)'),
            ('safe_mode', 'BOOLEAN DEFAULT 0'),
            ('dry_run', 'BOOLEAN DEFAULT 0'),
            ('replay_of', 'VARCHAR(36)'),
            ('dedup_key', 'VARCHAR(64)'),
        ],
        'campaigns': [
            ('engagement_id', 'VARCHAR(36)'),
        ],
        'audit_logs': [
            ('engagement_id', 'VARCHAR(36)'),
            ('prev_hash', 'VARCHAR(64)'),
            ('entry_hash', 'VARCHAR(64)'),
            ('sequence', 'INTEGER'),
        ],
        'attacks': [
            ('mcp_versions', 'TEXT'),
        ],
        'reports': [
            ('engagement_id', 'VARCHAR(36)'),
            ('template', "VARCHAR(50) DEFAULT 'technical'"),
        ],
    }
    with db.engine.begin() as conn:
        for table, cols in additions.items():
            if not inspector.has_table(table):
                continue
            existing = {c['name'] for c in inspector.get_columns(table)}
            for name, ddl in cols:
                if name in existing:
                    continue
                try:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}'))
                except Exception as e:  # noqa: BLE001 - tolerate any DB driver weirdness
                    print(f'[schema sync] could not add {table}.{name}: {e}')


def initialize_default_data():
    """Initialize the database with default data"""
    sync_schema_additions()
    
    # Create default users (one per role) for the FYP demo
    default_users = [
        ('admin',    'admin@minerva.local',    'admin',    'admin123'),
        ('operator', 'operator@minerva.local', 'operator', 'operator123'),
        ('analyst',  'analyst@minerva.local',  'analyst',  'analyst123'),
        ('viewer',   'viewer@minerva.local',   'viewer',   'viewer123'),
    ]
    for username, email, role, pw in default_users:
        if not User.query.filter_by(username=username).first():
            u = User(username=username, email=email, role=role, is_active=True)
            u.set_password(pw)
            db.session.add(u)
    
    # Create default categories
    default_categories = [
        {
            'name': 'MCP Attacks',
            'description': 'Model Context Protocol security testing attacks',
            'icon': 'server',
            'color': '#ef4444',
            'subcategories': [
                {'name': 'Client-Side Attacks', 'description': 'Attacks targeting MCP clients', 'icon': 'monitor', 'color': '#f97316'},
                {'name': 'Server-Side Attacks', 'description': 'Attacks targeting MCP servers', 'icon': 'database', 'color': '#eab308'},
                {'name': 'Data-in-Transit Attacks', 'description': 'MITM and interception attacks', 'icon': 'wifi', 'color': '#22c55e'},
                {'name': 'Tool Poisoning', 'description': 'Malicious tool injection attacks', 'icon': 'tool', 'color': '#06b6d4'},
                {'name': 'Prompt Injection', 'description': 'Prompt manipulation attacks', 'icon': 'terminal', 'color': '#8b5cf6'},
            ]
        },
        {
            'name': 'ACP Attacks',
            'description': 'Agent Communication Protocol security testing',
            'icon': 'users',
            'color': '#3b82f6',
            'subcategories': [
                {'name': 'Agent Impersonation', 'description': 'Identity spoofing attacks', 'icon': 'user-x', 'color': '#ec4899'},
                {'name': 'Message Tampering', 'description': 'Message manipulation attacks', 'icon': 'edit', 'color': '#f43f5e'},
                {'name': 'Coordination Exploits', 'description': 'Multi-agent coordination attacks', 'icon': 'git-branch', 'color': '#14b8a6'},
            ]
        },
        {
            'name': 'RAG System Attacks',
            'description': 'Retrieval-Augmented Generation attacks',
            'icon': 'search',
            'color': '#10b981',
            'subcategories': [
                {'name': 'Knowledge Poisoning', 'description': 'Vector DB poisoning attacks', 'icon': 'database', 'color': '#84cc16'},
                {'name': 'Retrieval Manipulation', 'description': 'Search result manipulation', 'icon': 'filter', 'color': '#06b6d4'},
                {'name': 'Context Overflow', 'description': 'Context window exploitation', 'icon': 'maximize', 'color': '#8b5cf6'},
            ]
        },
        {
            'name': 'LLM Attacks',
            'description': 'Large Language Model direct attacks',
            'icon': 'brain',
            'color': '#8b5cf6',
            'subcategories': [
                {'name': 'Jailbreaking', 'description': 'Bypass safety guardrails', 'icon': 'unlock', 'color': '#ef4444'},
                {'name': 'Data Extraction', 'description': 'Training data extraction', 'icon': 'download', 'color': '#f97316'},
                {'name': 'Model Manipulation', 'description': 'Adversarial inputs', 'icon': 'sliders', 'color': '#eab308'},
            ]
        },
        {
            'name': 'Agent Infrastructure',
            'description': 'Infrastructure-level attacks',
            'icon': 'layers',
            'color': '#f59e0b',
            'subcategories': [
                {'name': 'Container Escape', 'description': 'Sandbox breakout attacks', 'icon': 'box', 'color': '#ef4444'},
                {'name': 'Resource Exhaustion', 'description': 'DoS and resource attacks', 'icon': 'activity', 'color': '#f97316'},
                {'name': 'Privilege Escalation', 'description': 'Permission escalation', 'icon': 'shield', 'color': '#dc2626'},
            ]
        },
    ]
    
    for cat_data in default_categories:
        if not MainCategory.query.filter_by(name=cat_data['name']).first():
            main_cat = MainCategory(
                name=cat_data['name'],
                description=cat_data['description'],
                icon=cat_data['icon'],
                color=cat_data['color'],
                is_active=True
            )
            db.session.add(main_cat)
            db.session.flush()
            
            for sub_data in cat_data.get('subcategories', []):
                sub_cat = SubCategory(
                    name=sub_data['name'],
                    description=sub_data['description'],
                    icon=sub_data['icon'],
                    color=sub_data['color'],
                    main_category_id=main_cat.id,
                    is_active=True
                )
                db.session.add(sub_cat)
    
    # Create default system settings
    default_settings = [
        {'key': 'max_concurrent_attacks', 'value': '10', 'value_type': 'integer', 'description': 'Maximum concurrent attack executions'},
        {'key': 'default_timeout', 'value': '300', 'value_type': 'integer', 'description': 'Default attack timeout in seconds'},
        {'key': 'enable_auto_reporting', 'value': 'true', 'value_type': 'boolean', 'description': 'Auto-generate reports after campaigns'},
        {'key': 'report_format', 'value': 'pdf', 'value_type': 'string', 'description': 'Default report format'},
        {'key': 'scan_rate_limit', 'value': '100', 'value_type': 'integer', 'description': 'Scan requests per second limit'},
        {'key': 'evidence_retention_days', 'value': '90', 'value_type': 'integer', 'description': 'Days to retain evidence files'},
    ]
    
    for setting in default_settings:
        if not SystemSettings.query.filter_by(key=setting['key']).first():
            db.session.add(SystemSettings(**setting))
    
    # Seed the default "FYP Demo" engagement so the scope gate doesn't
    # break the out-of-the-box demo flow.
    try:
        from app.models import Engagement
        existing = Engagement.query.filter_by(name='FYP Demo').first()
        if not existing:
            from datetime import timedelta
            import secrets
            owner = User.query.filter_by(username='admin').first()
            eng = Engagement(
                name='FYP Demo',
                client_name='Final Year Project Demonstration',
                description=(
                    'Default engagement for the Minerva FYP demo. '
                    'Allowlists localhost + RFC1918 ranges.'
                ),
                signed_off_by='Minerva FYP author (self-authorised demo)',
                rules_of_engagement=(
                    'Demo only. Use against bundled demo_mcp_server or '
                    'your own deliberately-vulnerable lab targets.'
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
                health_threshold_x=5.0,
                created_by=owner.id if owner else None,
            )
            Engagement.query.filter(
                Engagement.is_active_default == True  # noqa: E712
            ).update({'is_active_default': False})
            db.session.add(eng)
    except Exception as e:
        print(f"  [warn] could not seed default engagement: {e}")

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing default data: {e}")
