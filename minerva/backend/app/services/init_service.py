"""
Initialization service for default data
"""
from app import db
from app.models import User, MainCategory, SubCategory, SystemSettings
from sqlalchemy import inspect, text
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
    
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@minerva.local',
            role='admin',
            is_active=True
        )
        admin.set_password('admin123')  # Change in production
        db.session.add(admin)
    
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
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing default data: {e}")
