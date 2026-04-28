"""
Database models for AEGIS Platform
"""
from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json
import uuid

# Association tables
attack_payloads = db.Table('attack_payloads',
    db.Column('attack_id', db.String(36), db.ForeignKey('attacks.id'), primary_key=True),
    db.Column('payload_id', db.String(36), db.ForeignKey('payloads.id'), primary_key=True)
)

attack_techniques = db.Table('attack_techniques',
    db.Column('attack_id', db.String(36), db.ForeignKey('attacks.id'), primary_key=True),
    db.Column('technique_id', db.String(36), db.ForeignKey('techniques.id'), primary_key=True)
)

campaign_attacks = db.Table('campaign_attacks',
    db.Column('campaign_id', db.String(36), db.ForeignKey('campaigns.id'), primary_key=True),
    db.Column('attack_id', db.String(36), db.ForeignKey('attacks.id'), primary_key=True)
)

campaign_targets = db.Table('campaign_targets',
    db.Column('campaign_id', db.String(36), db.ForeignKey('campaigns.id'), primary_key=True),
    db.Column('target_id', db.String(36), db.ForeignKey('targets.id'), primary_key=True)
)


class User(db.Model):
    """User model with role-based access control"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='operator')  # admin, manager, operator, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    campaigns = db.relationship('Campaign', backref='owner', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class MainCategory(db.Model):
    """Main attack categories (MCP, ACP, RAG, etc.)"""
    __tablename__ = 'main_categories'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50))
    color = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    subcategories = db.relationship('SubCategory', backref='main_category', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self, include_subcategories=False):
        subcats = self.subcategories.filter_by(is_active=True).all()
        total_attacks = sum(s.attacks.filter_by(is_active=True).count() for s in subcats)
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'color': self.color,
            'is_active': self.is_active,
            'order': self.order,
            'attack_count': total_attacks,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_subcategories:
            data['subcategories'] = [s.to_dict() for s in subcats]
        return data


class SubCategory(db.Model):
    """Sub-categories (Client-side, Server-side, etc.)"""
    __tablename__ = 'sub_categories'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50))
    color = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, default=0)
    main_category_id = db.Column(db.String(36), db.ForeignKey('main_categories.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    attacks = db.relationship('Attack', backref='subcategory', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self, include_attacks=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'color': self.color,
            'is_active': self.is_active,
            'order': self.order,
            'main_category_id': self.main_category_id,
            'attack_count': self.attacks.filter_by(is_active=True).count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_attacks:
            data['attacks'] = [a.to_dict() for a in self.attacks.filter_by(is_active=True).all()]
        return data


class Attack(db.Model):
    """Individual attack definitions"""
    __tablename__ = 'attacks'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default='medium')  # critical, high, medium, low, info
    attack_type = db.Column(db.String(50))  # injection, reconnaissance, exploitation, etc.
    mitre_id = db.Column(db.String(20))  # MITRE ATT&CK ID if applicable
    cve_ids = db.Column(db.Text)  # JSON array of CVE IDs
    
    # Script configuration
    script_path = db.Column(db.String(500))
    script_content = db.Column(db.Text)
    script_language = db.Column(db.String(20), default='python')  # python, bash, ruby, etc.
    
    # Configuration schema (JSON Schema for dynamic form generation)
    config_schema = db.Column(db.Text)
    default_config = db.Column(db.Text)
    
    # Execution settings
    requires_authentication = db.Column(db.Boolean, default=False)
    timeout = db.Column(db.Integer, default=300)
    parallel_safe = db.Column(db.Boolean, default=True)
    
    # Metadata
    author = db.Column(db.String(100))
    version = db.Column(db.String(20), default='1.0.0')
    tags = db.Column(db.Text)  # JSON array
    references = db.Column(db.Text)  # JSON array of reference URLs
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Relationships
    subcategory_id = db.Column(db.String(36), db.ForeignKey('sub_categories.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    payloads = db.relationship('Payload', secondary=attack_payloads, lazy='subquery',
                               backref=db.backref('attacks', lazy=True))
    techniques = db.relationship('Technique', secondary=attack_techniques, lazy='subquery',
                                 backref=db.backref('attacks', lazy=True))
    executions = db.relationship('AttackExecution', backref='attack', lazy='dynamic')
    
    def to_dict(self, include_script=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'attack_type': self.attack_type,
            'mitre_id': self.mitre_id,
            'cve_ids': json.loads(self.cve_ids) if self.cve_ids else [],
            'script_language': self.script_language,
            'config_schema': json.loads(self.config_schema) if self.config_schema else {},
            'default_config': json.loads(self.default_config) if self.default_config else {},
            'requires_authentication': self.requires_authentication,
            'timeout': self.timeout,
            'parallel_safe': self.parallel_safe,
            'author': self.author,
            'version': self.version,
            'tags': json.loads(self.tags) if self.tags else [],
            'references': json.loads(self.references) if self.references else [],
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'subcategory_id': self.subcategory_id,
            'payloads': [p.to_dict() for p in self.payloads],
            'techniques': [t.to_dict() for t in self.techniques],
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_script:
            data['script_content'] = self.script_content
            data['script_path'] = self.script_path
        return data


class Payload(db.Model):
    """Reusable attack payloads"""
    __tablename__ = 'payloads'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    payload_type = db.Column(db.String(50))  # injection, malformed_input, overflow, etc.
    content = db.Column(db.Text, nullable=False)
    encoding = db.Column(db.String(20))  # base64, hex, url, etc.
    is_active = db.Column(db.Boolean, default=True)
    tags = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'payload_type': self.payload_type,
            'content': self.content,
            'encoding': self.encoding,
            'is_active': self.is_active,
            'tags': json.loads(self.tags) if self.tags else [],
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Technique(db.Model):
    """Attack techniques (can be shared across attacks)"""
    __tablename__ = 'techniques'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    mitre_id = db.Column(db.String(20))
    tactic = db.Column(db.String(50))  # reconnaissance, initial_access, execution, etc.
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'mitre_id': self.mitre_id,
            'tactic': self.tactic,
            'is_active': self.is_active
        }


class ConnectionScript(db.Model):
    """Dynamic connection scripts for different server types"""
    __tablename__ = 'connection_scripts'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    server_type = db.Column(db.String(50), nullable=False)  # mcp_server, acp_server, rest_api, graphql, websocket, etc.
    protocol = db.Column(db.String(20))  # http, https, ws, wss, tcp, etc.
    script_content = db.Column(db.Text, nullable=False)
    script_language = db.Column(db.String(20), default='python')
    config_schema = db.Column(db.Text)  # JSON Schema for connection parameters
    default_config = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self, include_script=True):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'server_type': self.server_type,
            'protocol': self.protocol,
            'script_language': self.script_language,
            'config_schema': json.loads(self.config_schema) if self.config_schema else {},
            'default_config': json.loads(self.default_config) if self.default_config else {},
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_script:
            data['script_content'] = self.script_content
        return data


class Target(db.Model):
    """Target systems/infrastructure"""
    __tablename__ = 'targets'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    target_type = db.Column(db.String(50), nullable=False)  # mcp_server, acp_server, llm_endpoint, etc.
    
    # Connection details
    host = db.Column(db.String(255))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    base_url = db.Column(db.String(500))
    
    # Authentication
    auth_type = db.Column(db.String(30))  # none, api_key, oauth, basic, jwt, etc.
    auth_config = db.Column(db.Text)  # JSON encrypted credentials config
    
    # Connection script reference
    connection_script_id = db.Column(db.String(36), db.ForeignKey('connection_scripts.id'))
    custom_config = db.Column(db.Text)  # Additional JSON config
    
    # Metadata
    environment = db.Column(db.String(20))  # production, staging, development
    tags = db.Column(db.Text)
    notes = db.Column(db.Text)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    last_scanned = db.Column(db.DateTime)
    last_scan_result = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    connection_script = db.relationship('ConnectionScript', backref='targets')
    discovered_endpoints = db.relationship('DiscoveredEndpoint', backref='target', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'target_type': self.target_type,
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'base_url': self.base_url,
            'auth_type': self.auth_type,
            'connection_script_id': self.connection_script_id,
            'custom_config': json.loads(self.custom_config) if self.custom_config else {},
            'environment': self.environment,
            'tags': json.loads(self.tags) if self.tags else [],
            'notes': self.notes,
            'is_active': self.is_active,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class DiscoveredEndpoint(db.Model):
    """Endpoints discovered during scanning"""
    __tablename__ = 'discovered_endpoints'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = db.Column(db.String(36), db.ForeignKey('targets.id'), nullable=False)
    endpoint_path = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10))
    description = db.Column(db.Text)
    parameters = db.Column(db.Text)  # JSON
    response_schema = db.Column(db.Text)  # JSON
    is_vulnerable = db.Column(db.Boolean, default=False)
    vulnerability_notes = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_id': self.target_id,
            'endpoint_path': self.endpoint_path,
            'method': self.method,
            'description': self.description,
            'parameters': json.loads(self.parameters) if self.parameters else {},
            'is_vulnerable': self.is_vulnerable,
            'vulnerability_notes': self.vulnerability_notes,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }


class Campaign(db.Model):
    """Pentest campaigns/engagements"""
    __tablename__ = 'campaigns'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    
    # Campaign settings
    campaign_type = db.Column(db.String(30))  # external, internal, red_team, etc.
    mode = db.Column(db.String(20), default='manual')  # manual, automated, hybrid
    scenario = db.Column(db.String(50))  # direct_connection, legitimate_client, mitm, etc.
    
    # Scope
    scope_definition = db.Column(db.Text)  # JSON defining in-scope/out-of-scope
    rules_of_engagement = db.Column(db.Text)
    
    # Status
    status = db.Column(db.String(20), default='draft')  # draft, active, paused, completed, archived
    progress = db.Column(db.Integer, default=0)
    
    # Timing
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    
    # Owner
    owner_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    attacks = db.relationship('Attack', secondary=campaign_attacks, lazy='subquery',
                              backref=db.backref('campaigns', lazy=True))
    targets = db.relationship('Target', secondary=campaign_targets, lazy='subquery',
                              backref=db.backref('campaigns', lazy=True))
    executions = db.relationship('AttackExecution', backref='campaign', lazy='dynamic')
    reports = db.relationship('Report', backref='campaign', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'campaign_type': self.campaign_type,
            'mode': self.mode,
            'scenario': self.scenario,
            'scope_definition': json.loads(self.scope_definition) if self.scope_definition else {},
            'rules_of_engagement': self.rules_of_engagement,
            'status': self.status,
            'progress': self.progress,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'owner_id': self.owner_id,
            'attacks_count': len(self.attacks),
            'targets_count': len(self.targets),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AttackExecution(db.Model):
    """Individual attack execution records"""
    __tablename__ = 'attack_executions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # References
    attack_id = db.Column(db.String(36), db.ForeignKey('attacks.id'), nullable=False)
    target_id = db.Column(db.String(36), db.ForeignKey('targets.id'), nullable=False)
    campaign_id = db.Column(db.String(36), db.ForeignKey('campaigns.id'))
    executed_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    
    # Execution config
    config_used = db.Column(db.Text)  # JSON config used for this execution
    payloads_used = db.Column(db.Text)  # JSON array of payload IDs
    
    # Results
    status = db.Column(db.String(20), default='pending')  # pending, running, success, failed, error, timeout
    result = db.Column(db.String(20))  # vulnerable, not_vulnerable, inconclusive
    severity_found = db.Column(db.String(20))
    
    # Output
    output = db.Column(db.Text)
    error_message = db.Column(db.Text)
    evidence = db.Column(db.Text)  # JSON array of evidence items (screenshots, logs, etc.)
    notes = db.Column(db.Text)

    # Timing
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    target = db.relationship('Target', backref='executions')
    executor = db.relationship('User', backref='executions')
    
    def to_dict(self):
        return {
            'id': self.id,
            'attack_id': self.attack_id,
            'target_id': self.target_id,
            'campaign_id': self.campaign_id,
            'executed_by': self.executed_by,
            'config_used': json.loads(self.config_used) if self.config_used else {},
            'status': self.status,
            'result': self.result,
            'severity_found': self.severity_found,
            'output': self.output,
            'error_message': self.error_message,
            'evidence': json.loads(self.evidence) if self.evidence else [],
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Report(db.Model):
    """Generated reports"""
    __tablename__ = 'reports'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = db.Column(db.String(36), db.ForeignKey('campaigns.id'), nullable=False)
    
    name = db.Column(db.String(200), nullable=False)
    report_type = db.Column(db.String(30))  # executive, technical, compliance
    format = db.Column(db.String(10))  # pdf, html, json, csv
    
    # Content
    content = db.Column(db.Text)  # JSON structured report data
    file_path = db.Column(db.String(500))
    
    # Summary
    total_attacks = db.Column(db.Integer, default=0)
    successful_attacks = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    high_findings = db.Column(db.Integer, default=0)
    medium_findings = db.Column(db.Integer, default=0)
    low_findings = db.Column(db.Integer, default=0)
    
    # Recommendations
    recommendations = db.Column(db.Text)  # JSON array
    
    generated_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    generator = db.relationship('User', backref='reports')
    
    def to_dict(self):
        return {
            'id': self.id,
            'campaign_id': self.campaign_id,
            'name': self.name,
            'report_type': self.report_type,
            'format': self.format,
            'file_path': self.file_path,
            'total_attacks': self.total_attacks,
            'successful_attacks': self.successful_attacks,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'recommendations': json.loads(self.recommendations) if self.recommendations else [],
            'generated_by': self.generated_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ScanJob(db.Model):
    """Network/target scanning jobs"""
    __tablename__ = 'scan_jobs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    scan_type = db.Column(db.String(30), nullable=False)  # network_discovery, port_scan, service_enum, vulnerability

    # Scan configuration
    target_range = db.Column(db.String(500))  # IP range, CIDR, domain list
    scan_config = db.Column(db.Text)  # JSON config

    # Status
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)

    # Results
    results = db.Column(db.Text)  # JSON results
    discovered_hosts = db.Column(db.Integer, default=0)
    discovered_services = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)

    # Timing
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    initiated_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    initiator = db.relationship('User', backref='scans')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'scan_type': self.scan_type,
            'target_range': self.target_range,
            'scan_config': json.loads(self.scan_config) if self.scan_config else {},
            'status': self.status,
            'progress': self.progress,
            'results': json.loads(self.results) if self.results else {},
            'discovered_hosts': self.discovered_hosts,
            'discovered_services': self.discovered_services,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'initiated_by': self.initiated_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AuditLog(db.Model):
    """Audit trail for all actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(36))
    details = db.Column(db.Text)  # JSON
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': json.loads(self.details) if self.details else {},
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class OOBToken(db.Model):
    """Out-of-band canary token. Minted by attacks for side-channel proof
    of blind vulnerabilities (command injection, SSRF, RCE, SQLi OOB)."""
    __tablename__ = 'oob_tokens'

    token = db.Column(db.String(64), primary_key=True)
    attack_id = db.Column(db.String(64), index=True)
    metadata_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, index=True)

    hits = db.relationship('OOBHit', backref='token_row', lazy='dynamic',
                           cascade='all, delete-orphan')


class OOBHit(db.Model):
    """One inbound hit against an OOB token — proof of exploitation."""
    __tablename__ = 'oob_hits'

    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    token_id = db.Column(db.String(64), db.ForeignKey('oob_tokens.token'),
                         nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45))
    method = db.Column(db.String(10))
    path = db.Column(db.String(500))
    headers_json = db.Column(db.Text)
    query_json = db.Column(db.Text)
    body = db.Column(db.Text)


class ReverseShellSession(db.Model):
    """Metadata for a reverse-shell listener port + any captured sessions."""
    __tablename__ = 'rs_sessions'

    token = db.Column(db.String(64), primary_key=True)
    attack_id = db.Column(db.String(64), index=True)
    host = db.Column(db.String(120))
    port = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, index=True)
    closed_at = db.Column(db.DateTime)
    remote_ip = db.Column(db.String(45))
    remote_port = db.Column(db.Integer)
    captured_bytes = db.Column(db.Integer, default=0)
    captured_preview = db.Column(db.Text)


class MITMProxySession(db.Model):
    """Metadata for a spun-up MITM proxy + its captured flows."""
    __tablename__ = 'mitm_sessions'

    token = db.Column(db.String(64), primary_key=True)
    attack_id = db.Column(db.String(64), index=True)
    proxy_host = db.Column(db.String(120))
    proxy_port = db.Column(db.Integer)
    upstream_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, index=True)
    flow_count = db.Column(db.Integer, default=0)


class SystemSettings(db.Model):
    """System-wide settings"""
    __tablename__ = 'system_settings'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20))  # string, integer, boolean, json
    description = db.Column(db.Text)
    category = db.Column(db.String(50), default='general')
    is_editable = db.Column(db.Boolean, default=True)
    is_secret = db.Column(db.Boolean, default=False)
    updated_by = db.Column(db.String(36), db.ForeignKey('users.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value if not self.is_secret else '********',
            'value_type': self.value_type,
            'description': self.description,
            'category': self.category,
            'is_editable': self.is_editable,
            'is_secret': self.is_secret,
        }
