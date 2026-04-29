"""
Attack execution service - handles running attacks against targets
"""
import subprocess
import tempfile
import os
import json
import threading
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from app import db
from app.models import Attack, Target, AttackExecution, Campaign, ConnectionScript
import uuid


class AttackExecutor:
    """Handles attack execution"""
    
    def __init__(self, max_workers=10, timeout=300):
        self.max_workers = max_workers
        self.default_timeout = timeout
        self.active_executions = {}
        self.execution_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def execute_attack(self, attack_id, target_id, config, user_id, campaign_id=None):
        """Execute a single attack against a target"""
        attack = Attack.query.get(attack_id)
        target = Target.query.get(target_id)
        
        if not attack or not target:
            return {'error': 'Attack or target not found'}
        
        # Create execution record
        execution = AttackExecution(
            id=str(uuid.uuid4()),
            attack_id=attack_id,
            target_id=target_id,
            campaign_id=campaign_id,
            executed_by=user_id,
            config_used=json.dumps(config),
            status='pending'
        )
        db.session.add(execution)
        db.session.commit()
        
        # Submit to executor
        future = self.executor.submit(
            self._run_attack,
            execution.id,
            attack,
            target,
            config
        )
        
        self.active_executions[execution.id] = {
            'future': future,
            'execution': execution
        }
        
        return {'execution_id': execution.id, 'status': 'submitted'}
    
    def _run_attack(self, execution_id, attack, target, config):
        """Internal method to run the attack script"""
        from app import create_app
        app = create_app()
        
        with app.app_context():
            execution = AttackExecution.query.get(execution_id)
            if not execution:
                return
            
            execution.status = 'running'
            execution.started_at = datetime.utcnow()
            db.session.commit()
            
            try:
                script_content = attack.script_content
                if not script_content:
                    execution.status = 'error'
                    execution.error_message = 'No script content defined'
                    db.session.commit()
                    return

                # Normalise target into the dict shape attacks expect.
                from app.services import attack_runner
                target_dict = attack_runner.prepare_target_dict({
                    'host': target.host,
                    'port': target.port,
                    'protocol': target.protocol,
                    'base_url': target.base_url,
                    'target_type': target.target_type,
                }, target_row=target)

                language = (attack.script_language or 'python').lower()

                if language == 'python':
                    # In-process — pro attacks can use mcp_client, oob,
                    # payloads, evidence directly.
                    script_result = attack_runner.run_python_attack(
                        script_content,
                        target=target_dict,
                        params=config or {},
                        attack_id=attack.id,
                        timeout=attack.timeout or self.default_timeout,
                        execution_id=execution.id,
                    )
                else:
                    # Subprocess fallback for bash/ruby/js scripts.
                    env = self._build_execution_env(target, config)
                    # Optional connection-script preamble kept for back-compat.
                    connection_code = ''
                    if target.connection_script_id:
                        conn = ConnectionScript.query.get(target.connection_script_id)
                        if conn:
                            connection_code = conn.script_content or ''
                    full_script = self._build_full_script(
                        connection_code, script_content, config, target)
                    script_result = attack_runner.run_subprocess_attack(
                        full_script, language, target_dict, config or {},
                        env, timeout=attack.timeout or self.default_timeout)

                findings = script_result.get('findings') or []
                execution.output = json.dumps({
                    'summary': script_result.get('summary'),
                    'logs': (script_result.get('logs') or [])[-200:],
                })
                execution.evidence = json.dumps({
                    'findings': findings,
                    'evidence': script_result.get('evidence') or [],
                })
                execution.status = 'success' if script_result.get('success') else 'failed'
                execution.result = 'vulnerable' if findings else 'not_vulnerable'
                # Highest-severity finding drives severity_found
                sev_order = {'critical': 4, 'high': 3, 'medium': 2,
                             'low': 1, 'info': 0}
                if findings:
                    top = max((f.get('severity', 'info') for f in findings),
                              key=lambda s: sev_order.get(str(s).lower(), -1))
                    execution.severity_found = top

                try:
                    from app.services import notifier as _notifier
                    target_dict = {
                        'host': target.host,
                        'port': target.port,
                        'base_url': target.base_url,
                    }
                    campaign_name = None
                    if execution.campaign_id:
                        from app.models.models import Campaign as _Campaign
                        _camp = _Campaign.query.get(execution.campaign_id)
                        campaign_name = _camp.name if _camp else None
                    for _f in findings:
                        _notifier.notify_finding(_f, target=target_dict,
                                                 campaign_name=campaign_name)
                except Exception:
                    pass

            except Exception as e:
                execution.status = 'error'
                execution.error_message = str(e)
            finally:
                execution.completed_at = datetime.utcnow()
                if execution.started_at:
                    execution.duration_seconds = int(
                        (execution.completed_at - execution.started_at).total_seconds()
                    )
                db.session.commit()
                if execution.campaign_id:
                    try:
                        from app.api.executions import update_campaign_progress
                        update_campaign_progress(execution.campaign_id)
                    except Exception:
                        pass
    
    def _build_execution_env(self, target, config):
        """Build environment variables for script execution"""
        env = os.environ.copy()
        
        # Add target information
        env['AEGIS_TARGET_HOST'] = target.host or ''
        env['AEGIS_TARGET_PORT'] = str(target.port or '')
        env['AEGIS_TARGET_PROTOCOL'] = target.protocol or ''
        env['AEGIS_TARGET_URL'] = target.base_url or ''
        env['AEGIS_TARGET_TYPE'] = target.target_type or ''
        
        # Add authentication info (encrypted in production)
        if target.auth_config:
            auth = json.loads(target.auth_config)
            env['AEGIS_AUTH_TYPE'] = target.auth_type or ''
            for key, value in auth.items():
                env[f'AEGIS_AUTH_{key.upper()}'] = str(value)
        
        # Add custom config
        env['AEGIS_CONFIG'] = json.dumps(config)
        
        return env
    
    def _build_full_script(self, connection_code, attack_code, config, target):
        """Build the complete script with connection handling"""
        
        preamble = f'''
# AEGIS Attack Execution Preamble
import os
import json
import sys

# Target configuration
TARGET_CONFIG = {{
    'host': {repr(target.host)},
    'port': {target.port},
    'protocol': {repr(target.protocol)},
    'base_url': {repr(target.base_url)},
    'target_type': {repr(target.target_type)},
    'auth_type': {repr(target.auth_type)},
}}

# Attack configuration
ATTACK_CONFIG = {json.dumps(config)}

# Result helper
def aegis_result(result, severity=None, evidence=None, details=None):
    """Output structured result for AEGIS"""
    output = {{
        'result': result,  # vulnerable, not_vulnerable, inconclusive
        'severity': severity,
        'evidence': evidence or [],
        'details': details or {{}}
    }}
    print(json.dumps(output))
    sys.exit(0 if result != 'error' else 1)

'''
        
        return preamble + '\n' + connection_code + '\n' + attack_code
    
    def _execute_script(self, script_content, language, env, timeout):
        """Execute the script and return results"""
        
        # Create temp file
        suffix = {
            'python': '.py',
            'bash': '.sh',
            'ruby': '.rb',
            'javascript': '.js'
        }.get(language, '.py')
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(script_content)
            script_path = f.name
        
        try:
            # Determine interpreter
            interpreter = {
                'python': ['python3'],
                'bash': ['bash'],
                'ruby': ['ruby'],
                'javascript': ['node']
            }.get(language, ['python3'])
            
            # Execute
            result = subprocess.run(
                interpreter + [script_path],
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        finally:
            os.unlink(script_path)
    
    def execute_campaign(self, campaign_id, user_id, mode='sequential'):
        """Execute all attacks in a campaign"""
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return {'error': 'Campaign not found'}
        
        results = []
        
        if mode == 'parallel':
            futures = []
            for attack in campaign.attacks:
                for target in campaign.targets:
                    config = json.loads(attack.default_config) if attack.default_config else {}
                    result = self.execute_attack(
                        attack.id, target.id, config, user_id, campaign_id
                    )
                    results.append(result)
        else:
            for attack in campaign.attacks:
                for target in campaign.targets:
                    config = json.loads(attack.default_config) if attack.default_config else {}
                    result = self.execute_attack(
                        attack.id, target.id, config, user_id, campaign_id
                    )
                    results.append(result)
        
        return {'campaign_id': campaign_id, 'executions': results}
    
    def get_execution_status(self, execution_id):
        """Get the status of an execution"""
        execution = AttackExecution.query.get(execution_id)
        if not execution:
            return {'error': 'Execution not found'}
        return execution.to_dict()
    
    def cancel_execution(self, execution_id):
        """Cancel a running execution"""
        if execution_id in self.active_executions:
            self.active_executions[execution_id]['future'].cancel()
            execution = AttackExecution.query.get(execution_id)
            if execution:
                execution.status = 'cancelled'
                db.session.commit()
            return {'status': 'cancelled'}
        return {'error': 'Execution not found or already completed'}


# Global executor instance
attack_executor = AttackExecutor()
