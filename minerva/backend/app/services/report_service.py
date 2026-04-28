"""
Report generation service
"""
import json
import os
from datetime import datetime
from app import db
from app.models import Report, Campaign, AttackExecution, Attack, Target
import uuid


class ReportGenerator:
    """Generates pentest reports"""
    
    def __init__(self, reports_folder='reports'):
        self.reports_folder = reports_folder
        os.makedirs(reports_folder, exist_ok=True)
    
    def generate_report(self, campaign_id, report_type, user_id, report_format='json'):
        """Generate a report for a campaign"""
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return {'error': 'Campaign not found'}
        
        # Gather execution data
        executions = AttackExecution.query.filter_by(campaign_id=campaign_id).all()
        
        # Calculate statistics
        stats = self._calculate_stats(executions)
        
        # Generate findings
        findings = self._generate_findings(executions)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        # Build report content
        report_content = {
            'metadata': {
                'report_id': str(uuid.uuid4()),
                'campaign_id': campaign_id,
                'campaign_name': campaign.name,
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'generated_by': user_id
            },
            'executive_summary': self._generate_executive_summary(campaign, stats, findings),
            'scope': {
                'campaign_type': campaign.campaign_type,
                'scenario': campaign.scenario,
                'targets': [t.to_dict() for t in campaign.targets],
                'attacks_tested': [a.to_dict() for a in campaign.attacks],
                'rules_of_engagement': campaign.rules_of_engagement
            },
            'statistics': stats,
            'findings': findings,
            'detailed_results': [e.to_dict() for e in executions],
            'recommendations': recommendations,
            'conclusion': self._generate_conclusion(stats, findings)
        }
        
        # Save report
        report = Report(
            id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            name=f"{campaign.name} - {report_type.title()} Report",
            report_type=report_type,
            format=report_format,
            content=json.dumps(report_content),
            total_attacks=stats['total_attacks'],
            successful_attacks=stats['successful_attacks'],
            critical_findings=stats['severity_breakdown'].get('critical', 0),
            high_findings=stats['severity_breakdown'].get('high', 0),
            medium_findings=stats['severity_breakdown'].get('medium', 0),
            low_findings=stats['severity_breakdown'].get('low', 0),
            recommendations=json.dumps(recommendations),
            generated_by=user_id
        )
        
        # Generate file if needed
        if report_format == 'html':
            file_path = self._generate_html_report(report_content, campaign.name)
            report.file_path = file_path
        elif report_format == 'pdf':
            file_path = self._generate_pdf_report(report_content, campaign.name)
            report.file_path = file_path
        
        db.session.add(report)
        db.session.commit()
        
        return report.to_dict()
    
    def _calculate_stats(self, executions):
        """Calculate statistics from executions"""
        stats = {
            'total_attacks': len(executions),
            'successful_attacks': 0,
            'failed_attacks': 0,
            'inconclusive': 0,
            'status_breakdown': {},
            'severity_breakdown': {},
            'attack_type_breakdown': {},
            'target_breakdown': {},
            'average_duration': 0
        }
        
        total_duration = 0
        duration_count = 0
        
        for execution in executions:
            # Count by status
            status = execution.status
            stats['status_breakdown'][status] = stats['status_breakdown'].get(status, 0) + 1
            
            # Count successes
            if execution.result == 'vulnerable':
                stats['successful_attacks'] += 1
                
                # Count by severity
                severity = execution.severity_found or 'unknown'
                stats['severity_breakdown'][severity] = stats['severity_breakdown'].get(severity, 0) + 1
            elif execution.result == 'not_vulnerable':
                stats['failed_attacks'] += 1
            else:
                stats['inconclusive'] += 1
            
            # Attack type breakdown
            attack = Attack.query.get(execution.attack_id)
            if attack:
                attack_type = attack.attack_type or 'unknown'
                stats['attack_type_breakdown'][attack_type] = stats['attack_type_breakdown'].get(attack_type, 0) + 1
            
            # Target breakdown
            if execution.target_id:
                stats['target_breakdown'][execution.target_id] = stats['target_breakdown'].get(execution.target_id, 0) + 1
            
            # Duration
            if execution.duration_seconds:
                total_duration += execution.duration_seconds
                duration_count += 1
        
        if duration_count > 0:
            stats['average_duration'] = total_duration / duration_count
        
        return stats
    
    def _generate_findings(self, executions):
        """Generate detailed findings from executions"""
        findings = []
        
        for execution in executions:
            if execution.result == 'vulnerable':
                attack = Attack.query.get(execution.attack_id)
                target = Target.query.get(execution.target_id)
                
                finding = {
                    'id': str(uuid.uuid4()),
                    'execution_id': execution.id,
                    'title': attack.name if attack else 'Unknown Attack',
                    'severity': execution.severity_found or attack.severity if attack else 'unknown',
                    'target': {
                        'name': target.name if target else 'Unknown',
                        'host': target.host if target else None,
                        'type': target.target_type if target else None
                    },
                    'description': attack.description if attack else '',
                    'evidence': json.loads(execution.evidence) if execution.evidence else [],
                    'output': execution.output,
                    'mitre_id': attack.mitre_id if attack else None,
                    'cve_ids': json.loads(attack.cve_ids) if attack and attack.cve_ids else [],
                    'references': json.loads(attack.references) if attack and attack.references else [],
                    'discovered_at': execution.completed_at.isoformat() if execution.completed_at else None
                }
                
                findings.append(finding)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        return findings
    
    def _generate_recommendations(self, findings):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Generic recommendations based on finding types
        recommendation_templates = {
            'prompt_injection': {
                'title': 'Implement Input Validation and Sanitization',
                'description': 'Implement robust input validation to detect and prevent prompt injection attacks.',
                'priority': 'high',
                'steps': [
                    'Implement input sanitization for all user inputs',
                    'Use allowlisting for expected input patterns',
                    'Implement rate limiting on API endpoints',
                    'Add monitoring for suspicious input patterns'
                ]
            },
            'tool_poisoning': {
                'title': 'Secure Tool Registration and Validation',
                'description': 'Implement strict validation for tool registration and execution.',
                'priority': 'critical',
                'steps': [
                    'Validate tool schemas before registration',
                    'Implement tool signing and verification',
                    'Restrict tool permissions to minimum required',
                    'Monitor tool execution for anomalies'
                ]
            },
            'data_extraction': {
                'title': 'Implement Data Loss Prevention Controls',
                'description': 'Add controls to prevent unauthorized data extraction.',
                'priority': 'high',
                'steps': [
                    'Implement output filtering for sensitive data',
                    'Add data classification and tagging',
                    'Monitor for unusual data access patterns',
                    'Implement access controls on sensitive data'
                ]
            },
            'authentication': {
                'title': 'Strengthen Authentication Mechanisms',
                'description': 'Improve authentication to prevent unauthorized access.',
                'priority': 'critical',
                'steps': [
                    'Implement multi-factor authentication',
                    'Use secure token management',
                    'Implement session timeout policies',
                    'Add authentication logging and monitoring'
                ]
            }
        }
        
        seen_types = set()
        
        for finding in findings:
            # Determine recommendation type based on finding
            attack_type = finding.get('title', '').lower()
            
            for key, template in recommendation_templates.items():
                if key in attack_type and key not in seen_types:
                    recommendations.append({
                        'id': str(uuid.uuid4()),
                        'related_findings': [finding['id']],
                        **template
                    })
                    seen_types.add(key)
        
        # Add generic recommendations
        if findings:
            recommendations.append({
                'id': str(uuid.uuid4()),
                'title': 'Implement Security Monitoring',
                'description': 'Set up comprehensive security monitoring and alerting.',
                'priority': 'medium',
                'steps': [
                    'Deploy security information and event management (SIEM)',
                    'Configure alerts for security-relevant events',
                    'Implement log aggregation and analysis',
                    'Establish incident response procedures'
                ]
            })
            
            recommendations.append({
                'id': str(uuid.uuid4()),
                'title': 'Conduct Regular Security Assessments',
                'description': 'Establish a program for regular security testing.',
                'priority': 'medium',
                'steps': [
                    'Schedule periodic penetration testing',
                    'Implement automated vulnerability scanning',
                    'Conduct code reviews for security issues',
                    'Maintain an up-to-date threat model'
                ]
            })
        
        return recommendations
    
    def _generate_executive_summary(self, campaign, stats, findings):
        """Generate executive summary"""
        critical_high = stats['severity_breakdown'].get('critical', 0) + stats['severity_breakdown'].get('high', 0)
        
        risk_level = 'Low'
        if stats['severity_breakdown'].get('critical', 0) > 0:
            risk_level = 'Critical'
        elif stats['severity_breakdown'].get('high', 0) > 0:
            risk_level = 'High'
        elif stats['severity_breakdown'].get('medium', 0) > 0:
            risk_level = 'Medium'
        
        return {
            'overview': f"Security assessment of {campaign.name} conducted using {stats['total_attacks']} attack scenarios against {len(campaign.targets)} targets.",
            'risk_level': risk_level,
            'key_findings': f"Identified {stats['successful_attacks']} vulnerabilities, including {critical_high} critical/high severity issues.",
            'critical_issues': [f for f in findings if f['severity'] in ['critical', 'high']][:5],
            'immediate_actions': self._get_immediate_actions(findings)
        }
    
    def _get_immediate_actions(self, findings):
        """Get immediate action items from findings"""
        actions = []
        
        for finding in findings:
            if finding['severity'] in ['critical', 'high']:
                actions.append({
                    'finding': finding['title'],
                    'action': f"Address {finding['severity']} severity vulnerability: {finding['title']}",
                    'target': finding['target']['name']
                })
        
        return actions[:5]
    
    def _generate_conclusion(self, stats, findings):
        """Generate report conclusion"""
        return {
            'summary': f"The security assessment identified {stats['successful_attacks']} vulnerabilities across the tested infrastructure.",
            'overall_security_posture': self._assess_security_posture(stats),
            'next_steps': [
                'Review and prioritize findings by severity',
                'Implement recommended remediations',
                'Schedule follow-up testing to verify fixes',
                'Update security policies based on findings'
            ]
        }
    
    def _assess_security_posture(self, stats):
        """Assess overall security posture"""
        if stats['severity_breakdown'].get('critical', 0) > 0:
            return 'Poor - Critical vulnerabilities require immediate attention'
        elif stats['severity_breakdown'].get('high', 0) > 0:
            return 'Below Average - High severity issues need to be addressed'
        elif stats['severity_breakdown'].get('medium', 0) > 0:
            return 'Average - Medium severity issues should be remediated'
        elif stats['successful_attacks'] > 0:
            return 'Above Average - Minor issues identified'
        else:
            return 'Good - No significant vulnerabilities identified'
    
    def _generate_html_report(self, content, campaign_name):
        """Generate HTML report file"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"report_{campaign_name.replace(' ', '_')}_{timestamp}.html"
        filepath = os.path.join(self.reports_folder, filename)
        
        html = self._build_html_report(content)
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        return filepath
    
    def _build_html_report(self, content):
        """Build HTML report content"""
        findings_html = ''
        for finding in content['findings']:
            findings_html += f'''
            <div class="finding severity-{finding['severity']}">
                <h4>{finding['title']}</h4>
                <p><strong>Severity:</strong> {finding['severity'].upper()}</p>
                <p><strong>Target:</strong> {finding['target']['name']}</p>
                <p>{finding['description']}</p>
            </div>
            '''
        
        recommendations_html = ''
        for rec in content['recommendations']:
            steps_html = '<ul>' + ''.join([f'<li>{s}</li>' for s in rec['steps']]) + '</ul>'
            recommendations_html += f'''
            <div class="recommendation priority-{rec['priority']}">
                <h4>{rec['title']}</h4>
                <p>{rec['description']}</p>
                {steps_html}
            </div>
            '''
        
        return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Minerva Security Report - {content['metadata']['campaign_name']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 3rem; margin-bottom: 2rem; border-radius: 12px; border: 1px solid #00ff88; }}
        h1 {{ color: #00ff88; font-size: 2.5rem; margin-bottom: 0.5rem; }}
        h2 {{ color: #00d4ff; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #00d4ff; }}
        h3 {{ color: #ff6b6b; margin: 1.5rem 0 1rem; }}
        h4 {{ color: #ffd93d; margin-bottom: 0.5rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }}
        .stat-card {{ background: #1a1a2e; padding: 1.5rem; border-radius: 8px; text-align: center; border: 1px solid #333; }}
        .stat-value {{ font-size: 2.5rem; font-weight: bold; color: #00ff88; }}
        .stat-label {{ color: #888; text-transform: uppercase; font-size: 0.8rem; }}
        .finding {{ background: #1a1a2e; padding: 1.5rem; margin: 1rem 0; border-radius: 8px; border-left: 4px solid; }}
        .severity-critical {{ border-color: #ff0000; }}
        .severity-high {{ border-color: #ff6b6b; }}
        .severity-medium {{ border-color: #ffd93d; }}
        .severity-low {{ border-color: #00d4ff; }}
        .severity-info {{ border-color: #888; }}
        .recommendation {{ background: #1a2e1a; padding: 1.5rem; margin: 1rem 0; border-radius: 8px; border-left: 4px solid #00ff88; }}
        .priority-critical {{ border-color: #ff0000; }}
        .priority-high {{ border-color: #ff6b6b; }}
        .priority-medium {{ border-color: #ffd93d; }}
        ul {{ margin: 1rem 0 0 1.5rem; }}
        li {{ margin: 0.5rem 0; }}
        .summary {{ background: linear-gradient(135deg, #1a2e1a 0%, #162e16 100%); padding: 2rem; border-radius: 8px; margin: 2rem 0; }}
        footer {{ text-align: center; padding: 2rem; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Minerva Security Report</h1>
            <p>Campaign: {content['metadata']['campaign_name']}</p>
            <p>Generated: {content['metadata']['generated_at']}</p>
        </header>
        
        <section class="summary">
            <h2>Executive Summary</h2>
            <p>{content['executive_summary']['overview']}</p>
            <p><strong>Risk Level:</strong> {content['executive_summary']['risk_level']}</p>
            <p>{content['executive_summary']['key_findings']}</p>
        </section>
        
        <section>
            <h2>Statistics</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{content['statistics']['total_attacks']}</div>
                    <div class="stat-label">Total Tests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ff6b6b;">{content['statistics']['successful_attacks']}</div>
                    <div class="stat-label">Vulnerabilities Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ffd93d;">{content['statistics']['severity_breakdown'].get('critical', 0) + content['statistics']['severity_breakdown'].get('high', 0)}</div>
                    <div class="stat-label">Critical/High</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Findings</h2>
            {findings_html if findings_html else '<p>No vulnerabilities identified.</p>'}
        </section>
        
        <section>
            <h2>Recommendations</h2>
            {recommendations_html}
        </section>
        
        <section>
            <h2>Conclusion</h2>
            <p>{content['conclusion']['summary']}</p>
            <p><strong>Security Posture:</strong> {content['conclusion']['overall_security_posture']}</p>
        </section>
        
        <footer>
            <p>Generated by Minerva MCP Pentesting Framework</p>
        </footer>
    </div>
</body>
</html>
'''
    
    def _generate_pdf_report(self, content, campaign_name):
        """Generate PDF report file (placeholder - would use weasyprint or reportlab)"""
        # For now, generate HTML and note PDF generation would need additional libraries
        return self._generate_html_report(content, campaign_name)


# Global report generator instance
report_generator = ReportGenerator()
