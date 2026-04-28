"""
Scanning service - handles network discovery and enumeration
"""
import socket
import subprocess
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from app import db
from app.models import ScanJob, Target, DiscoveredEndpoint
import uuid
import ipaddress
import re


class ScannerService:
    """Network and service scanning functionality"""
    
    def __init__(self, max_workers=50):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans = {}
    
    def start_scan(self, scan_config, user_id):
        """Start a new scan job"""
        scan_job = ScanJob(
            id=str(uuid.uuid4()),
            name=scan_config.get('name', 'Unnamed Scan'),
            scan_type=scan_config.get('scan_type', 'network_discovery'),
            target_range=scan_config.get('target_range', ''),
            scan_config=json.dumps(scan_config),
            status='pending',
            initiated_by=user_id
        )
        db.session.add(scan_job)
        db.session.commit()
        
        # Start scan in background
        future = self.executor.submit(
            self._run_scan,
            scan_job.id,
            scan_config
        )
        
        self.active_scans[scan_job.id] = {
            'future': future,
            'scan_job': scan_job
        }
        
        return {'scan_id': scan_job.id, 'status': 'started'}
    
    def _run_scan(self, scan_id, config):
        """Internal method to run the scan"""
        from app import create_app
        app = create_app()
        
        with app.app_context():
            scan_job = ScanJob.query.get(scan_id)
            if not scan_job:
                return
            
            scan_job.status = 'running'
            scan_job.started_at = datetime.utcnow()
            db.session.commit()
            
            try:
                scan_type = config.get('scan_type', 'network_discovery')
                
                if scan_type == 'network_discovery':
                    results = self._network_discovery(config, scan_job)
                elif scan_type == 'port_scan':
                    results = self._port_scan(config, scan_job)
                elif scan_type == 'service_enum':
                    results = self._service_enumeration(config, scan_job)
                elif scan_type == 'ai_endpoint_discovery':
                    results = self._ai_endpoint_discovery(config, scan_job)
                elif scan_type == 'mcp_discovery':
                    results = self._mcp_server_discovery(config, scan_job)
                else:
                    results = {'error': 'Unknown scan type'}
                
                scan_job.results = json.dumps(results)
                scan_job.status = 'completed'
                scan_job.discovered_hosts = results.get('hosts_found', 0)
                scan_job.discovered_services = results.get('services_found', 0)
                
            except Exception as e:
                scan_job.status = 'failed'
                scan_job.results = json.dumps({'error': str(e)})
            finally:
                scan_job.completed_at = datetime.utcnow()
                db.session.commit()
    
    def _network_discovery(self, config, scan_job):
        """Discover hosts on a network"""
        target_range = config.get('target_range', '')
        results = {
            'hosts_found': 0,
            'hosts': [],
            'scan_type': 'network_discovery'
        }
        
        try:
            # Parse the target range
            if '/' in target_range:
                # CIDR notation
                network = ipaddress.ip_network(target_range, strict=False)
                hosts_to_scan = list(network.hosts())
            elif '-' in target_range:
                # Range notation (e.g., 192.168.1.1-255)
                hosts_to_scan = self._parse_range(target_range)
            else:
                # Single host or comma-separated
                hosts_to_scan = [ip.strip() for ip in target_range.split(',')]
            
            total_hosts = len(hosts_to_scan)
            discovered = []
            
            # Parallel host discovery
            with ThreadPoolExecutor(max_workers=min(100, total_hosts)) as executor:
                futures = {
                    executor.submit(self._check_host, str(host)): str(host)
                    for host in hosts_to_scan
                }
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    scan_job.progress = int((completed / total_hosts) * 100)
                    db.session.commit()
                    
                    host = futures[future]
                    try:
                        result = future.result()
                        if result['alive']:
                            discovered.append(result)
                    except Exception:
                        pass
            
            results['hosts'] = discovered
            results['hosts_found'] = len(discovered)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_host(self, host):
        """Check if a host is alive"""
        result = {
            'host': host,
            'alive': False,
            'hostname': None,
            'response_time': None
        }
        
        try:
            # Try TCP connect to common ports
            common_ports = [80, 443, 22, 8080, 8443, 3000, 5000]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    start = datetime.now()
                    sock.connect((host, port))
                    result['response_time'] = (datetime.now() - start).total_seconds() * 1000
                    result['alive'] = True
                    sock.close()
                    break
                except:
                    pass
            
            # Try to resolve hostname
            if result['alive']:
                try:
                    result['hostname'] = socket.gethostbyaddr(host)[0]
                except:
                    pass
                    
        except Exception:
            pass
        
        return result
    
    def _port_scan(self, config, scan_job):
        """Scan ports on target hosts"""
        target = config.get('target', '')
        port_range = config.get('port_range', '1-1000')
        results = {
            'target': target,
            'open_ports': [],
            'services_found': 0,
            'scan_type': 'port_scan'
        }
        
        try:
            # Parse port range
            ports = self._parse_port_range(port_range)
            total_ports = len(ports)
            open_ports = []
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {
                    executor.submit(self._check_port, target, port): port
                    for port in ports
                }
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    scan_job.progress = int((completed / total_ports) * 100)
                    db.session.commit()
                    
                    port = futures[future]
                    try:
                        result = future.result()
                        if result['open']:
                            open_ports.append(result)
                    except:
                        pass
            
            results['open_ports'] = sorted(open_ports, key=lambda x: x['port'])
            results['services_found'] = len(open_ports)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_port(self, host, port):
        """Check if a port is open and identify service"""
        result = {
            'port': port,
            'open': False,
            'service': None,
            'banner': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            if sock.connect_ex((host, port)) == 0:
                result['open'] = True
                
                # Common service identification
                common_services = {
                    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                    53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
                    443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
                    3306: 'mysql', 5432: 'postgresql', 6379: 'redis',
                    8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
                    3000: 'node', 5000: 'flask', 8000: 'django',
                    9000: 'php-fpm', 11211: 'memcached'
                }
                
                result['service'] = common_services.get(port, 'unknown')
                
                # Try to grab banner
                try:
                    if port not in [80, 443, 8080, 8443]:
                        sock.settimeout(2)
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            result['banner'] = banner[:200]
                except:
                    pass
            
            sock.close()
        except:
            pass
        
        return result
    
    def _service_enumeration(self, config, scan_job):
        """Enumerate services on discovered hosts"""
        targets = config.get('targets', [])
        results = {
            'services': [],
            'services_found': 0,
            'scan_type': 'service_enum'
        }
        
        all_services = []
        
        for target in targets:
            host = target.get('host')
            ports = target.get('ports', [])
            
            for port_info in ports:
                port = port_info.get('port')
                service = self._enumerate_service(host, port)
                if service:
                    all_services.append(service)
        
        results['services'] = all_services
        results['services_found'] = len(all_services)
        
        return results
    
    def _enumerate_service(self, host, port):
        """Enumerate details about a specific service"""
        service = {
            'host': host,
            'port': port,
            'protocol': None,
            'product': None,
            'version': None,
            'extra_info': {}
        }
        
        # Check for HTTP/HTTPS
        if port in [80, 8080, 3000, 5000, 8000]:
            service.update(self._enumerate_http(host, port, False))
        elif port in [443, 8443]:
            service.update(self._enumerate_http(host, port, True))
        
        return service
    
    def _enumerate_http(self, host, port, https=False):
        """Enumerate HTTP/HTTPS service"""
        import urllib.request
        import ssl
        
        info = {
            'protocol': 'https' if https else 'http',
            'product': None,
            'version': None,
            'extra_info': {}
        }
        
        try:
            url = f"{'https' if https else 'http'}://{host}:{port}/"
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Minerva Security Scanner')
            
            with urllib.request.urlopen(req, timeout=5, context=context) as response:
                headers = dict(response.headers)
                
                info['extra_info']['server'] = headers.get('Server', '')
                info['extra_info']['powered_by'] = headers.get('X-Powered-By', '')
                info['extra_info']['content_type'] = headers.get('Content-Type', '')
                
                # Check for common AI/ML endpoints
                content = response.read(10000).decode('utf-8', errors='ignore')
                
                if 'openai' in content.lower() or 'gpt' in content.lower():
                    info['product'] = 'OpenAI Compatible API'
                elif 'anthropic' in content.lower() or 'claude' in content.lower():
                    info['product'] = 'Anthropic API'
                elif 'mcp' in content.lower():
                    info['product'] = 'MCP Server'
                
        except Exception as e:
            info['extra_info']['error'] = str(e)
        
        return info
    
    def _ai_endpoint_discovery(self, config, scan_job):
        """Discover AI/ML endpoints"""
        target = config.get('target', '')
        base_url = config.get('base_url', f'http://{target}')
        
        results = {
            'target': target,
            'endpoints': [],
            'ai_services_detected': [],
            'scan_type': 'ai_endpoint_discovery'
        }
        
        # Common AI/ML endpoint paths
        ai_endpoints = [
            '/v1/chat/completions',
            '/v1/completions',
            '/v1/embeddings',
            '/v1/models',
            '/api/generate',
            '/api/chat',
            '/mcp',
            '/mcp/tools',
            '/mcp/resources',
            '/mcp/prompts',
            '/.well-known/mcp',
            '/health',
            '/api/health',
            '/openapi.json',
            '/swagger.json',
            '/docs',
            '/api/docs',
            '/graphql',
            '/api/v1/agents',
            '/api/v1/workflows',
        ]
        
        import urllib.request
        import ssl
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        for endpoint in ai_endpoints:
            try:
                url = f"{base_url.rstrip('/')}{endpoint}"
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Minerva Security Scanner')
                
                with urllib.request.urlopen(req, timeout=5, context=context) as response:
                    results['endpoints'].append({
                        'path': endpoint,
                        'status': response.status,
                        'content_type': response.headers.get('Content-Type', ''),
                        'accessible': True
                    })
                    
            except urllib.request.HTTPError as e:
                if e.code in [401, 403]:
                    results['endpoints'].append({
                        'path': endpoint,
                        'status': e.code,
                        'accessible': False,
                        'auth_required': True
                    })
            except:
                pass
        
        results['services_found'] = len(results['endpoints'])
        return results
    
    def _mcp_server_discovery(self, config, scan_job):
        """Discover MCP servers and their capabilities"""
        target = config.get('target', '')
        results = {
            'target': target,
            'mcp_servers': [],
            'tools_found': [],
            'resources_found': [],
            'scan_type': 'mcp_discovery'
        }
        
        # MCP discovery logic would go here
        # This is a placeholder for actual MCP protocol implementation
        
        return results
    
    def _parse_range(self, range_str):
        """Parse IP range notation"""
        hosts = []
        
        if '-' in range_str:
            parts = range_str.split('.')
            if '-' in parts[-1]:
                base = '.'.join(parts[:-1])
                start, end = parts[-1].split('-')
                for i in range(int(start), int(end) + 1):
                    hosts.append(f"{base}.{i}")
            else:
                hosts.append(range_str)
        else:
            hosts.append(range_str)
        
        return hosts
    
    def _parse_port_range(self, port_range):
        """Parse port range notation"""
        ports = []
        
        for part in port_range.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        
        return ports
    
    def get_scan_status(self, scan_id):
        """Get scan job status"""
        scan_job = ScanJob.query.get(scan_id)
        if not scan_job:
            return {'error': 'Scan not found'}
        return scan_job.to_dict()
    
    def cancel_scan(self, scan_id):
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['future'].cancel()
            scan_job = ScanJob.query.get(scan_id)
            if scan_job:
                scan_job.status = 'cancelled'
                db.session.commit()
            return {'status': 'cancelled'}
        return {'error': 'Scan not found or already completed'}
    
    def import_targets_from_scan(self, scan_id):
        """Import discovered hosts as targets"""
        scan_job = ScanJob.query.get(scan_id)
        if not scan_job or not scan_job.results:
            return {'error': 'Scan not found or no results'}
        
        results = json.loads(scan_job.results)
        imported = []
        
        for host_info in results.get('hosts', []):
            target = Target(
                name=host_info.get('hostname') or host_info['host'],
                host=host_info['host'],
                target_type='discovered',
                is_active=True
            )
            db.session.add(target)
            imported.append(target.to_dict())
        
        db.session.commit()
        return {'imported': len(imported), 'targets': imported}


# Global scanner instance
scanner_service = ScannerService()
