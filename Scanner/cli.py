#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI Wrapper for Security Scanner
Updated to support Whitebox scanning with Git integration.
"""

import sys
import os
import json
import argparse
import logging
import shutil
import subprocess
import importlib
from datetime import datetime
from pathlib import Path

# Add current directory to path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cli_debug.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding='utf-8')
    ]
)
logger = logging.getLogger("CLI_Scanner")

# Enable HTTP logging
logging.getLogger("urllib3").setLevel(logging.INFO)
logging.getLogger("requests").setLevel(logging.INFO)

# Import scanner modules
try:
    from scanner_engine import VulnerabilityScanner, InfraScanner
except ImportError as e:
    logger.error(f"Failed to import scanner modules: {e}")
    sys.exit(1)

# Ensure reports and temp directories exist
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# Whitebox Modules Definition
WHITEBOX_MODULES = {
    'access_control': ['missing_auth_check', 'idor', 'admin_exposure', 'missing_method_security'],
    'injection': ['sql_injection', 'command_injection', 'path_traversal', 'ldap_nosql_injection', 'template_injection'],
    'xss_output': ['stored_reflected_xss', 'dom_xss', 'weak_csp'],
    'session_management': ['csrf_missing', 'insecure_cookie', 'session_fixation', 'weak_jwt'],
    'secrets_crypto': ['hardcoded_secrets', 'env_exposure', 'weak_crypto'],
    'file_handling': ['weak_upload_validation', 'webroot_upload', 'path_manipulation', 'upload_size_limit'],
    'deserialization': ['unsafe_deserialization', 'xxe', 'zip_slip'],
    'logging_errors': ['debug_mode_production', 'sensitive_data_logging', 'error_disclosure'],
    'security_headers': ['missing_https_redirect', 'missing_security_headers', 'weak_cors'],
    'dependencies': ['vulnerable_dependencies', 'missing_lockfile', 'risky_package_scripts'],
}

def save_scan_result(scan_id, data):
    """Save scan result to JSON file"""
    try:
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, datetime):
                    return o.isoformat()
                return super().default(o)
                
        file_path = os.path.join(REPORTS_DIR, f'scan_result_{scan_id}.json')
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
        return file_path
    except Exception as e:
        logger.error(f"Failed to save scan status: {str(e)}")
        return None

def load_scan_result_safe(scan_id):
    try:
        path = os.path.join(REPORTS_DIR, f'scan_result_{scan_id}.json')
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
    except:
        return None

class FileUpdatingDict(dict):
    """Dictionary that saves to file on update"""
    def __init__(self, scan_id, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scan_id = scan_id
        
    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key == self.scan_id:
            save_scan_result(self.scan_id, value)

# -------------------------------------------------------------------------
# Git & Whitebox Helper Functions
# -------------------------------------------------------------------------

def prepare_git_repo(repo_url, commit_hash):
    """Clone repo and checkout specific commit"""
    scan_id_part = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir = os.path.join(TEMP_DIR, f"repo_{scan_id_part}_{commit_hash[:7]}")
    
    # If using same repo repeatedly, maybe better to cache? 
    # For now, fresh clone to avoid conflicts.
    
    logger.info(f"Cloning {repo_url} into {target_dir}")
    try:
        # Clone
        subprocess.run(['git', 'clone', repo_url, target_dir], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Checkout
        logger.info(f"Checking out {commit_hash}")
        subprocess.run(['git', 'checkout', commit_hash], cwd=target_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return target_dir
    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e.stderr.decode()}")
        raise Exception(f"Git operation failed: {e.stderr.decode()}")

def get_target_files(project_path):
    project_path = Path(project_path)
    if not project_path.exists():
        raise ValueError(f"Path does not exist: {project_path}")
    
    exclude_dirs = {'.git', '.svn', 'node_modules', '__pycache__', 'venv', 'dist', 'build', '.idea', '.vscode'}
    include_extensions = {
        '.py', '.java', '.js', '.jsx', '.ts', '.tsx', '.php', '.rb', '.go', 
        '.html', '.json', '.xml', '.yml', '.yaml', 'Dockerfile', 'package.json'
    }
    
    target_files = []
    for file_path in project_path.rglob('*'):
        if file_path.is_dir(): continue
        if any(excluded in file_path.parts for excluded in exclude_dirs): continue
        if file_path.suffix.lower() in include_extensions or file_path.name in include_extensions:
            target_files.append(file_path)
            
    return target_files

def generate_whitebox_report(scan_id, project_path, results, summary, commit_hash=None):
    try:
        report_path = os.path.join(REPORTS_DIR, f'whitebox_report_{scan_id}.md')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# Whitebox Scan Report\n\n**Scan ID**: `{scan_id}`\n**Commit**: `{commit_hash}`\n\n---\n\n")
            f.write(f"## Summary\n- Total Findings: {summary.get('total_findings', 0)}\n- Vulnerable Modules: {summary.get('vulnerable_modules', 0)}\n\n")
            f.write("## Vulnerabilities\n\n")
            
            for result in results:
                if result['status'] == 'VULNERABLE':
                    f.write(f"### [{result['category']}] {result['module']}\n\n")
                    
                    # Group findings by file
                    files_map = {}
                    for finding in result.get('findings', []):
                        fname = finding.get('file', 'Unknown File')
                        if fname not in files_map:
                            files_map[fname] = []
                        files_map[fname].append(finding)
                    
                    # Generate a terminal block for each file
                    for fname, file_findings in files_map.items():
                        f.write(f"#### File: `{fname}`\n\n")
                        f.write("```bash\n")
                        f.write(f"[!] VULNERABILITY DETECTED: {result['module']}\n")
                        f.write(f"==================================================\n")
                        f.write(f"IMPACT / DESCRIPTION:\n{result['details']}\n")
                        f.write(f"==================================================\n\n")
                        
                        for finding in file_findings:
                            line = finding.get('line', '?')
                            severity = finding.get('severity', 'MEDIUM')
                            f.write(f"Line {line} [{severity}]:\n")
                            if 'snippet' in finding:
                                # Indent snippet for better readability in 'terminal'
                                snippet = finding['snippet'].strip()
                                f.write(f"{snippet}\n\n")
                            else:
                                f.write("(No snippet available)\n\n")
                            f.write("-" * 50 + "\n")
                        
                        f.write("```\n\n")
                        
                    f.write("\n---\n")

        return report_path
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return None

# -------------------------------------------------------------------------
# Scan Runners
# -------------------------------------------------------------------------

def run_web_scan(target_url, scan_id=None, scan_types=['all'], use_infra=False):
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    if not scan_id:
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logger.info(f"Starting Web Scan: {scan_id} on {target_url}")
    scan_data = {
        'scan_id': scan_id,
        'type': 'web',
        'status': 'running',
        'target_url': target_url,
        'started_at': datetime.now().isoformat(),
        'results': []
    }
    save_scan_result(scan_id, scan_data)
    
    try:
        local_status = FileUpdatingDict(scan_id)
        local_status[scan_id] = scan_data
        
        scanner = VulnerabilityScanner(target_url, local_status, scan_id, scan_types=scan_types, use_infra_detection=use_infra)
        results = scanner.scan_all()
        
        final_data = local_status[scan_id]
        final_data['results'] = results
        final_data['infra_profile'] = getattr(scanner, 'infra_profile', None)
        final_data['metrics'] = getattr(scanner, 'metrics', None)
        final_data['status'] = 'completed'
        final_data['completed_at'] = datetime.now().isoformat()
        final_data['report_path'] = scanner.generate_report(results)
        
        save_scan_result(scan_id, final_data)
        print(json.dumps({"success": True, "scan_id": scan_id, "report_path": final_data['report_path']}))
        
    except Exception as e:
        logger.error(f"Web scan failed: {e}")
        error_data = load_scan_result_safe(scan_id) or scan_data
        error_data['status'] = 'error'
        error_data['error'] = str(e)
        save_scan_result(scan_id, error_data)
        print(json.dumps({"success": False, "error": str(e)}))

def run_infra_scan(host, user, scan_id=None, port=22, password=None, pem_path=None):
    if not scan_id:
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_infra")
    
    logger.info(f"Starting Infra Scan: {scan_id} on {host}")
    scan_data = {
        'scan_id': scan_id,
        'type': 'infrastructure',
        'status': 'running',
        'target': host,
        'started_at': datetime.now().isoformat(),
        'results': []
    }
    save_scan_result(scan_id, scan_data)
    

    try:
        local_status = FileUpdatingDict(scan_id)
        local_status[scan_id] = scan_data
        
        # Initial progress
        scan_data['progress'] = 5
        save_scan_result(scan_id, scan_data)
        
        scanner = InfraScanner(
            ssh_host=host, ssh_user=user, ssh_pass=password, ssh_port=int(port), 
            ssh_key_file=pem_path, scan_status=local_status, scan_id=scan_id, use_discovery=True
        )
        results = scanner.scan_infrastructure(categories=['all'])
        
        scan_data['results'] = results
        scan_data['metrics'] = getattr(scanner, 'metrics', {}) or {}
        scan_data['status'] = 'completed'
        scan_data['progress'] = 100
        scan_data['completed_at'] = datetime.now().isoformat()
        scan_data['report_path'] = scanner.generate_report(results)
        
        save_scan_result(scan_id, scan_data)
        print(json.dumps({"success": True, "scan_id": scan_id, "report_path": scan_data['report_path']}))
        
    except Exception as e:
        logger.error(f"Infra scan failed: {e}")
        error_data = load_scan_result_safe(scan_id) or scan_data
        error_data['status'] = 'error'
        error_data['error'] = str(e)
        save_scan_result(scan_id, error_data)
        print(json.dumps({"success": False, "error": str(e)}))

def run_whitebox_scan(repo_url, commit_hash, scan_id=None):
    if not scan_id:
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_whitebox")
        
    logger.info(f"Starting Whitebox Scan: {scan_id} on {repo_url} ({commit_hash})")
    scan_data = {
        'scan_id': scan_id,
        'type': 'whitebox',
        'status': 'preparing',
        'repo_url': repo_url,
        'commit_hash': commit_hash,
        'started_at': datetime.now().isoformat(),
        'results': []
    }
    save_scan_result(scan_id, scan_data)
    

    try:
        # 1. Prepare Repo
        project_path = prepare_git_repo(repo_url, commit_hash)
        scan_data['status'] = 'running'
        scan_data['progress'] = 10
        save_scan_result(scan_id, scan_data)
        
        # 2. Collect Files
        target_files = get_target_files(project_path)
        scan_data['files_scanned'] = len(target_files)
        scan_data['progress'] = 20
        save_scan_result(scan_id, scan_data)
        
        # 3. Run Modules
        module_results = [] # Keep structured for report
        flat_findings = []  # Flat for frontend stats
        
        project_path_obj = Path(project_path)
        
        total_modules = sum(len(m) for m in WHITEBOX_MODULES.values())
        header_modules_done = 0
        
        for category, modules in WHITEBOX_MODULES.items():
            for module_name in modules:
                try:
                    # Update status for real-time log
                    scan_data['current_test'] = f"Analyzing {category}/{module_name}..."
                    save_scan_result(scan_id, scan_data)

                    module_path = f'modules.whitebox.{category}.{module_name}'
                    module = importlib.import_module(module_path)
                    result = module.scan(project_path_obj, target_files)
                    
                    if result and result.get('status') == 'VULNERABLE':
                        # Structured result for report
                        module_results.append({
                            'category': category,
                            'module': module_name,
                            'status': result.get('status'),
                            'details': result.get('details'),
                            'findings': result.get('findings', []),
                            'recommendation': result.get('recommendation', '')
                        })
                        
                        # Flat findings for frontend
                        for finding in result.get('findings', []):
                            flat_findings.append({
                                'category': category,
                                'module': module_name,
                                'severity': finding.get('severity', 'MEDIUM'),
                                'file': finding.get('file'),
                                'line': finding.get('line'),
                                'snippet': finding.get('snippet'),
                                'description': result.get('details')
                            })
                            
                except Exception as e:
                    logger.error(f"Module error {module_name}: {e}")
                
                header_modules_done += 1
                scan_data['progress'] = 20 + int((header_modules_done / total_modules) * 70)
                # Save progress and current test
                save_scan_result(scan_id, scan_data)
        
        # 4. Finalize
        scan_data['results'] = flat_findings
        scan_data['status'] = 'completed'
        scan_data['progress'] = 100
        scan_data['completed_at'] = datetime.now().isoformat()
        
        summary = {
            'total_findings': len(flat_findings),
            'vulnerable_modules': len(module_results)
        }
        scan_data['summary'] = summary
        scan_data['report_path'] = generate_whitebox_report(scan_id, project_path, module_results, summary, commit_hash)
        
        save_scan_result(scan_id, scan_data)
        
        # Clean up temp
        try:
            shutil.rmtree(project_path)
        except:
            pass
            
        print(json.dumps({"success": True, "scan_id": scan_id, "report_path": scan_data['report_path']}))
        
    except Exception as e:
        logger.error(f"Whitebox scan failed: {e}")
        error_data = load_scan_result_safe(scan_id) or scan_data
        error_data['status'] = 'error'
        error_data['error'] = str(e)
        save_scan_result(scan_id, error_data)
        print(json.dumps({"success": False, "error": str(e)}))

def main():
    parser = argparse.ArgumentParser(description='Security Scanner CLI')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Web Scan
    web_parser = subparsers.add_parser('web', help='Run web application scan')
    web_parser.add_argument('--url', required=True, help='Target URL')
    web_parser.add_argument('--infra', action='store_true', help='Use infrastructure detection')
    web_parser.add_argument('--scan-id', help='Optional Scan ID')

    # Infra Scan
    infra_parser = subparsers.add_parser('infra', help='Run infrastructure scan')
    infra_parser.add_argument('--host', required=True, help='SSH Host')
    infra_parser.add_argument('--user', required=True, help='SSH User')
    infra_parser.add_argument('--port', default=22, help='SSH Port')
    infra_parser.add_argument('--password', help='SSH Password')
    infra_parser.add_argument('--pem', help='SSH Private Key Path')
    infra_parser.add_argument('--scan-id', help='Optional Scan ID')
    
    # Whitebox Scan
    wb_parser = subparsers.add_parser('whitebox', help='Run whitebox source scan')
    wb_parser.add_argument('--repo', required=True, help='Git Repository URL')
    wb_parser.add_argument('--commit', required=True, help='Commit Hash')
    wb_parser.add_argument('--scan-id', help='Optional Scan ID')

    args = parser.parse_args()

    if args.command == 'web':
        run_web_scan(args.url, scan_id=args.scan_id, use_infra=args.infra)
    elif args.command == 'infra':
        run_infra_scan(args.host, args.user, scan_id=args.scan_id, port=args.port, password=args.password, pem_path=args.pem)
    elif args.command == 'whitebox':
        run_whitebox_scan(args.repo, args.commit, scan_id=args.scan_id)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
