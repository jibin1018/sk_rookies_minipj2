"""
백업 파일 노출 점검

서버에 노출된 백업 파일, 설정 파일, 임시 파일을 탐지합니다.
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': '백업 파일 노출 점검',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '백업 파일을 웹 루트 외부에 저장하거나 접근 차단',
        'details': ''
    }
    
    details = []
    
    # 점검할 파일 목록
    BACKUP_FILES = [
        # 백업 확장자
        '.bak', '.backup', '.old', '.orig', '.save',
        '.swp', '.swo', '~', '.tmp', '.temp',
        
        # 설정 파일 백업
        'config.php.bak', 'config.php.old', 'config.bak',
        'settings.php.bak', 'database.php.bak',
        'wp-config.php.bak', 'wp-config.php~',
        
        # 압축 파일
        'backup.zip', 'backup.tar.gz', 'backup.sql',
        'site.zip', 'www.zip', 'public_html.zip',
        'db.sql', 'database.sql', 'dump.sql',
        
        # 숨김 파일
        '.htaccess.bak', '.htpasswd', '.env',
        '.env.local', '.env.production', '.env.backup',
        '.git/config', '.svn/entries',
        '.DS_Store', 'Thumbs.db',
        
        # 에디터 임시 파일
        'index.php~', 'index.php.bak', 'index.html.bak',
        '.vscode/settings.json', '.idea/workspace.xml',
        
        # 로그 파일
        'error.log', 'access.log', 'debug.log',
        'php_errors.log', 'application.log',
        
        # 설정 파일
        'web.config.bak', 'httpd.conf.bak',
        'robots.txt.bak', '.htaccess.old',
    ]
    
    try:
        details.append("[Backup-1] 백업/임시 파일 탐지\n")
        
        found_files = []
        sensitive_files = []
        
        for filename in BACKUP_FILES:
            url = urljoin(target_url, filename)
            
            try:
                response = requests.head(url, timeout=3, verify=False, allow_redirects=False)
                
                # 200 또는 파일 크기가 있는 응답
                if response.status_code == 200:
                    content_length = response.headers.get('Content-Length', '0')
                    content_type = response.headers.get('Content-Type', 'unknown')
                    
                    # 빈 파일이나 에러 페이지 제외
                    if int(content_length) > 0:
                        file_info = {
                            'filename': filename,
                            'size': content_length,
                            'type': content_type,
                        }
                        
                        # 민감 파일 분류
                        sensitive_ext = ['.sql', '.env', '.bak', '.git', '.svn', 'config']
                        if any(s in filename.lower() for s in sensitive_ext):
                            sensitive_files.append(file_info)
                        else:
                            found_files.append(file_info)
                        
                        details.append(f"  발견: {filename}")
                        details.append(f"    크기: {content_length} bytes, 타입: {content_type}")
                
            except requests.RequestException:
                continue
        
        # 디렉토리 리스팅 확인
        details.append("\n[Backup-2] 디렉토리 리스팅 확인")
        
        common_dirs = ['/backup/', '/bak/', '/old/', '/tmp/', '/.git/']
        
        for dir_path in common_dirs:
            url = urljoin(target_url, dir_path)
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        sensitive_files.append({
                            'filename': dir_path,
                            'size': 'directory',
                            'type': 'directory listing'
                        })
                        details.append(f"  ✗ 디렉토리 리스팅: {dir_path}")
            except:
                continue
        
        # 요약
        details.append("\n[Backup-3] 보안 요약")
        
        if sensitive_files:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'CRITICAL'
            result['vulnerabilities'] = [
                f"민감 파일 노출: {f['filename']}"
                for f in sensitive_files
            ]
            details.append(f"\n  ✗ 민감 파일: {len(sensitive_files)}개 발견")
            for f in sensitive_files:
                details.append(f"    - {f['filename']}")
        
        if found_files:
            details.append(f"\n  ⚠ 기타 파일: {len(found_files)}개 발견")
            if result['status'] == 'SAFE':
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
        
        if not sensitive_files and not found_files:
            details.append("\n  ✓ 백업/임시 파일 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
