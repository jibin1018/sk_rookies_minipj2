"""
AWS S3 버킷 공개 접근 점검 (URL 기반)
"""
import requests
from urllib.parse import urlparse


def scan(target_url):
    result = {
        'name': 'AWS S3 버킷 공개 접근 점검',
        'category': 'Cloud Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'S3 버킷 퍼블릭 액세스 차단, 버킷 정책 검토',
        'details': ''
    }
    
    details = []
    
    try:
        # S3 버킷 URL 패턴 감지
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ''
        
        # S3 버킷 URL 형식 확인
        s3_patterns = [
            '.s3.amazonaws.com',
            '.s3-',
            's3.amazonaws.com/',
        ]
        
        is_s3 = any(pattern in hostname for pattern in s3_patterns)
        
        if not is_s3:
            # 일반 URL인 경우 S3 경로 탐지 시도
            details.append("[S3-1] S3 URL 탐지")
            
            s3_endpoints = [
                '/s3/',
                '/.s3/',
                '/static/s3/',
                '/uploads/',
            ]
            
            for endpoint in s3_endpoints:
                try:
                    url = target_url.rstrip('/') + endpoint
                    response = requests.get(url, timeout=5, verify=False)
                    
                    if 'ListBucketResult' in response.text or 'AccessDenied' in response.text:
                        is_s3 = True
                        details.append(f"  S3 엔드포인트 발견: {endpoint}")
                        break
                        
                except requests.RequestException:
                    continue
            
            if not is_s3:
                details.append("  • S3 엔드포인트 미감지")
                result['details'] = '\n'.join(details)
                return result
        
        details.append("[S3-2] S3 버킷 접근 테스트")
        
        # 버킷 리스팅 시도
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                # 버킷 리스팅 노출
                if 'ListBucketResult' in response.text:
                    result['status'] = 'VULNERABLE'
                    result['vulnerabilities'].append("S3 버킷 리스팅 공개됨")
                    details.append("  ✗ 버킷 리스팅 공개 (모든 파일 목록 노출)")
                    
                    # 파일 개수 파악
                    import re
                    keys = re.findall(r'<Key>([^<]+)</Key>', response.text)
                    if keys:
                        details.append(f"  노출된 파일 수: {len(keys)}개")
                        for key in keys[:5]:
                            details.append(f"    - {key}")
                            
                elif '<html' in response.text.lower():
                    details.append("  ✓ 정적 웹 호스팅 모드")
                else:
                    details.append("  파일 직접 접근 가능")
                    
            elif response.status_code == 403:
                details.append("  ✓ 버킷 접근 거부됨 (정상)")
                
            elif response.status_code == 404:
                details.append("  • 버킷 미존재 또는 접근 불가")
                
        except requests.RequestException as e:
            details.append(f"  접근 오류: {str(e)}")
        
        # 민감 파일 존재 확인
        details.append("\n[S3-3] 민감 파일 노출 확인")
        
        sensitive_files = [
            '.env',
            'config.json',
            'credentials.json',
            'backup.sql',
            'database.sql',
            '.git/config',
            'id_rsa',
            'id_rsa.pub',
        ]
        
        exposed_files = []
        
        for file in sensitive_files:
            try:
                file_url = target_url.rstrip('/') + '/' + file
                response = requests.head(file_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    exposed_files.append(file)
                    
            except requests.RequestException:
                continue
        
        if exposed_files:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'].append(f"민감 파일 노출: {', '.join(exposed_files)}")
            details.append(f"  ✗ 민감 파일 접근 가능:")
            for f in exposed_files:
                details.append(f"    - {f}")
        else:
            details.append("  ✓ 민감 파일 미노출")
        
        # ACL 확인 (가능한 경우)
        details.append("\n[S3-4] 버킷 ACL 확인")
        
        try:
            acl_url = target_url.rstrip('/') + '/?acl'
            response = requests.get(acl_url, timeout=5, verify=False)
            
            if response.status_code == 200 and 'AccessControlPolicy' in response.text:
                details.append("  ⚠ ACL 공개 읽기 가능")
                
                if 'AllUsers' in response.text:
                    result['vulnerabilities'].append("S3 ACL에 AllUsers 권한 존재")
                    details.append("  ✗ AllUsers 권한 발견")
                    result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ ACL 접근 차단")
                
        except requests.RequestException:
            details.append("  ACL 확인 불가")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
