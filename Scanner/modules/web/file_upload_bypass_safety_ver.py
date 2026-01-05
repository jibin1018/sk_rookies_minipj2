"""
File Upload Bypass 안전 버전 (Safety Version)

웹쉘이나 악성 파일을 업로드하지 않고, 업로드 검증 로직만 테스트합니다.
- 무해한 텍스트 파일만 업로드
- 파일 확장자 필터링 우회 가능 여부만 확인
"""
import requests
from urllib.parse import urljoin
import io


def scan(target_url):
    result = {
        'name': 'File Upload Bypass (안전 버전)',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '파일 확장자 화이트리스트, 매직 바이트 검증, 격리된 저장소 사용',
        'details': ''
    }
    
    details = []
    
    # 안전한 테스트 파일 (무해한 텍스트)
    SAFE_TEST_FILES = [
        # 확장자 우회 테스트 (모두 텍스트 내용)
        ('test.txt', 'text/plain', b'This is a harmless test file.'),
        ('test.php.txt', 'text/plain', b'Extension bypass test - NOT executable'),
        ('test.jpg.php', 'text/plain', b'Extension bypass test - NOT executable'),
        ('test.php%00.jpg', 'image/jpeg', b'Null byte test - NOT executable'),
        ('test.phtml', 'text/plain', b'Alternate extension test'),
        ('test.PhP', 'text/plain', b'Case variation test'),
        
        # MIME 타입 우회 테스트
        ('test.php', 'image/jpeg', b'MIME bypass test - text only'),
        ('test.php', 'image/gif', b'GIF89a - fake header, text file'),
        
        # 더블 확장자
        ('test.jpg.asp', 'image/jpeg', b'Double extension test'),
    ]
    
    # 업로드 폼 경로 후보
    UPLOAD_PATHS = [
        '/upload',
        '/file/upload',
        '/api/upload',
        '/upload.php',
        '/admin/upload',
        '/media/upload',
    ]
    
    try:
        details.append("[Upload-Safe-1] 파일 업로드 보안 테스트 (안전 모드)")
        details.append("  ※ 무해한 텍스트 파일만 업로드, 웹쉘 없음\n")
        
        upload_found = False
        vulnerable_points = []
        
        for path in UPLOAD_PATHS:
            upload_url = urljoin(target_url, path)
            
            try:
                # 업로드 폼 존재 확인
                response = requests.get(upload_url, timeout=5, verify=False)
                
                if response.status_code != 200:
                    continue
                
                # 폼이 있는지 확인
                if 'multipart' not in response.text.lower() and 'upload' not in response.text.lower():
                    continue
                
                upload_found = True
                details.append(f"[발견] 업로드 엔드포인트: {path}")
                
                # 각 테스트 파일로 업로드 시도
                for filename, content_type, content in SAFE_TEST_FILES:
                    try:
                        files = {
                            'file': (filename, io.BytesIO(content), content_type)
                        }
                        
                        upload_response = requests.post(
                            upload_url,
                            files=files,
                            timeout=10,
                            verify=False
                        )
                        
                        # 업로드 성공 시그니처
                        success_indicators = ['success', 'uploaded', 'complete', 'saved', '200']
                        failed_indicators = ['denied', 'not allowed', 'invalid', 'error', 'rejected']
                        
                        response_lower = upload_response.text.lower()
                        
                        # 위험 확장자가 허용되었는지 확인
                        dangerous_ext = ['.php', '.asp', '.jsp', '.phtml']
                        is_dangerous = any(ext in filename.lower() for ext in dangerous_ext)
                        
                        if upload_response.status_code == 200:
                            if any(ind in response_lower for ind in success_indicators):
                                if is_dangerous:
                                    vulnerable_points.append({
                                        'path': path,
                                        'filename': filename,
                                        'content_type': content_type,
                                        'issue': 'dangerous_extension_allowed'
                                    })
                                    details.append(f"    ✗ 위험 확장자 허용: {filename}")
                                else:
                                    details.append(f"    ✓ 안전한 파일 업로드: {filename}")
                            
                            elif any(ind in response_lower for ind in failed_indicators):
                                details.append(f"    ✓ 차단됨: {filename}")
                        
                    except Exception as e:
                        continue
                
            except Exception as e:
                continue
        
        if not upload_found:
            details.append("  • 업로드 엔드포인트 미발견")
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"위험 확장자 허용: {v['filename']} at {v['path']}"
                for v in vulnerable_points
            ]
            details.append(f"\n  총 {len(vulnerable_points)}개 취약점 발견")
        else:
            details.append("\n  ✓ 파일 업로드 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
