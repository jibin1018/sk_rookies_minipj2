"""
Deserialization 안전 버전 (Safety Version)

실제 페이로드를 실행하지 않고, 역직렬화 취약점 시그니처만 탐지합니다.
- RCE 페이로드 없음
- 에러 메시지 및 응답 분석
"""
import requests
import base64
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'Deserialization (안전 버전)',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '신뢰할 수 없는 데이터 역직렬화 금지, 타입 검증',
        'details': ''
    }
    
    details = []
    
    # 탐지용 마커 (실행되지 않음)
    DETECTION_MARKERS = [
        # Java 직렬화 마커
        ('rO0AB', 'java_base64'),
        ('aced0005', 'java_hex'),
        
        # PHP 직렬화 마커
        ('O:4:"test"', 'php_object'),
        ('a:1:{s:4:"test";s:4:"test";}', 'php_array'),
        
        # Python pickle 마커 (무해)
        ('gASVCAAAAAAAAACMBHRlc3SU', 'python_pickle_b64'),
        
        # .NET 마커
        ('AAEAAAD/////AQ', 'dotnet_base64'),
    ]
    
    # 역직렬화 에러 시그니처
    ERROR_SIGNATURES = [
        'unserialize()', 'ObjectInputStream', 'pickle.loads',
        'java.io.InvalidClassException', 'ClassNotFoundException',
        'streamCorruptedException', 'deserialize',
        'SerializationException', '__wakeup', '__destruct',
        'BinaryFormatter', 'SoapFormatter',
        'yaml.load', 'yaml.unsafe_load',
    ]
    
    try:
        details.append("[Deser-Safe-1] 역직렬화 취약점 탐지 (안전 모드)")
        details.append("  ※ RCE 페이로드 없음, 시그니처 기반 탐지만\n")
        
        vulnerable_points = []
        
        # 쿠키에서 직렬화된 데이터 확인
        details.append("[탐지-1] 쿠키 분석")
        
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            
            for cookie in response.cookies:
                cookie_value = cookie.value
                
                # Base64 디코딩 시도
                try:
                    decoded = base64.b64decode(cookie_value).decode('utf-8', errors='ignore')
                    
                    for marker, marker_type in DETECTION_MARKERS:
                        if marker in cookie_value or marker in decoded:
                            vulnerable_points.append({
                                'location': 'cookie',
                                'name': cookie.name,
                                'type': marker_type
                            })
                            details.append(f"    ⚠ 직렬화된 쿠키 발견: {cookie.name} ({marker_type})")
                            break
                except:
                    pass
                
                # PHP 직렬화 패턴
                if cookie_value.startswith(('a:', 'O:', 's:', 'i:')):
                    vulnerable_points.append({
                        'location': 'cookie',
                        'name': cookie.name,
                        'type': 'php_serialized'
                    })
                    details.append(f"    ⚠ PHP 직렬화 쿠키: {cookie.name}")
                    
        except Exception as e:
            details.append(f"    오류: {str(e)}")
        
        # 잘못된 직렬화 데이터로 에러 유발
        details.append("\n[탐지-2] 에러 응답 분석")
        
        test_endpoints = [
            '/api/user',
            '/session',
            '/data',
        ]
        
        for endpoint in test_endpoints:
            url = urljoin(target_url, endpoint)
            
            try:
                # 잘못된 직렬화 데이터 전송
                malformed_data = 'rO0ABXNyABNqYXZhLnV0aWwuSGFzaFNldLpE'  # 불완전한 Java 직렬화
                
                # POST 요청
                response = requests.post(
                    url,
                    data=malformed_data,
                    headers={'Content-Type': 'application/octet-stream'},
                    timeout=5,
                    verify=False
                )
                
                # 에러 시그니처 확인
                for sig in ERROR_SIGNATURES:
                    if sig.lower() in response.text.lower():
                        vulnerable_points.append({
                            'location': 'endpoint',
                            'name': endpoint,
                            'type': 'error_signature',
                            'signature': sig
                        })
                        details.append(f"    ⚠ 역직렬화 에러 감지: {endpoint}")
                        details.append(f"      시그니처: {sig}")
                        break
                        
            except:
                continue
        
        # 헤더에서 기술 스택 확인
        details.append("\n[탐지-3] 기술 스택 분석")
        
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            
            risk_techs = []
            
            # Java
            if 'jsessionid' in str(response.cookies).lower():
                risk_techs.append('Java (JSESSIONID)')
            
            # .NET
            if 'asp.net' in response.headers.get('X-Powered-By', '').lower():
                risk_techs.append('.NET (ViewState 주의)')
            
            # PHP
            if 'phpsessid' in str(response.cookies).lower():
                risk_techs.append('PHP (unserialize 주의)')
            
            if risk_techs:
                details.append(f"    역직렬화 위험 기술: {', '.join(risk_techs)}")
            else:
                details.append("    • 특정 기술 스택 미감지")
                
        except:
            pass
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'HIGH'
            result['vulnerabilities'] = [
                f"역직렬화 위험: {v['location']} ({v['type']})"
                for v in vulnerable_points
            ]
            details.append(f"\n  총 {len(vulnerable_points)}개 잠재적 취약점 발견")
        else:
            details.append("\n  ✓ 역직렬화 취약점 시그니처 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
