"""
XSS 안전 버전 (Safety Version)

저장형 XSS 없이 반사형 XSS만 탐지합니다.
- 데이터베이스에 저장되지 않는 페이로드만 사용
- 응답에 반사되는지만 확인
"""
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import html


def scan(target_url):
    result = {
        'name': 'XSS (안전 버전)',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '출력 인코딩, CSP 설정, 입력값 검증',
        'details': ''
    }
    
    details = []
    
    # 안전한 페이로드 (무해한 문자열, 실행되지 않음)
    SAFE_PAYLOADS = [
        # 고유 마커로 반사 여부만 확인
        ('<xss_test_marker_12345>', 'basic_tag'),
        ('"><xss_test_marker_12345>', 'break_attribute'),
        ("'><xss_test_marker_12345>", 'break_single_quote'),
        
        # HTML 엔티티 인코딩 테스트
        ('&lt;script&gt;', 'html_entity'),
        
        # 이벤트 핸들러 패턴 (실행되지 않는 마커)
        ('onmouseover=xss_marker', 'event_handler'),
        
        # JavaScript 프로토콜
        ('javascript:xss_marker', 'js_protocol'),
        
        # SVG/Math 태그
        ('<svg/onload=xss_marker>', 'svg_tag'),
    ]
    
    try:
        details.append("[XSS-Safe-1] XSS 탐지 (안전 모드)")
        details.append("  ※ 반사형 XSS만 탐지, 저장형 테스트 없음\n")
        
        # URL 파라미터 추출
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            test_urls = [
                urljoin(target_url, '/search?q=test'),
                urljoin(target_url, '/?name=test'),
                urljoin(target_url, '/api/search?keyword=test'),
            ]
        else:
            test_urls = [target_url]
        
        vulnerable_points = []
        
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                details.append(f"[테스트] 파라미터: {param_name}")
                
                for payload, payload_type in SAFE_PAYLOADS:
                    try:
                        test_params = {k: v[0] if v else '' for k, v in params.items()}
                        test_params[param_name] = payload
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                        
                        response = requests.get(test_url, timeout=10, verify=False)
                        
                        # 페이로드가 그대로 반사되는지 확인
                        if payload in response.text:
                            vulnerable_points.append({
                                'param': param_name,
                                'payload': payload_type,
                                'reflected': True
                            })
                            details.append(f"    ✗ 반사형 XSS 감지: {payload_type}")
                            details.append(f"      페이로드가 인코딩 없이 반사됨")
                        
                        # HTML 인코딩되어 반사되는 경우 (안전)
                        elif html.escape(payload) in response.text:
                            details.append(f"    ✓ {payload_type}: HTML 인코딩됨 (안전)")
                        
                    except Exception as e:
                        continue
        
        # CSP 헤더 확인
        details.append("\n[XSS-Safe-2] CSP (Content-Security-Policy) 확인")
        
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            headers = response.headers
            
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                details.append(f"  ✓ CSP 설정됨")
                
                # 취약한 CSP 설정 확인
                if "'unsafe-inline'" in csp:
                    details.append("    ⚠ 'unsafe-inline' 사용 (XSS 방어 약화)")
                if "'unsafe-eval'" in csp:
                    details.append("    ⚠ 'unsafe-eval' 사용")
            else:
                details.append("  ⚠ CSP 미설정 (XSS 방어 부재)")
                result['vulnerabilities'].append("CSP 헤더 미설정")
                if result['status'] == 'SAFE':
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'MEDIUM'
                    
        except:
            pass
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'HIGH'
            for v in vulnerable_points:
                result['vulnerabilities'].append(
                    f"반사형 XSS: {v['param']} ({v['payload']})"
                )
            details.append(f"\n  총 {len(vulnerable_points)}개 취약점 발견")
        else:
            details.append("\n  ✓ 반사형 XSS 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
