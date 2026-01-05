"""
웹 캐시 포이즈닝 점검

캐시 키에 포함되지 않는 입력을 통한 캐시 오염 가능성을 탐지합니다.
"""
import requests
import time
import random
import string


def scan(target_url):
    result = {
        'name': '웹 캐시 포이즈닝',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '캐시 키에 모든 관련 헤더 포함, Vary 헤더 설정',
        'details': ''
    }
    
    details = []
    
    # 캐시 포이즈닝 테스트 헤더
    UNKEYED_HEADERS = [
        ('X-Forwarded-Host', 'evil.com'),
        ('X-Original-URL', '/admin'),
        ('X-Rewrite-URL', '/admin'),
        ('X-Forwarded-Scheme', 'http'),
        ('X-Forwarded-Proto', 'http'),
        ('X-Host', 'evil.com'),
        ('X-Original-Host', 'evil.com'),
        ('X-Custom-IP-Authorization', '127.0.0.1'),
    ]
    
    # 고유 캐시 버스터 생성
    def generate_cache_buster():
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    try:
        details.append("[Cache-1] 캐시 헤더 분석\n")
        
        # 정상 요청
        response = requests.get(target_url, timeout=10, verify=False)
        
        # 캐시 관련 헤더 확인
        cache_headers = {
            'Cache-Control': response.headers.get('Cache-Control'),
            'Vary': response.headers.get('Vary'),
            'Age': response.headers.get('Age'),
            'X-Cache': response.headers.get('X-Cache'),
            'CF-Cache-Status': response.headers.get('CF-Cache-Status'),
            'X-Varnish': response.headers.get('X-Varnish'),
        }
        
        is_cached = False
        
        for header, value in cache_headers.items():
            if value:
                details.append(f"  {header}: {value}")
                if 'hit' in str(value).lower() or 'age' in header.lower():
                    is_cached = True
        
        if not any(cache_headers.values()):
            details.append("  캐시 헤더 없음")
        
        # 캐시 포이즈닝 테스트
        details.append("\n[Cache-2] Unkeyed 헤더 테스트")
        
        vulnerable_headers = []
        
        for header_name, header_value in UNKEYED_HEADERS:
            # 캐시 버스터로 고유 URL 생성
            cache_buster = generate_cache_buster()
            test_url = f"{target_url}?cb={cache_buster}"
            
            try:
                # 악성 헤더로 첫 번째 요청 (캐시에 저장되도록)
                headers_with_poison = {header_name: header_value}
                response1 = requests.get(
                    test_url,
                    headers=headers_with_poison,
                    timeout=5,
                    verify=False
                )
                
                # 잠시 대기
                time.sleep(0.5)
                
                # 정상 요청 (캐시에서 가져오는지 확인)
                response2 = requests.get(
                    test_url,
                    timeout=5,
                    verify=False
                )
                
                # 응답에 주입된 값이 있는지 확인
                if header_value in response2.text:
                    vulnerable_headers.append({
                        'header': header_name,
                        'value': header_value,
                        'reflected': True
                    })
                    details.append(f"  ✗ 취약: {header_name}")
                    details.append(f"    주입값 '{header_value}' 캐시됨")
                
                # X-Forwarded-Host의 경우 Location 헤더 확인
                if header_name == 'X-Forwarded-Host':
                    location = response1.headers.get('Location', '')
                    if header_value in location:
                        vulnerable_headers.append({
                            'header': header_name,
                            'value': header_value,
                            'reflected_in': 'Location header'
                        })
                        details.append(f"  ✗ 취약: {header_name} → Location 헤더에 반영")
                
            except Exception as e:
                continue
        
        # Vary 헤더 분석
        details.append("\n[Cache-3] Vary 헤더 분석")
        
        vary = response.headers.get('Vary', '')
        if vary:
            details.append(f"  Vary: {vary}")
            
            # 중요 헤더가 Vary에 포함되어 있는지
            important_headers = ['Origin', 'Accept-Encoding', 'Accept-Language']
            missing = [h for h in important_headers if h.lower() not in vary.lower()]
            
            if missing:
                details.append(f"  ⚠ 누락된 Vary 헤더: {', '.join(missing)}")
        else:
            details.append("  ⚠ Vary 헤더 없음")
            details.append("    캐시 포이즈닝 위험 증가")
        
        # 요약
        details.append("\n[Cache-4] 보안 요약")
        
        if vulnerable_headers:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"캐시 포이즈닝: {v['header']}"
                for v in vulnerable_headers
            ]
            details.append(f"\n  ✗ 취약한 헤더: {len(vulnerable_headers)}개")
        else:
            details.append("\n  ✓ 캐시 포이즈닝 취약점 미발견")
            if is_cached:
                details.append("    ※ 캐시 사용 중, 정기 점검 권장")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
