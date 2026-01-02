"""
WAF (Web Application Firewall) 탐지

대상 사이트의 WAF 존재 여부를 탐지합니다.
"""
import requests
import re


def scan(target_url):
    result = {
        'name': 'WAF 탐지',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'INFO',
        'vulnerabilities': [],
        'recommendation': 'WAF는 추가 보안 계층을 제공하지만 만능이 아님',
        'details': ''
    }
    
    details = []
    
    # WAF 시그니처
    WAF_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'server': ['cloudflare'],
            'body': ['cloudflare', 'cf-browser-verification'],
        },
        'akamai': {
            'headers': ['x-akamai-transformed', 'akamai-grn'],
            'server': ['akamaighost', 'akamai'],
            'body': ['akamai'],
        },
        'aws_waf': {
            'headers': ['x-amz-cf-id', 'x-amzn-requestid'],
            'server': ['awselb', 'amazon'],
            'body': ['aws'],
        },
        'aws_cloudfront': {
            'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
            'server': ['cloudfront'],
            'body': [],
        },
        'imperva_incapsula': {
            'headers': ['x-cdn', 'x-iinfo'],
            'server': ['incapsula'],
            'body': ['incapsula', 'visid_incap'],
        },
        'f5_big_ip': {
            'headers': [],
            'server': ['big-ip', 'bigip'],
            'body': [],
            'cookies': ['bigipserver', 'f5-'],
        },
        'fortinet_fortiweb': {
            'headers': ['fortiwafsid'],
            'server': ['fortiweb'],
            'body': [],
        },
        'sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'server': ['sucuri'],
            'body': ['sucuri'],
        },
        'barracuda': {
            'headers': ['barra_counter_session'],
            'server': ['barracuda'],
            'body': [],
        },
        'modsecurity': {
            'headers': [],
            'server': ['mod_security', 'modsecurity'],
            'body': ['modsecurity', 'mod_security'],
        },
    }
    
    try:
        details.append("[WAF-1] WAF 탐지 시작\n")
        
        detected_wafs = []
        
        # 정상 요청
        response = requests.get(target_url, timeout=10, verify=False)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        server = headers.get('server', '').lower()
        body = response.text.lower()
        cookies = str(response.cookies).lower()
        
        details.append("[WAF-2] 응답 헤더 분석")
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            detected = False
            detection_method = []
            
            # 헤더 검사
            for sig_header in signatures.get('headers', []):
                if sig_header.lower() in headers:
                    detected = True
                    detection_method.append(f'header:{sig_header}')
            
            # 서버 헤더 검사
            for sig_server in signatures.get('server', []):
                if sig_server.lower() in server:
                    detected = True
                    detection_method.append(f'server:{sig_server}')
            
            # 쿠키 검사
            for sig_cookie in signatures.get('cookies', []):
                if sig_cookie.lower() in cookies:
                    detected = True
                    detection_method.append(f'cookie:{sig_cookie}')
            
            # 본문 검사 (차단 페이지)
            for sig_body in signatures.get('body', []):
                if sig_body.lower() in body:
                    detected = True
                    detection_method.append(f'body:{sig_body}')
            
            if detected:
                detected_wafs.append({
                    'name': waf_name,
                    'method': detection_method
                })
        
        # 알려진 CDN/proxy 헤더 확인
        cdn_headers = ['via', 'x-cache', 'x-served-by', 'x-proxy']
        for h in cdn_headers:
            if h in headers:
                details.append(f"  {h}: {headers[h][:50]}")
        
        # 차단 테스트 (무해한 패턴)
        details.append("\n[WAF-3] 차단 패턴 테스트")
        
        test_payloads = [
            "?test=<script>alert(1)</script>",
            "?id=1' OR '1'='1",
            "?file=../../../etc/passwd",
        ]
        
        blocked_count = 0
        for payload in test_payloads:
            try:
                test_url = target_url.rstrip('/') + payload
                test_response = requests.get(test_url, timeout=5, verify=False)
                
                # 차단 시그니처
                block_indicators = ['blocked', 'denied', 'forbidden', '403', 
                                   'security', 'firewall', 'waf', 'attack']
                
                if test_response.status_code == 403:
                    blocked_count += 1
                elif any(ind in test_response.text.lower() for ind in block_indicators):
                    blocked_count += 1
                    
            except:
                continue
        
        if blocked_count > 0:
            details.append(f"  차단된 패턴: {blocked_count}/{len(test_payloads)}")
            if not detected_wafs:
                detected_wafs.append({
                    'name': 'unknown_waf',
                    'method': ['behavior:blocking']
                })
        
        # 요약
        details.append("\n[WAF-4] 탐지 결과")
        
        if detected_wafs:
            result['status'] = 'SAFE'
            result['severity'] = 'INFO'
            details.append(f"\n  ✓ WAF 탐지됨: {len(detected_wafs)}개")
            
            for waf in detected_wafs:
                details.append(f"    - {waf['name'].upper()}")
                details.append(f"      방법: {', '.join(waf['method'])}")
            
            result['vulnerabilities'] = [
                f"WAF 감지: {waf['name']}" for waf in detected_wafs
            ]
        else:
            details.append("\n  ⚠ WAF 미감지")
            details.append("    WAF가 없거나 탐지 회피 설정")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
