"""
CSP (Content-Security-Policy) 분석

CSP 헤더의 보안 설정을 상세 분석합니다.
"""
import requests


def scan(target_url):
    result = {
        'name': 'CSP 분석',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '엄격한 CSP 설정으로 XSS 방어',
        'details': ''
    }
    
    details = []
    
    # 취약한 CSP 지시어
    DANGEROUS_DIRECTIVES = {
        "'unsafe-inline'": "인라인 스크립트 허용 (XSS 취약)",
        "'unsafe-eval'": "eval() 허용 (코드 실행 위험)",
        "'unsafe-hashes'": "인라인 이벤트 핸들러 허용",
        "data:": "data: URI 허용 (XSS 가능)",
        "blob:": "blob: URI 허용",
        "*": "모든 소스 허용 (위험)",
    }
    
    try:
        details.append("[CSP-1] Content-Security-Policy 분석\n")
        
        response = requests.get(target_url, timeout=10, verify=False)
        headers = response.headers
        
        csp = headers.get('Content-Security-Policy')
        csp_ro = headers.get('Content-Security-Policy-Report-Only')
        
        if not csp and not csp_ro:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'].append("CSP 헤더 미설정")
            details.append("  ✗ CSP 헤더 없음")
            details.append("    XSS 방어를 위해 CSP 설정 권장")
            result['details'] = '\n'.join(details)
            return result
        
        # CSP 분석
        policy = csp or csp_ro
        is_report_only = csp_ro and not csp
        
        if is_report_only:
            details.append("  ⚠ Report-Only 모드 (차단하지 않음)")
        else:
            details.append("  ✓ CSP 적용됨")
        
        # 지시어 파싱
        directives = {}
        for directive in policy.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                directives[parts[0]] = parts[1:] if len(parts) > 1 else []
        
        details.append(f"\n[CSP-2] 지시어 분석 ({len(directives)}개)")
        
        important_directives = [
            'default-src', 'script-src', 'style-src', 'img-src',
            'connect-src', 'frame-src', 'object-src', 'base-uri'
        ]
        
        issues = []
        
        for dir_name in important_directives:
            if dir_name in directives:
                sources = directives[dir_name]
                details.append(f"\n  {dir_name}:")
                details.append(f"    {' '.join(sources)}")
                
                # 취약한 설정 확인
                for source in sources:
                    for danger, desc in DANGEROUS_DIRECTIVES.items():
                        if danger in source:
                            issues.append(f"{dir_name}: {danger}")
                            details.append(f"    ⚠ {danger} - {desc}")
            else:
                if dir_name == 'default-src':
                    details.append(f"\n  {dir_name}: 미설정 (위험)")
                    issues.append("default-src 미설정")
        
        # object-src 확인 (Flash 등)
        if 'object-src' not in directives:
            if 'default-src' not in directives or "'none'" not in directives.get('default-src', []):
                issues.append("object-src 미설정")
                details.append("\n  object-src: 미설정 (플래시 취약점 가능)")
        
        # base-uri 확인
        if 'base-uri' not in directives:
            issues.append("base-uri 미설정")
            details.append("\n  base-uri: 미설정 (base tag injection 가능)")
        
        # 요약
        details.append("\n[CSP-3] 보안 요약")
        
        if issues:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = issues[:5]  # 상위 5개
            details.append(f"\n  취약점: {len(issues)}개")
            for issue in issues[:5]:
                details.append(f"    - {issue}")
        else:
            details.append("\n  ✓ CSP 설정 양호")
        
        # Nonce/Hash 사용 여부
        if 'nonce-' in policy:
            details.append("\n  ✓ Nonce 기반 CSP 사용")
        if "'strict-dynamic'" in policy:
            details.append("  ✓ strict-dynamic 사용")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
