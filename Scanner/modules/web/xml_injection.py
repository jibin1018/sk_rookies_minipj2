"""
XML Injection 안전 점검

XML 파싱 관련 취약점을 안전하게 탐지합니다.
- XML External Entity (XXE)와 별도로 XML 구조 인젝션 점검
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'XML Injection',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'XML 파서 보안 설정, 외부 엔티티 비활성화',
        'details': ''
    }
    
    details = []
    
    # 안전한 XML 인젝션 테스트 페이로드
    SAFE_XML_PAYLOADS = [
        # 잘못된 XML 구조
        ('<test', 'incomplete_tag'),
        ('</test>', 'closing_only'),
        ('<test attr="value"', 'unclosed_attr'),
        
        # CDATA 인젝션
        (']]><test>injected</test><![CDATA[', 'cdata_escape'),
        
        # 주석 인젝션
        ('--><test>injected</test><!--', 'comment_escape'),
        
        # 엔티티 테스트 (안전)
        ('&amp;test&amp;', 'entity_safe'),
        ('&#x41;&#x42;&#x43;', 'hex_entity'),
        
        # 속성 인젝션
        ('" attr="injected', 'attr_injection'),
        ("' attr='injected", 'attr_single_quote'),
    ]
    
    # XML 에러 시그니처
    XML_ERRORS = [
        'xml parsing error', 'xml syntax', 'xmlparseentity',
        'simplexml', 'saxparser', 'xerces', 'expat',
        'malformed xml', 'invalid xml', 'xml document',
        'expected \'>\' ', 'start tag', 'end tag',
        'jaxb', 'javax.xml', 'sax exception',
        'dom exception', 'xml parser error',
    ]
    
    try:
        details.append("[XML-1] XML Injection 탐지 (안전 모드)\n")
        
        # XML API 엔드포인트 탐색
        xml_endpoints = [
            '/api/xml', '/xml', '/soap', '/wsdl',
            '/feed', '/rss', '/sitemap.xml',
        ]
        
        parsed_base = urljoin(target_url, '/')
        
        found_xml = []
        vulnerable_points = []
        
        # 기본 요청으로 XML 지원 확인
        for ep in xml_endpoints:
            url = urljoin(parsed_base, ep)
            try:
                response = requests.get(url, timeout=5, verify=False)
                content_type = response.headers.get('Content-Type', '')
                
                if 'xml' in content_type.lower() or '<?xml' in response.text[:100]:
                    found_xml.append(ep)
                    details.append(f"  XML 엔드포인트: {ep}")
                    
            except:
                continue
        
        if not found_xml:
            details.append("  XML 엔드포인트 미발견")
        
        # POST 요청으로 XML 인젝션 테스트
        details.append("\n[XML-2] XML 파싱 테스트")
        
        # Content-Type: application/xml로 테스트
        for payload, payload_type in SAFE_XML_PAYLOADS[:5]:
            try:
                # 기본 XML 구조에 페이로드 삽입
                test_xml = f'<?xml version="1.0"?><root><data>{payload}</data></root>'
                
                response = requests.post(
                    target_url,
                    data=test_xml,
                    headers={'Content-Type': 'application/xml'},
                    timeout=5,
                    verify=False
                )
                
                response_lower = response.text.lower()
                
                # XML 에러 감지
                for error in XML_ERRORS:
                    if error in response_lower:
                        vulnerable_points.append({
                            'payload': payload_type,
                            'error': error
                        })
                        details.append(f"  ✗ XML 에러 감지: {error}")
                        break
                        
            except:
                continue
        
        # SOAP 엔드포인트 확인
        details.append("\n[XML-3] SOAP 서비스 확인")
        
        soap_endpoints = ['/soap', '/webservice', '/ws', '?wsdl']
        
        for ep in soap_endpoints:
            url = urljoin(parsed_base, ep)
            try:
                response = requests.get(url, timeout=3, verify=False)
                if 'wsdl' in response.text.lower() or 'soap' in response.text.lower():
                    details.append(f"  발견: {ep}")
                    result['vulnerabilities'].append(f"SOAP 서비스 노출: {ep}")
            except:
                continue
        
        # 요약
        details.append("\n[XML-4] 보안 요약")
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            for v in vulnerable_points:
                result['vulnerabilities'].append(f"XML 파싱 취약: {v['error']}")
            details.append(f"\n  ✗ XML 파싱 취약점: {len(vulnerable_points)}개")
        else:
            if result['vulnerabilities']:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
            else:
                details.append("\n  ✓ XML Injection 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
