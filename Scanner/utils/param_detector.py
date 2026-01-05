"""
파라미터 탐지기

웹 페이지에서 테스트 가능한 파라미터를 자동으로 추출합니다.
- URL 쿼리 파라미터
- Form 필드 (POST)
- JSON API 필드
"""
import requests
import re
from urllib.parse import urlparse, parse_qs, urljoin
from typing import List, Dict, Any, Optional
import json


class ParamDetector:
    """파라미터 자동 탐지기"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        })
    
    def detect_all(self, url: str) -> Dict[str, Any]:
        """
        모든 유형의 파라미터 탐지
        
        Returns:
            {
                'url_params': [...],
                'form_params': [...],
                'json_endpoints': [...],
                'cookies': [...],
                'headers': [...]
            }
        """
        result = {
            'url_params': self.detect_url_params(url),
            'form_params': self.detect_form_params(url),
            'json_endpoints': self.detect_json_endpoints(url),
            'cookies': self.detect_cookies(url),
            'headers': self.detect_injectable_headers(),
        }
        return result
    
    def detect_url_params(self, url: str) -> List[Dict]:
        """URL 쿼리 파라미터 추출"""
        params = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for name, values in query_params.items():
            params.append({
                'name': name,
                'value': values[0] if values else '',
                'type': 'query',
                'method': 'GET'
            })
        
        return params
    
    def detect_form_params(self, url: str) -> List[Dict]:
        """HTML Form 파라미터 추출"""
        params = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            html = response.text
            
            # Form 태그 추출
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)
            
            for form_html in forms:
                # Action URL
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                action = action_match.group(1) if action_match else url
                
                # Method
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
                method = method_match.group(1).upper() if method_match else 'GET'
                
                # Input 필드
                input_pattern = r'<input[^>]+>'
                inputs = re.findall(input_pattern, form_html, re.I)
                
                for input_tag in inputs:
                    name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.I)
                    type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.I)
                    value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.I)
                    
                    if name_match:
                        input_type = type_match.group(1) if type_match else 'text'
                        
                        # 제외할 타입
                        if input_type.lower() in ['submit', 'button', 'image', 'reset']:
                            continue
                        
                        params.append({
                            'name': name_match.group(1),
                            'value': value_match.group(1) if value_match else '',
                            'type': input_type,
                            'method': method,
                            'action': urljoin(url, action)
                        })
                
                # Textarea
                textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
                textareas = re.findall(textarea_pattern, form_html, re.I)
                for name in textareas:
                    params.append({
                        'name': name,
                        'value': '',
                        'type': 'textarea',
                        'method': method,
                        'action': urljoin(url, action)
                    })
                
                # Select
                select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
                selects = re.findall(select_pattern, form_html, re.I)
                for name in selects:
                    params.append({
                        'name': name,
                        'value': '',
                        'type': 'select',
                        'method': method,
                        'action': urljoin(url, action)
                    })
                    
        except Exception as e:
            pass
        
        return params
    
    def detect_json_endpoints(self, url: str) -> List[Dict]:
        """JSON API 엔드포인트 탐지"""
        endpoints = []
        
        # 일반적인 API 경로
        api_paths = [
            '/api', '/api/v1', '/api/v2',
            '/graphql', '/rest', '/json',
        ]
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        for path in api_paths:
            api_url = base_url + path
            try:
                response = self.session.get(
                    api_url, 
                    timeout=5, 
                    verify=False,
                    headers={'Accept': 'application/json'}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        endpoints.append({
                            'url': api_url,
                            'method': 'GET',
                            'response_type': 'json',
                            'sample': str(data)[:100]
                        })
                    except:
                        pass
                        
            except:
                continue
        
        return endpoints
    
    def detect_cookies(self, url: str) -> List[Dict]:
        """쿠키 파라미터 추출"""
        cookies = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            for cookie in self.session.cookies:
                cookies.append({
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path
                })
                
        except:
            pass
        
        return cookies
    
    def detect_injectable_headers(self) -> List[Dict]:
        """인젝션 가능한 헤더 목록"""
        return [
            {'name': 'Host', 'injectable': True, 'risk': 'Host Header Injection'},
            {'name': 'X-Forwarded-For', 'injectable': True, 'risk': 'IP Spoofing'},
            {'name': 'X-Forwarded-Host', 'injectable': True, 'risk': 'Cache Poisoning'},
            {'name': 'Referer', 'injectable': True, 'risk': 'Header Injection'},
            {'name': 'User-Agent', 'injectable': True, 'risk': 'Log Injection'},
            {'name': 'Cookie', 'injectable': True, 'risk': 'Cookie Manipulation'},
        ]


def detect_params(url: str) -> Dict[str, Any]:
    """단순화된 인터페이스"""
    detector = ParamDetector()
    return detector.detect_all(url)


def get_testable_params(url: str) -> List[Dict]:
    """테스트 가능한 파라미터만 추출"""
    result = detect_params(url)
    
    testable = []
    
    # URL 파라미터
    for param in result['url_params']:
        testable.append({
            'name': param['name'],
            'location': 'url',
            'method': 'GET',
            'url': url
        })
    
    # Form 파라미터
    for param in result['form_params']:
        testable.append({
            'name': param['name'],
            'location': 'form',
            'method': param['method'],
            'url': param.get('action', url)
        })
    
    return testable
