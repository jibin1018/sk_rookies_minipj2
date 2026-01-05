"""
REST API 엔드포인트 열거

숨겨진 API 엔드포인트를 탐지합니다.
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'REST API 열거',
        'category': 'API Security',
        'status': 'SAFE',
        'severity': 'INFO',
        'vulnerabilities': [],
        'recommendation': '불필요한 API 엔드포인트 비활성화, 인증 적용',
        'details': ''
    }
    
    details = []
    
    # 일반적인 API 엔드포인트
    API_ENDPOINTS = [
        # API 문서
        ('/swagger', 'Swagger UI'),
        ('/swagger-ui.html', 'Swagger UI'),
        ('/swagger-ui/', 'Swagger UI'),
        ('/api-docs', 'API Docs'),
        ('/api/swagger.json', 'Swagger JSON'),
        ('/openapi.json', 'OpenAPI'),
        ('/v2/api-docs', 'Swagger v2'),
        ('/v3/api-docs', 'Swagger v3'),
        ('/redoc', 'ReDoc'),
        
        # GraphQL
        ('/graphql', 'GraphQL'),
        ('/graphiql', 'GraphiQL'),
        ('/playground', 'GraphQL Playground'),
        
        # 일반적인 API 경로
        ('/api', 'API Root'),
        ('/api/v1', 'API v1'),
        ('/api/v2', 'API v2'),
        ('/api/v3', 'API v3'),
        ('/rest', 'REST API'),
        
        # 관리자 API
        ('/api/admin', 'Admin API'),
        ('/api/internal', 'Internal API'),
        ('/api/debug', 'Debug API'),
        ('/api/test', 'Test API'),
        
        # 사용자 관련
        ('/api/users', 'Users API'),
        ('/api/user', 'User API'),
        ('/api/profile', 'Profile API'),
        ('/api/accounts', 'Accounts API'),
        
        # 인증 관련
        ('/api/auth', 'Auth API'),
        ('/api/login', 'Login API'),
        ('/api/token', 'Token API'),
        ('/oauth', 'OAuth'),
        
        # 데이터 관련
        ('/api/data', 'Data API'),
        ('/api/export', 'Export API'),
        ('/api/import', 'Import API'),
        ('/api/backup', 'Backup API'),
        
        # 헬스체크
        ('/health', 'Health Check'),
        ('/healthz', 'Health Check'),
        ('/status', 'Status'),
        ('/api/health', 'API Health'),
        ('/metrics', 'Metrics'),
        ('/api/metrics', 'API Metrics'),
    ]
    
    try:
        details.append("[API-1] REST API 엔드포인트 열거\n")
        
        found_endpoints = []
        sensitive_endpoints = []
        
        parsed_base = urljoin(target_url, '/')
        
        for path, name in API_ENDPOINTS:
            url = urljoin(parsed_base, path)
            
            try:
                response = requests.get(
                    url,
                    timeout=3,
                    verify=False,
                    headers={'Accept': 'application/json'}
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    endpoint_info = {
                        'path': path,
                        'name': name,
                        'status': response.status_code,
                        'content_type': content_type[:30]
                    }
                    
                    # 민감한 엔드포인트 분류
                    if any(s in path.lower() for s in ['admin', 'internal', 'debug', 'backup', 'swagger', 'api-docs']):
                        sensitive_endpoints.append(endpoint_info)
                        details.append(f"  ⚠ {name}: {path}")
                    else:
                        found_endpoints.append(endpoint_info)
                        details.append(f"  • {name}: {path}")
                
                elif response.status_code in [401, 403]:
                    # 인증 필요 = API 존재
                    found_endpoints.append({
                        'path': path,
                        'name': name,
                        'status': response.status_code,
                        'protected': True
                    })
                    details.append(f"  🔒 {name}: {path} (인증 필요)")
                    
            except:
                continue
        
        # 요약
        details.append(f"\n[API-2] 발견된 엔드포인트: {len(found_endpoints) + len(sensitive_endpoints)}개")
        
        if sensitive_endpoints:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'MEDIUM'
            result['vulnerabilities'] = [
                f"민감 API 노출: {e['path']}" for e in sensitive_endpoints
            ]
            details.append(f"  ⚠ 민감 엔드포인트: {len(sensitive_endpoints)}개")
        
        if found_endpoints:
            protected = sum(1 for e in found_endpoints if e.get('protected'))
            details.append(f"  • 일반 엔드포인트: {len(found_endpoints)}개")
            details.append(f"  🔒 보호된 엔드포인트: {protected}개")
        
        if not found_endpoints and not sensitive_endpoints:
            details.append("  • API 엔드포인트 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
