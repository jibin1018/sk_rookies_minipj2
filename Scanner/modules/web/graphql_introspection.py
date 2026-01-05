"""
GraphQL Introspection 점검

GraphQL 엔드포인트의 스키마 노출 여부를 확인합니다.
"""
import requests
import json


def scan(target_url):
    result = {
        'name': 'GraphQL Introspection',
        'category': 'API Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Production 환경에서 Introspection 비활성화',
        'details': ''
    }
    
    details = []
    
    # GraphQL 엔드포인트 후보
    GRAPHQL_ENDPOINTS = [
        '/graphql',
        '/graphql/',
        '/api/graphql',
        '/v1/graphql',
        '/query',
        '/gql',
    ]
    
    # Introspection 쿼리
    INTROSPECTION_QUERY = {
        'query': '''
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                        }
                    }
                }
            }
        '''
    }
    
    # 간단한 쿼리
    SIMPLE_QUERY = {
        'query': '{ __typename }'
    }
    
    try:
        details.append("[GraphQL-1] GraphQL 엔드포인트 탐지\n")
        
        graphql_found = []
        introspection_enabled = []
        
        for endpoint in GRAPHQL_ENDPOINTS:
            url = target_url.rstrip('/') + endpoint
            
            try:
                # 간단한 쿼리로 GraphQL 확인
                response = requests.post(
                    url,
                    json=SIMPLE_QUERY,
                    headers={'Content-Type': 'application/json'},
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data or 'errors' in data:
                            graphql_found.append(endpoint)
                            details.append(f"  발견: {endpoint}")
                    except:
                        pass
                        
            except:
                continue
        
        if not graphql_found:
            details.append("  GraphQL 엔드포인트 미발견")
            result['details'] = '\n'.join(details)
            return result
        
        # Introspection 테스트
        details.append("\n[GraphQL-2] Introspection 테스트")
        
        for endpoint in graphql_found:
            url = target_url.rstrip('/') + endpoint
            
            try:
                response = requests.post(
                    url,
                    json=INTROSPECTION_QUERY,
                    headers={'Content-Type': 'application/json'},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'data' in data and data['data'] and '__schema' in data['data']:
                        schema = data['data']['__schema']
                        
                        introspection_enabled.append(endpoint)
                        
                        # 스키마 정보 추출
                        types = schema.get('types', [])
                        type_names = [t['name'] for t in types if not t['name'].startswith('__')]
                        
                        details.append(f"\n  ✗ Introspection 활성화: {endpoint}")
                        details.append(f"    Query Type: {schema.get('queryType', {}).get('name')}")
                        details.append(f"    Mutation Type: {schema.get('mutationType', {}).get('name')}")
                        details.append(f"    타입 수: {len(type_names)}개")
                        
                        if len(type_names) > 0:
                            details.append(f"    주요 타입: {', '.join(type_names[:5])}")
                            if len(type_names) > 5:
                                details.append(f"    ... 외 {len(type_names) - 5}개")
                    
                    elif 'errors' in data:
                        details.append(f"\n  ✓ Introspection 비활성화: {endpoint}")
                        
            except Exception as e:
                continue
        
        # 결과 요약
        details.append("\n[GraphQL-3] 보안 요약")
        
        if introspection_enabled:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"GraphQL Introspection 활성화: {ep}"
                for ep in introspection_enabled
            ]
            details.append(f"\n  ✗ 취약: {len(introspection_enabled)}개 엔드포인트")
            details.append("    스키마 정보가 외부에 노출됨")
        else:
            details.append("\n  ✓ Introspection 비활성화됨")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
