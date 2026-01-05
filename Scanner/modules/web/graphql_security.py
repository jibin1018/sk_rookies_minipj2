"""
GraphQL Security Scanner
GraphQL 관련 보안 취약점 탐지 (GraphQL 사용 시)
"""
import requests
import json

def scan(target_url):
    result = {
        'name': 'GraphQL Security',
        'category': 'API Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Introspection 비활성화, Query Depth 제한, Rate Limiting',
        'details': ''
    }

    details = []

    # GraphQL 엔드포인트 찾기
    graphql_endpoints = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
    ]

    graphql_url = None

    details.append("[GraphQL-1] GraphQL 엔드포인트 탐지")

    for endpoint in graphql_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            # 간단한 쿼리로 GraphQL 확인
            query = {"query": "{ __typename }"}

            resp = requests.post(url, json=query, timeout=5)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'data' in data or 'errors' in data:
                        graphql_url = url
                        details.append(f"  ✓ GraphQL 엔드포인트 발견: {endpoint}")
                        break
                except:
                    pass

        except:
            pass

    if not graphql_url:
        details.append("  • GraphQL 엔드포인트 없음 (테스트 건너뜀)")
        result['status'] = 'SAFE'
        result['details'] = '\n'.join(details)
        return result

    # 2. Introspection 쿼리 허용 여부
    details.append("\n[GraphQL-2] Introspection 쿼리")

    try:
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            """
        }

        resp = requests.post(graphql_url, json=introspection_query, timeout=5)

        if resp.status_code == 200:
            try:
                data = resp.json()

                if 'data' in data and '__schema' in data['data']:
                    result['vulnerabilities'].append("Introspection 쿼리 허용")
                    details.append(f"  ✗ Introspection 활성화됨 (스키마 노출)")
                    result['status'] = 'VULNERABLE'

                    # 스키마 정보 요약
                    types = data['data']['__schema']['types']
                    type_names = [t['name'] for t in types if not t['name'].startswith('__')]
                    details.append(f"     • 발견된 타입: {len(type_names)}개")

                else:
                    details.append(f"  ✓ Introspection 비활성화됨")

            except:
                details.append(f"  • Introspection 응답 파싱 실패")

    except:
        details.append(f"  • Introspection 테스트 실패")

    # 3. Query Depth Limiting
    details.append("\n[GraphQL-3] Query Depth Limiting")

    try:
        # 깊이 10 쿼리
        deep_query = {
            "query": """
            {
                user {
                    posts {
                        comments {
                            author {
                                posts {
                                    comments {
                                        author {
                                            posts {
                                                comments {
                                                    author {
                                                        id
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }

        resp = requests.post(graphql_url, json=deep_query, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("Query Depth 제한 없음")
            details.append(f"  ✗ 깊은 쿼리 허용됨 (DoS 취약)")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 400:
            details.append(f"  ✓ Query Depth 제한 적용됨 (400)")

    except:
        details.append(f"  • Query Depth 테스트 실패")

    # 4. Batching Attack
    details.append("\n[GraphQL-4] Batching Attack")

    try:
        # 여러 쿼리를 배열로 전송
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            # ... 100개
        ] * 100

        resp = requests.post(graphql_url, json=batch_query, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("Batching Attack 가능")
            details.append(f"  ✗ 대량 배치 쿼리 허용됨")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 413:
            details.append(f"  ✓ 대량 배치 차단됨 (413)")

    except:
        details.append(f"  • Batching 테스트 실패")

    # 5. Circular Query (순환 참조)
    details.append("\n[GraphQL-5] Circular Query")

    try:
        circular_query = {
            "query": """
            {
                user {
                    friends {
                        friends {
                            friends {
                                friends {
                                    id
                                }
                            }
                        }
                    }
                }
            }
            """
        }

        resp = requests.post(graphql_url, json=circular_query, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("순환 쿼리 허용")
            details.append(f"  ⚠ 순환 참조 쿼리 허용됨")

    except:
        details.append(f"  • 순환 쿼리 테스트 실패")

    # 6. Field Suggestion
    details.append("\n[GraphQL-6] Field Suggestion")

    try:
        # 존재하지 않는 필드 쿼리
        query = {
            "query": "{ secretField }"
        }

        resp = requests.post(graphql_url, json=query, timeout=5)

        if resp.status_code == 400:
            try:
                error_data = resp.json()

                if 'errors' in error_data:
                    error_message = str(error_data['errors'])

                    # "Did you mean" 같은 제안이 있는지
                    if 'did you mean' in error_message.lower() or 'suggestion' in error_message.lower():
                        result['vulnerabilities'].append("Field Suggestion 노출")
                        details.append(f"  ⚠ 에러 메시지에서 필드 제안 제공")

            except:
                pass

    except:
        details.append(f"  • Field Suggestion 테스트 실패")

    # 7. Mutation without Authentication
    details.append("\n[GraphQL-7] 인증 없는 Mutation")

    try:
        # 인증 없이 Mutation 시도
        mutation = {
            "query": """
            mutation {
                createUser(name: "hacker", email: "hack@evil.com") {
                    id
                }
            }
            """
        }

        resp = requests.post(graphql_url, json=mutation, timeout=5)

        if resp.status_code == 200:
            try:
                data = resp.json()

                if 'data' in data and data['data'] is not None:
                    result['vulnerabilities'].append("인증 없이 Mutation 가능")
                    details.append(f"  ✗ 인증 없이 데이터 생성 가능")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • Mutation 테스트 실패")

    # 8. Query Complexity
    details.append("\n[GraphQL-8] Query Complexity")

    try:
        # 복잡한 쿼리 (많은 필드)
        complex_query = {
            "query": """
            {
                users {
                    id
                    name
                    email
                    posts {
                        id
                        title
                        content
                        comments {
                            id
                            text
                            author {
                                id
                                name
                            }
                        }
                    }
                }
            }
            """
        }

        resp = requests.post(graphql_url, json=complex_query, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("Query Complexity 제한 없음")
            details.append(f"  ⚠ 복잡한 쿼리 허용됨")

    except:
        details.append(f"  • Query Complexity 테스트 실패")

    # 9. Alias를 이용한 Rate Limiting 우회
    details.append("\n[GraphQL-9] Alias를 이용한 우회")

    try:
        # 하나의 쿼리에 여러 alias
        alias_query = {
            "query": """
            {
                user1: user(id: 1) { id }
                user2: user(id: 2) { id }
                user3: user(id: 3) { id }
                user4: user(id: 4) { id }
                user5: user(id: 5) { id }
            }
            """
        }

        resp = requests.post(graphql_url, json=alias_query, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("Alias를 이용한 Rate Limiting 우회")
            details.append(f"  ⚠ 하나의 쿼리에 다중 Alias 허용")

    except:
        details.append(f"  • Alias 테스트 실패")

    # 10. Subscription DoS
    details.append("\n[GraphQL-10] Subscription")

    try:
        # Subscription 지원 여부
        subscription = {
            "query": """
            subscription {
                messageAdded {
                    id
                    text
                }
            }
            """
        }

        resp = requests.post(graphql_url, json=subscription, timeout=5)

        if resp.status_code == 200:
            details.append(f"  • Subscription 지원됨")
            details.append(f"     권장: Subscription Rate Limiting")

    except:
        details.append(f"  • Subscription 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ GraphQL 보안이 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
