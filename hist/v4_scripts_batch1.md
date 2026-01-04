# Version 4: 신규 취약점 스크립트 (1차 - 5개)

## 날짜
2026-01-03

## 작업 내용

### 추가된 스크립트

| 파일 | 점검 항목 | 심각도 |
|------|----------|:------:|
| `graphql_introspection.py` | GraphQL 스키마 노출 | MEDIUM |
| `session_fixation.py` | 세션 고정 공격 | HIGH |
| `cache_poisoning.py` | 웹 캐시 포이즈닝 | HIGH |
| `websocket_security.py` | WebSocket 보안 | MEDIUM |
| `cors_detailed.py` | CORS 상세 분석 | HIGH |

---

### 1. graphql_introspection.py

GraphQL Introspection 쿼리를 통한 스키마 노출 탐지

- `/graphql`, `/api/graphql` 등 엔드포인트 탐색
- `__schema` 쿼리 실행
- 타입, 필드, 뮤테이션 정보 노출 확인

---

### 2. session_fixation.py

세션 고정 공격 취약점 점검

- 로그인 전후 세션 ID 변경 확인
- 클라이언트 제공 세션 ID 수용 여부
- Secure/HttpOnly 속성 검사

---

### 3. cache_poisoning.py

웹 캐시 오염 가능성 탐지

- Unkeyed 헤더 테스트:
  - `X-Forwarded-Host`
  - `X-Original-URL`
  - `X-Rewrite-URL`
- 캐시 키 분석

---

### 4. websocket_security.py

WebSocket 연결 보안 점검

- Origin 헤더 검증 여부
- WSS (TLS) 사용 여부
- 인증 토큰 전송 방식

---

### 5. cors_detailed.py

CORS 정책 상세 분석

- Origin 반영 여부
- `Access-Control-Allow-Credentials`
- Preflight 요청 처리
- 와일드카드 (`*`) 사용 여부

## 변경 파일

- `Scanner/modules/web/graphql_introspection.py` (신규)
- `Scanner/modules/web/session_fixation.py` (신규)
- `Scanner/modules/web/cache_poisoning.py` (신규)
- `Scanner/modules/web/websocket_security.py` (신규)
- `Scanner/modules/web/cors_detailed.py` (신규)
