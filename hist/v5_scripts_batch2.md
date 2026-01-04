# Version 5: 신규 취약점 스크립트 (2차 - 8개)

## 날짜
2026-01-03

## 작업 내용

### 추가된 스크립트

| 파일 | 점검 항목 | 심각도 |
|------|----------|:------:|
| `ldap_injection.py` | LDAP 쿼리 인젝션 | CRITICAL |
| `api_rate_limit_bypass.py` | Rate Limit 우회 | MEDIUM |
| `cloud_metadata.py` | 클라우드 메타데이터 SSRF | CRITICAL |
| `session_timeout.py` | 세션 만료 설정 | MEDIUM |
| `log_injection.py` | 로그 위조 | MEDIUM |
| `ci_cd_exposure.py` | CI/CD 도구 노출 | HIGH |
| `rest_api_enum.py` | REST API 열거 | MEDIUM |
| `xml_injection.py` | XML 파싱 취약점 | HIGH |

---

### 1. ldap_injection.py

LDAP 쿼리 인젝션 탐지 (에러 기반)

- 페이로드: `*`, `)(cn=*`, `*)(uid=*))(|(uid=*`
- LDAP 에러 메시지 탐지

---

### 2. api_rate_limit_bypass.py

Rate Limiting 우회 가능성 점검

- `X-Forwarded-For`, `X-Real-IP` 헤더 조작
- `X-Originating-IP` 변형
- 헤더별 응답 차이 분석

---

### 3. cloud_metadata.py

클라우드 메타데이터 SSRF 점검

- AWS: `169.254.169.254/latest/meta-data/`
- GCP: `metadata.google.internal`
- Azure: `169.254.169.254/metadata/`

---

### 4. session_timeout.py

세션 타임아웃 설정 분석

- `Set-Cookie` 헤더의 `max-age`, `expires`
- 세션 관련 보안 헤더 확인

---

### 5. log_injection.py

로그 인젝션 가능성 탐지

- 줄바꿈 문자 (`\r\n`)
- ANSI 이스케이프 코드
- 가짜 로그 엔트리 삽입

---

### 6. ci_cd_exposure.py

CI/CD 도구 및 설정 파일 노출 탐지

- Jenkins: `/jenkins/`, `/script`
- GitLab: `/.gitlab-ci.yml`
- GitHub Actions: `/.github/workflows/`
- 설정 파일: `Jenkinsfile`, `azure-pipelines.yml`

---

### 7. rest_api_enum.py

REST API 엔드포인트 열거

- Swagger: `/swagger.json`, `/api-docs`
- OpenAPI: `/openapi.json`
- Admin API: `/api/admin`, `/api/v1/users`

---

### 8. xml_injection.py

XML 파싱 취약점 탐지

- 잘못된 XML 구조 테스트
- CDATA 섹션 인젝션
- 엔티티 확장 (XXE 기초)

## 변경 파일

- `Scanner/modules/web/ldap_injection.py` (신규)
- `Scanner/modules/web/api_rate_limit_bypass.py` (신규)
- `Scanner/modules/web/cloud_metadata.py` (신규)
- `Scanner/modules/web/session_timeout.py` (신규)
- `Scanner/modules/web/log_injection.py` (신규)
- `Scanner/modules/web/ci_cd_exposure.py` (신규)
- `Scanner/modules/web/rest_api_enum.py` (신규)
- `Scanner/modules/web/xml_injection.py` (신규)
