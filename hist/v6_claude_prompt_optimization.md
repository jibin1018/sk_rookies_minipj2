# Version 6: Claude 프롬프트 최적화

## 날짜
2026-01-03

## 작업 내용

### claude_analyzer.py 수정

#### 변경 전후 비교

| 항목 | 변경 전 | 변경 후 |
|------|:-------:|:-------:|
| **프롬프트 길이** | ~15,000자 | ~1,400자 |
| **예상 토큰** | ~3,500개 | ~350개 |
| **절감율** | - | **90%** |
| **섹션 수** | 10개 | 6개 |

---

### 신규 함수: `_categorize_vulnerabilities()`

취약점을 6개 카테고리로 자동 분류

| 카테고리 | 포함 키워드 |
|----------|------------|
| 🔥 **Injection** | sqli, xss, ldap, xml, command, log |
| 🔐 **인증/세션** | session, auth, jwt, cookie, csrf |
| 🌐 **API/클라우드** | api, graphql, cors, ssrf, rate limit, cloud |
| ⚙️ **설정 오류** | header, ssl, csp, cache, cicd, waf |
| 📦 **컴포넌트** | library, deserialization, vulnerable |
| 🔍 **정보 노출** | disclosure, backup, information, enum |

---

### 개선된 보고서 구조

```markdown
### 1. 종합 평가 (Executive Summary)
- 보안 등급, 점수, TOP 3 위험

### 2. 비즈니스 영향
- 금전적 손실, 법적 리스크, 평판 영향

### 3. 취약점 상세 (CRITICAL/HIGH만)
- CVSS, 공격 시나리오, 조치 방안

### 4. 조치 로드맵
- P0/P1/P2 우선순위별 테이블

### 5. 예상 비용
- 즉시/단기/중기 비용 추정

### 6. 규정 준수 요약
- GDPR, 개인정보보호법 위반 가능성
```

---

### 작성 원칙

- 구체적 수치 중심
- 실행 가능한 조치
- 마크다운 테이블 활용

## 변경 파일

- `Scanner/claude_analyzer.py` (수정)
  - `_create_analysis_prompt()` 함수 교체
  - `_categorize_vulnerabilities()` 함수 추가
