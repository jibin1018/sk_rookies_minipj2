# Version 2: 결과 표준화 및 페이로드 라이브러리

## 날짜
2026-01-03

## 작업 내용

### 1. utils/result.py - 스캔 결과 표준화

#### ScanResult 클래스

```python
@dataclass
class ScanResult:
    name: str           # 스크립트 이름
    category: str       # 카테고리 (injection, session 등)
    status: ScanStatus  # SAFE, VULNERABLE, ERROR
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW
    vulnerabilities: List[str]
    recommendation: str
```

#### ScanStatus Enum

| 상태 | 설명 |
|------|------|
| SAFE | 취약점 없음 |
| VULNERABLE | 취약점 발견 |
| ERROR | 스캔 오류 |
| SKIPPED | 스킵됨 |

---

### 2. utils/payloads.py - 페이로드 라이브러리

| 카테고리 | 페이로드 수 | 용도 |
|---------|:----------:|------|
| **SQLI_PAYLOADS** | 20+ | SQL Injection 탐지 |
| **XSS_PAYLOADS** | 15+ | Cross-Site Scripting |
| **CMDI_PAYLOADS** | 10+ | Command Injection |
| **PATH_TRAVERSAL** | 12+ | 경로 탐색 |
| **ERROR_SIGNATURES** | 30+ | 에러 메시지 탐지 |

---

### 3. utils/encoders.py - 인코딩 유틸리티

| 함수 | 설명 |
|------|------|
| `url_encode()` | URL 인코딩 |
| `double_url_encode()` | 이중 URL 인코딩 |
| `html_entity_encode()` | HTML 엔티티 |
| `hex_encode()` | 16진수 인코딩 |
| `unicode_encode()` | 유니코드 |
| `mixed_case()` | 대소문자 혼합 (WAF 우회) |
| `generate_encoded_variants()` | 모든 변형 생성 |

## 변경 파일

- `Scanner/utils/result.py` (신규)
- `Scanner/utils/payloads.py` (신규)
- `Scanner/utils/encoders.py` (신규)
- `Scanner/utils/__init__.py` (수정)
