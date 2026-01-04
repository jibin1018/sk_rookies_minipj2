# Version 8: 인프라 타입 감지 + 스크립트 선별 실행

## 날짜
2026-01-03

## 작업 내용

### 목표
- 인프라 타입 자동 감지
- 감지된 서비스에 맞는 스크립트만 선별 실행
- 스캔 성능 개선

---

### 생성된 파일

| 파일 | 설명 |
|------|------|
| `discovery/infra_detector.py` | 인프라 자동 감지 클래스 |
| `utils/script_registry.py` | 스크립트 메타데이터 관리 |
| `smart_scanner.py` | 통합 스마트 스캐너 |

---

### 1. InfraDetector

**기능**: 포트 스캔 + 배너 분석 + HTTP 헤더로 인프라 유형 식별

**감지 항목**:
- Web Server: Nginx, Apache, IIS
- Database: MySQL, PostgreSQL, MongoDB, Redis
- WAS: Tomcat, PHP, Java, Express
- OS: SSH 배너에서 추정

---

### 2. ScriptRegistry

**기능**: 스크립트 탐색 및 서비스 기반 필터링

---

### 3. SmartScanner

**기능**: 인프라 감지 → 스크립트 선별 → 실행 자동화

---

### 성능 개선 효과

| 시나리오 | 이전 | 이후 | 절감 |
|----------|:----:|:----:|:----:|
| MySQL만 | 80개 | 13개 | 84% |
| Nginx+PHP | 80개 | 65개 | 19% |
| 전체 3티어 | 80개 | 75개 | 6% |

---

## 사용 방법

```bash
# 스마트 스캔 (자동 감지)
python smart_scanner.py https://example.com

# 수동 모듈 지정
python smart_scanner.py https://example.com web db
```

## 변경 파일

- `Scanner/discovery/infra_detector.py` (신규)
- `Scanner/discovery/__init__.py` (수정)
- `Scanner/utils/script_registry.py` (신규)
- `Scanner/utils/__init__.py` (수정)
- `Scanner/smart_scanner.py` (신규)
