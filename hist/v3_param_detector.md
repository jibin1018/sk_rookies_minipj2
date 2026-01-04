# Version 3: 파라미터 자동 탐지

## 날짜
2026-01-03

## 작업 내용

### utils/param_detector.py

웹 페이지에서 테스트 가능한 파라미터를 자동으로 탐지하는 유틸리티

#### ParamDetector 클래스

```python
class ParamDetector:
    def detect_all(self, url: str) -> Dict
    def detect_url_params(self, url: str) -> List[Dict]
    def detect_form_params(self, url: str) -> List[Dict]
    def detect_json_endpoints(self, url: str) -> List[Dict]
    def detect_cookies(self, url: str) -> List[Dict]
    def detect_headers(self, url: str) -> List[Dict]
```

#### 탐지 대상

| 소스 | 탐지 항목 |
|------|----------|
| **URL Query** | `?param=value` 형태 |
| **HTML Form** | `<form>` 태그 내 `<input>`, `<select>` |
| **JSON API** | `/api/`, `/v1/` 등 엔드포인트 |
| **Cookies** | 세션 쿠키, 사용자 정의 쿠키 |
| **Headers** | `X-Forwarded-For` 등 인젝션 가능 헤더 |

#### 사용 예시

```python
from utils import ParamDetector

detector = ParamDetector()
results = detector.detect_all("https://target.com/search?q=test")

# 결과
{
    'url_params': [{'name': 'q', 'value': 'test', 'type': 'query'}],
    'form_params': [...],
    'json_endpoints': [...],
    'cookies': [...],
    'headers': [...]
}
```

#### 활용

- SQLi/XSS 자동 테스트 대상 선정
- 폼 기반 공격 자동화
- API 엔드포인트 발견

## 변경 파일

- `Scanner/utils/param_detector.py` (신규)
- `Scanner/utils/__init__.py` (수정)
