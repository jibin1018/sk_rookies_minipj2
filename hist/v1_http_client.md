# Version 1: SafeHttpClient 구현

## 날짜
2026-01-03

## 작업 내용

### utils/http_client.py

안전한 HTTP 요청을 위한 래퍼 클래스 구현

#### 주요 기능

| 기능 | 설명 |
|------|------|
| **타임아웃** | 기본 10초, 커스텀 설정 가능 |
| **재시도** | 실패 시 자동 재시도 (기본 2회) |
| **Rate Limiting** | 요청 간 딜레이 (기본 0.1초) |
| **응답 크기 제한** | 최대 1MB (메모리 보호) |
| **SSL 옵션** | 검증 비활성화 가능 (테스트용) |

#### 코드 구조

```python
class SafeHttpClient:
    def __init__(self, timeout=10, max_size=1MB, retry_count=2):
        self.session = self._create_session()
    
    def get(self, url, **kwargs) -> Response
    def post(self, url, **kwargs) -> Response
    def head(self, url, **kwargs) -> Response
    def request(self, method, url, **kwargs) -> Response
```

#### 사용 예시

```python
from utils import SafeHttpClient

client = SafeHttpClient(timeout=5, verify_ssl=False)
response = client.get("https://target.com/api")
```

## 변경 파일

- `Scanner/utils/http_client.py` (신규)
- `Scanner/utils/__init__.py` (수정)
