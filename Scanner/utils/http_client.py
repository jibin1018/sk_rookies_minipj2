"""
안전한 HTTP 클라이언트

모든 스캔 스크립트에서 사용하는 표준화된 HTTP 요청 래퍼입니다.
- 타임아웃 관리
- 응답 크기 제한
- 자동 재시도
- Rate limiting
- 표준화된 에러 처리
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import warnings
from typing import Optional, Dict, Any
from urllib.parse import urlparse


# SSL 경고 숨김 (옵션)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class SafeHttpClient:
    """안전한 HTTP 클라이언트"""
    
    DEFAULT_TIMEOUT = 10  # 초
    DEFAULT_MAX_SIZE = 1024 * 1024  # 1MB
    DEFAULT_RETRY_COUNT = 2
    DEFAULT_DELAY = 0.1  # 요청 간 딜레이 (초)
    
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_response_size: int = DEFAULT_MAX_SIZE,
        retry_count: int = DEFAULT_RETRY_COUNT,
        delay: float = DEFAULT_DELAY,
        verify_ssl: bool = False,
        user_agent: str = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    ):
        """
        Args:
            timeout: 요청 타임아웃 (초)
            max_response_size: 최대 응답 크기 (bytes)
            retry_count: 자동 재시도 횟수
            delay: 요청 간 딜레이 (초)
            verify_ssl: SSL 인증서 검증 여부
            user_agent: User-Agent 헤더
        """
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.retry_count = retry_count
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self._last_request_time = 0
        
        # 세션 설정
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """재시도 로직이 포함된 세션 생성"""
        session = requests.Session()
        
        # 재시도 전략
        retry_strategy = Retry(
            total=self.retry_count,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 기본 헤더
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def _rate_limit(self):
        """Rate limiting 적용"""
        if self.delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self._last_request_time = time.time()
    
    def _check_response_size(self, response: requests.Response) -> bool:
        """응답 크기 확인"""
        content_length = response.headers.get('Content-Length')
        if content_length:
            if int(content_length) > self.max_response_size:
                return False
        return True
    
    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        안전한 GET 요청
        
        Args:
            url: 요청 URL
            params: 쿼리 파라미터
            headers: 추가 헤더
            **kwargs: 추가 requests 옵션
            
        Returns:
            Response 객체
            
        Raises:
            RequestException: 요청 실패 시
        """
        self._rate_limit()
        
        response = self.session.get(
            url,
            params=params,
            headers=headers,
            timeout=kwargs.pop('timeout', self.timeout),
            verify=kwargs.pop('verify', self.verify_ssl),
            allow_redirects=kwargs.pop('allow_redirects', True),
            **kwargs
        )
        
        if not self._check_response_size(response):
            response._content = b'[Response too large]'
        
        return response
    
    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        안전한 POST 요청
        
        Args:
            url: 요청 URL
            data: Form 데이터
            json: JSON 데이터
            headers: 추가 헤더
            **kwargs: 추가 requests 옵션
            
        Returns:
            Response 객체
        """
        self._rate_limit()
        
        response = self.session.post(
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=kwargs.pop('timeout', self.timeout),
            verify=kwargs.pop('verify', self.verify_ssl),
            **kwargs
        )
        
        if not self._check_response_size(response):
            response._content = b'[Response too large]'
        
        return response
    
    def head(
        self,
        url: str,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """안전한 HEAD 요청"""
        self._rate_limit()
        
        return self.session.head(
            url,
            headers=headers,
            timeout=kwargs.pop('timeout', self.timeout),
            verify=kwargs.pop('verify', self.verify_ssl),
            allow_redirects=kwargs.pop('allow_redirects', True),
            **kwargs
        )
    
    def options(
        self,
        url: str,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """안전한 OPTIONS 요청"""
        self._rate_limit()
        
        return self.session.options(
            url,
            headers=headers,
            timeout=kwargs.pop('timeout', self.timeout),
            verify=kwargs.pop('verify', self.verify_ssl),
            **kwargs
        )
    
    def close(self):
        """세션 종료"""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# 전역 싱글톤 클라이언트
_default_client: Optional[SafeHttpClient] = None


def get_client() -> SafeHttpClient:
    """전역 HTTP 클라이언트 반환"""
    global _default_client
    if _default_client is None:
        _default_client = SafeHttpClient()
    return _default_client


def safe_get(url: str, **kwargs) -> requests.Response:
    """단순화된 GET 요청"""
    return get_client().get(url, **kwargs)


def safe_post(url: str, **kwargs) -> requests.Response:
    """단순화된 POST 요청"""
    return get_client().post(url, **kwargs)


def safe_head(url: str, **kwargs) -> requests.Response:
    """단순화된 HEAD 요청"""
    return get_client().head(url, **kwargs)
