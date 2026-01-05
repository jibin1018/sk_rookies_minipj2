"""
웹 크롤러 모듈

사이트의 모든 링크와 폼을 수집하여 공격 지점을 식별합니다.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class WebCrawler:
    def __init__(self, base_url, cookies=None, headers=None):
        self.base_url = base_url
        self.visited_urls = set()
        self.api_endpoints = set()
        self.session = requests.Session()
        
        # Default headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        })

        # Add Authentication Headers
        if headers:
            self.session.headers.update(headers)
        
        # Add Cookies
        if cookies:
            self.session.cookies.update(cookies)

    def crawl(self, max_pages=50):
        """
        BFS 방식으로 사이트를 크롤링하며 URL과 API 엔드포인트를 수집합니다.
        
        Args:
            max_pages (int): 최대 크롤링 페이지 수 (무한 루프 방지)
        """
        queue = [self.base_url]
        self.visited_urls.add(self.base_url)
        
        count = 0
        while queue and count < max_pages:
            current_url = queue.pop(0)
            count += 1
            
            try:
                response = self.session.get(current_url, timeout=3)
                if response.status_code != 200:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 1. 링크 수집 (<a> 태그)
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    
                    # 같은 도메인만 방문
                    if self._is_same_domain(full_url) and full_url not in self.visited_urls:
                        self.visited_urls.add(full_url)
                        # 정적 리소스(이미지 등)는 큐에 넣지 않음 (단순화)
                        if not self._is_static_resource(full_url):
                            queue.append(full_url)
                            
                # 2. 폼 수집 (API 엔드포인트 식별)
                for form in soup.find_all('form'):
                    action = form.get('action')
                    if action:
                        full_action = urljoin(current_url, action)
                        self.api_endpoints.add(full_action)
                        
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"[Crawler] Error crawling {current_url}: {e}")
                
    def _is_same_domain(self, url):
        """같은 도메인인지 확인 (서브도메인 포함 여부는 프로젝트 정책에 따름)"""
        base_netloc = urlparse(self.base_url).netloc
        target_netloc = urlparse(url).netloc
        return base_netloc == target_netloc

    def _is_static_resource(self, url):
        """정적 리소스 확장자 확인"""
        static_exts = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf']
        return any(url.lower().endswith(ext) for ext in static_exts)

    def get_visited_urls(self):
        return list(self.visited_urls)

    def get_api_endpoints(self):
        return list(self.api_endpoints)
