import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Scanner directory path addition
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from web_crawler import WebCrawler

class TestWebCrawler(unittest.TestCase):
    def setUp(self):
        self.crawler = WebCrawler(base_url="http://test.com")

    @patch('requests.Session.get')
    def test_crawl_links(self, mock_get):
        # Mock Response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '''
        <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="http://test.com/page2">Page 2</a>
                <a href="http://external.com">External</a>
            </body>
        </html>
        '''
        mock_get.return_value = mock_response

        # Allow execution
        self.crawler.crawl()

        # Verification
        # /page1, /page2 should be included
        # external.com should be excluded
        visited = self.crawler.get_visited_urls()
        self.assertIn("http://test.com/page1", visited)
        self.assertIn("http://test.com/page2", visited)
        self.assertNotIn("http://external.com", visited)

    @patch('requests.Session.get')
    def test_crawl_forms(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '''
        <html>
            <form action="/api/login" method="POST">
                <input name="username">
            </form>
        </html>
        '''
        mock_get.return_value = mock_response

        self.crawler.crawl()
        
        # Form endpoint detection check
        endpoints = self.crawler.get_api_endpoints()
        self.assertIn("http://test.com/api/login", endpoints)

if __name__ == '__main__':
    unittest.main()
