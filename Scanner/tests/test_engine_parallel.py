import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import time

# Scanner directory path addition
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner_engine import VulnerabilityScanner

class TestParallelEngine(unittest.TestCase):
    def setUp(self):
        # Mocking modules to avoid actual network/file IO
        self.mock_crawler = MagicMock()
        self.mock_crawler.get_visited_urls.return_value = ["http://test.com/page1", "http://test.com/page2"]
        self.mock_crawler.get_api_endpoints.return_value = ["http://test.com/api/login"]

    @patch('web_crawler.WebCrawler')
    @patch('importlib.import_module')
    def test_parallel_execution(self, mock_import, mock_crawler_class):
        # Setup Mock Crawler
        mock_crawler_class.return_value = self.mock_crawler
        
        # Setup Mock Scan Module (simulating delay)
        mock_module = MagicMock()
        def slow_scan(url):
            time.sleep(0.1)  # Simulate 0.1s delay
            return {'status': 'SAFE', 'name': 'MockTest'}
        
        mock_module.scan = slow_scan
        mock_import.return_value = mock_module

        # Init Scanner
        scanner = VulnerabilityScanner("http://test.com")
        
        # Override WEB_TESTS to run 10 tests
        scanner.WEB_TESTS = [('test_module', f'Test-{i}', 'LOW') for i in range(10)]
        
        # Measure time
        start_time = time.time()
        results = scanner.scan_all()
        duration = time.time() - start_time
        
        # Verification
        # If sequential: 10 * 0.1s = 1.0s+
        # If parallel (5 workers): ~0.2s+
        # We expect it to be faster than sequential
        print(f"Test Duration: {duration:.2f}s")
        
        self.assertEqual(len(results), 10)
        self.assertLess(duration, 0.6, "Parallel execution failed: took too long")

if __name__ == '__main__':
    unittest.main()
