import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import threading
import time

# Add parent directory to path to import Scanner modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_engine import VulnerabilityScanner
from app import app, scan_status

class TestScannerFlow(unittest.TestCase):
    def setUp(self):
        self.scan_id = "test_scan_id"
        self.target_url = "http://example.com"
        self.scan_status = {}

    @patch('scanner_engine.VulnerabilityScanner._run_single_test')
    @patch('web_crawler.WebCrawler')
    @patch('scanner_engine.InfraDetector')
    def test_web_scan_execution(self, MockInfra, MockCrawler, MockRun):
        """Test that the scanner logic actually runs and updates status."""
        
        # Setup Mocks
        mock_crawler_instance = MockCrawler.return_value
        mock_crawler_instance.get_visited_urls.return_value = ["http://example.com"]
        mock_crawler_instance.get_api_endpoints.return_value = []

        mock_infra_instance = MockInfra.return_value
        mock_infra_instance.detect.return_value = {"web_server": "Nginx"}
        
        MockRun.return_value = {
            'name': 'SQL Injection',
            'status': 'SAFE',
            'severity': 'HIGH'
        }

        # Initialize Scanner
        scanner = VulnerabilityScanner(
            target_url=self.target_url,
            scan_status=self.scan_status,
            scan_id=self.scan_id,
            use_infra_detection=True
        )

        # Mock WEB_TESTS to run only one test to be fast
        original_tests = scanner.WEB_TESTS
        scanner.WEB_TESTS = [('sqli', 'SQL Injection', 'CRITICAL')]

        # Run Scan
        self.scan_status[self.scan_id] = {'progress': 0}
        results = scanner.scan_all()
        
        # Verify Interactions
        MockCrawler.assert_called() # Should initialize crawler
        mock_crawler_instance.crawl.assert_called() # Should crawl
        MockInfra.assert_called() # Should detect infra
        
        # Verify Results
        self.assertTrue(len(results) > 0, "Scan should return results")
        self.assertEqual(results[0]['status'], 'SAFE')
        
        # Verify Progress Update (checking the dictionary)
        # Note: In scan_all, it updates self.scan_status[self.scan_id]['progress']
        self.assertIn(self.scan_id, self.scan_status)
        self.assertGreater(self.scan_status[self.scan_id]['progress'], 0)

        # Restore
        scanner.WEB_TESTS = original_tests

    def test_api_start_scan(self):
        """Test the Flask API endpoint and background thread spawning."""
        with patch('app.run_web_scan_background') as mock_bg:
            client = app.test_client()
            response = client.post('/api/scan/start', json={
                'target_url': 'http://test.com',
                'scan_types': ['sqli']
            })
            
            self.assertEqual(response.status_code, 200)
            json_data = response.get_json()
            self.assertTrue(json_data['success'])
            self.assertIn('scan_id', json_data)
            
            # Verify background thread was called
            mock_bg.assert_called_once()

if __name__ == '__main__':
    unittest.main()
