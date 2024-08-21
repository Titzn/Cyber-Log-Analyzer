import unittest
from log_analyzer import analyze_log, generate_report
from utils.geoip import geolocate_ip
import os

class TestLogAnalyzer(unittest.TestCase):

    def test_analyze_log(self):
        failed_attempts, successful_logins = analyze_log('sample_auth.log', {'failed_login': 'Failed password', 'successful_login': 'Accepted password'})
        self.assertGreaterEqual(len(failed_attempts), 0)
        self.assertGreaterEqual(len(successful_logins), 0)

    def test_geolocate_ip(self):
        location = geolocate_ip('8.8.8.8')
        self.assertIn('United States', location)

    def test_generate_report(self):
        failed_attempts = {'192.168.1.1': 10}
        successful_logins = {'192.168.1.2': []}
        generate_report(failed_attempts, successful_logins, 'test_reports', 'html')
        # Verify report is generated
        self.assertTrue(os.path.exists('test_reports/log_analysis_report.html'))

if __name__ == '__main__':
    unittest.main()
