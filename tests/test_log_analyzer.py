import unittest
from log_analyzer import analyze_log, generate_report, extract_ip, extract_timestamp
from utils.geoip import geolocate_ip
import os

class TestLogAnalyzer(unittest.TestCase):

    def test_analyze_log_failed_attempts(self):
        patterns = {
            'failed_login': "Failed password",
            'successful_login': "Accepted password"
        }
        failed_attempts, _ = analyze_log('sample_logs/test_auth.log', patterns)
        self.assertGreater(len(failed_attempts), 0, "Failed login attempts should be detected.")

    def test_analyze_log_successful_logins(self):
        patterns = {
            'failed_login': "Failed password",
            'successful_login': "Accepted password"
        }
        _, successful_logins = analyze_log('sample_logs/test_auth.log', patterns)
        self.assertEqual(len(successful_logins), 0, "No successful logins should be detected in the test log.")

    def test_geolocate_ip(self):
        location = geolocate_ip('8.8.8.8')
        self.assertIn('United States', location, "Geolocation should return the correct country.")

    def test_generate_report_html(self):
        failed_attempts = {'192.168.1.1': 10}
        successful_logins = {'192.168.1.2': []}
        generate_report(failed_attempts, successful_logins, 'test_reports', 'html')
        self.assertTrue(os.path.exists('test_reports/log_analysis_report.html'), "HTML report should be generated.")

    def test_generate_report_csv(self):
        failed_attempts = {'192.168.1.1': 10}
        successful_logins = {'192.168.1.2': []}
        generate_report(failed_attempts, successful_logins, 'test_reports', 'csv')
        self.assertTrue(os.path.exists('test_reports/log_analysis_report.csv'), "CSV report should be generated.")

    def test_extract_ip(self):
        log_entry = "Jul 24 00:00:01 server sshd[12345]: Failed password for invalid user admin from 192.168.1.1 port 22 ssh2"
        ip = extract_ip(log_entry)
        self.assertEqual(ip, "192.168.1.1", "IP extraction should correctly identify the IP address.")

    def test_extract_timestamp(self):
        log_entry = "Jul 24 00:00:01 server sshd[12345]: Failed password for invalid user admin from 192.168.1.1 port 22 ssh2"
        timestamp = extract_timestamp(log_entry)
        self.assertIsNotNone(timestamp, "Timestamp extraction should return a valid datetime object.")

if __name__ == '__main__':
    unittest.main()
