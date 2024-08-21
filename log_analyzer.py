import re
import yaml
import argparse
import pandas as pd
import logging
from datetime import datetime
from collections import defaultdict
from utils.geoip import geolocate_ip
from utils.email_notifier import send_email

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_path):
    """Load configuration from a YAML file."""
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        raise

def analyze_log(file_path, patterns):
    """Analyze the log file for failed and successful login attempts."""
    failed_attempts = defaultdict(int)
    successful_logins = defaultdict(list)

    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        logging.error(f"Log file not found: {file_path}")
        return failed_attempts, successful_logins
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return failed_attempts, successful_logins

    for log in logs:
        if re.search(patterns['failed_login'], log):
            ip = re.search(r'[0-9]+(?:\.[0-9]+){3}', log)
            if ip:
                failed_attempts[ip.group()] += 1
        elif re.search(patterns['successful_login'], log):
            ip = re.search(r'[0-9]+(?:\.[0-9]+){3}', log)
            if ip:
                timestamp = datetime.strptime(log.split()[0], "%b %d %H:%M:%S")
                successful_logins[ip.group()].append(timestamp)

    return failed_attempts, successful_logins

def generate_report(failed_attempts, successful_logins, report_path, report_format):
    """Generate a report in the specified format."""
    report = []
    for ip, attempts in failed_attempts.items():
        location = geolocate_ip(ip)
        report.append({
            'IP': ip,
            'Attempts': attempts,
            'Location': location,
            'Type': 'Failed Login'
        })
    
    for ip, timestamps in successful_logins.items():
        location = geolocate_ip(ip)
        report.append({
            'IP': ip,
            'Attempts': len(timestamps),
            'Location': location,
            'Type': 'Successful Login'
        })
    
    df = pd.DataFrame(report)
    if report_format == 'html':
        df.to_html(f'{report_path}/log_analysis_report.html')
    elif report_format == 'csv':
        df.to_csv(f'{report_path}/log_analysis_report.csv', index=False)
    else:
        logging.error(f"Unsupported report format: {report_format}")
        return

    logging.info("Report generated successfully.")

def analyze_and_alert(config):
    """Analyze logs and send alerts based on the findings."""
    failed_attempts, successful_logins = analyze_log(config['log_file_path'], config['patterns'])

    for ip, attempts in failed_attempts.items():
        if attempts > config['alert_thresholds']['failed_attempts']:
            send_email(
                config,
                subject=f"Alert: Multiple failed login attempts from {ip}",
                message=f"There have been {attempts} failed login attempts from IP: {ip}."
            )
    
    for ip, timestamps in successful_logins.items():
        if len(timestamps) > 1:
            send_email(
                config,
                subject=f"Alert: Multiple successful logins from {ip}",
                message=f"There have been multiple successful logins from IP: {ip} at {timestamps}."
            )

    generate_report(
        failed_attempts,
        successful_logins,
        config['report_path'],
        config.get('report_format', 'html')
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze server logs for security threats.')
    parser.add_argument('--config', help='Path to the configuration file', default='config.yaml')
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        analyze_and_alert(config)
    except Exception as e:
        logging.error(f"Failed to complete analysis: {e}")
