import re
import yaml
import argparse
import pandas as pd
import logging
import os
from datetime import datetime
from collections import defaultdict
from utils.geoip import geolocate_ip
from utils.email_notifier import send_email

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_path):
    """Load configuration from a YAML file."""
    if not os.path.exists(config_path):
        logging.error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Configuration file {config_path} not found.")
    
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            logging.info(f"Configuration loaded successfully from {config_path}")
            return config
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML configuration: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error loading configuration: {e}")
        raise

def analyze_log(file_path, patterns):
    """Analyze the log file for failed and successful login attempts."""
    failed_attempts = defaultdict(int)
    successful_logins = defaultdict(list)

    if not os.path.exists(file_path):
        logging.error(f"Log file not found: {file_path}")
        return failed_attempts, successful_logins

    try:
        with open(file_path, 'r') as file:
            for log in file:
                ip = extract_ip(log)
                if not ip:
                    continue

                if re.search(patterns['failed_login'], log):
                    failed_attempts[ip] += 1
                elif re.search(patterns['successful_login'], log):
                    timestamp = extract_timestamp(log)
                    if timestamp:
                        successful_logins[ip].append(timestamp)
    except Exception as e:
        logging.error(f"Error processing log file: {e}")

    return failed_attempts, successful_logins

def extract_ip(log_entry):
    """Extract the IP address from a log entry."""
    match = re.search(r'[0-9]+(?:\.[0-9]+){3}', log_entry)
    return match.group() if match else None

def extract_timestamp(log_entry):
    """Extract the timestamp from a log entry."""
    try:
        timestamp_str = log_entry.split()[0]  # Modify as per actual log format
        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    except (ValueError, IndexError):
        logging.warning(f"Failed to parse timestamp in log entry: {log_entry}")
        return None

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
    
    if not os.path.exists(report_path):
        os.makedirs(report_path)

    try:
        if report_format == 'html':
            df.to_html(f'{report_path}/log_analysis_report.html', index=False)
        elif report_format == 'csv':
            df.to_csv(f'{report_path}/log_analysis_report.csv', index=False)
        else:
            logging.error(f"Unsupported report format: {report_format}")
            return
        logging.info(f"Report generated successfully at {report_path}")
    except Exception as e:
        logging.error(f"Failed to generate report: {e}")

def analyze_and_alert(config):
    """Analyze logs and send alerts based on the findings."""
    failed_attempts, successful_logins = analyze_log(config['log_file_path'], config['patterns'])

    try:
        for ip, attempts in failed_attempts.items():
            if attempts > config['alert_thresholds'].get('failed_attempts', 5):
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
    except KeyError as ke:
        logging.error(f"Missing configuration key: {ke}")
    except Exception as e:
        logging.error(f"Error during analysis or alerting: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze server logs for security threats.')
    parser.add_argument('--config', help='Path to the configuration file', default='config.yaml')
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        analyze_and_alert(config)
    except Exception as e:
        logging.error(f"Failed to complete analysis: {e}")
