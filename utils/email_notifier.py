import smtplib
from email.mime.text import MIMEText
import logging

def send_email(config, subject, message):
    """Send an email notification."""
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = config['alert']['from_email']
    msg['To'] = config['alert']['to_email']

    try:
        with smtplib.SMTP(config['alert']['smtp_server'], config['alert']['smtp_port']) as server:
            server.starttls()
            server.login(config['alert']['from_email'], config['alert']['password'])
            server.send_message(msg)
            logging.info(f"Alert sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
