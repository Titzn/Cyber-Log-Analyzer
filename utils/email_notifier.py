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
        with smtplib.SMTP(config['alert']['smtp_server'], config['alert']['smtp_port'], timeout=10) as server:
            server.starttls()
            server.login(config['alert']['from_email'], config['alert']['password'])
            server.send_message(msg)
            logging.info(f"Alert sent: {subject}")
    except smtplib.SMTPAuthenticationError as e:
        logging.error(f"SMTP authentication failed: {e}")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error occurred: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during email sending: {e}")
