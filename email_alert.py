"""
Email alerting module.
Configure via environment variables (see .env.example).
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import Config

logger = logging.getLogger("sentinel.email")


def send_alert(subject: str, body: str) -> bool:
    """
    Send a plain-text email alert.
    Returns True on success, False on failure.
    Silently skips if ALERT_EMAIL is not configured.
    """
    if not Config.ALERT_EMAIL or not Config.SMTP_USER:
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = Config.SMTP_USER
    msg["To"]      = Config.ALERT_EMAIL

    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;padding:20px">
      <div style="max-width:600px;margin:auto;background:#16213e;border-radius:8px;padding:24px;border:1px solid #0f3460">
        <h2 style="color:#e94560;margin-top:0">🚨 SSH Sentinel Alert</h2>
        <pre style="background:#0f3460;padding:16px;border-radius:6px;white-space:pre-wrap;color:#a8dadc">{body}</pre>
        <p style="color:#888;font-size:12px;margin-bottom:0">SSH Sentinel — Automated Security Alert</p>
      </div>
    </body></html>
    """

    msg.attach(MIMEText(body,      "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(Config.SMTP_ALERT_HOST, Config.SMTP_ALERT_PORT, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(Config.SMTP_USER, Config.SMTP_PASS)
            smtp.sendmail(Config.SMTP_USER, Config.ALERT_EMAIL, msg.as_string())
        logger.info("Alert email sent to %s: %s", Config.ALERT_EMAIL, subject)
        return True
    except Exception as exc:
        logger.warning("Failed to send alert email: %s", exc)
        return False
