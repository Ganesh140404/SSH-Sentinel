import os
import secrets


class Config:
    # ── Honeypot ports ────────────────────────────────────────────────────────
    SSH_PORT    = int(os.getenv("SSH_PORT",    2222))
    FTP_PORT    = int(os.getenv("FTP_PORT",    2121))
    HTTP_PORT   = int(os.getenv("HTTP_PORT",   8080))
    TELNET_PORT = int(os.getenv("TELNET_PORT", 2323))
    MYSQL_PORT  = int(os.getenv("MYSQL_PORT",  3307))
    REDIS_PORT  = int(os.getenv("REDIS_PORT",  6380))
    SMTP_PORT   = int(os.getenv("SMTP_PORT",   2525))

    # ── Dashboard ─────────────────────────────────────────────────────────────
    DASHBOARD_PORT     = int(os.getenv("DASHBOARD_PORT", 5000))
    DASHBOARD_HOST     = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    SECRET_KEY         = os.getenv("SECRET_KEY", secrets.token_hex(32))
    DASHBOARD_USER     = os.getenv("DASHBOARD_USER", "admin")
    DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "changeme")

    # ── Storage ───────────────────────────────────────────────────────────────
    DB_PATH  = os.getenv("DB_PATH",  "honeypot.db")
    LOG_FILE = os.getenv("LOG_FILE", "sentinel.log")

    # ── SSH host key ──────────────────────────────────────────────────────────
    HOST_KEY_PATH = os.getenv("HOST_KEY_PATH", "honeypot_host_key")

    # ── Rate limiting ─────────────────────────────────────────────────────────
    MAX_CONN_PER_IP = int(os.getenv("MAX_CONN_PER_IP", 30))
    BAN_THRESHOLD   = int(os.getenv("BAN_THRESHOLD",  100))

    # ── Geolocation ───────────────────────────────────────────────────────────
    GEO_CACHE_HOURS = int(os.getenv("GEO_CACHE_HOURS", 24))

    # ── Email alerts ──────────────────────────────────────────────────────────
    ALERT_EMAIL     = os.getenv("ALERT_EMAIL",     "")
    SMTP_ALERT_HOST = os.getenv("SMTP_ALERT_HOST", "smtp.gmail.com")
    SMTP_ALERT_PORT = int(os.getenv("SMTP_ALERT_PORT", 587))
    SMTP_USER       = os.getenv("SMTP_USER", "")
    SMTP_PASS       = os.getenv("SMTP_PASS", "")
    ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", 10))

    # ── Fake server banners ───────────────────────────────────────────────────
    SSH_BANNER    = os.getenv("SSH_BANNER",    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9")
    FTP_BANNER    = os.getenv("FTP_BANNER",    "220 (vsFTPd 3.0.3)")
    MYSQL_VERSION = os.getenv("MYSQL_VERSION", "5.7.42-log")
    HTTP_SERVER   = os.getenv("HTTP_SERVER",   "Apache/2.4.52 (Ubuntu)")
