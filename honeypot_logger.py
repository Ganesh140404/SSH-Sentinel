"""
Centralised SQLite logger for all honeypot events.
Thread-safe. Includes geo-lookup with a 24-hour in-DB cache.
"""
import sqlite3
import threading
import logging
from datetime import datetime, timedelta

import requests

from config import Config

_lock = threading.Lock()
logger = logging.getLogger("sentinel.logger")


# ── DB init ───────────────────────────────────────────────────────────────────

def init_db():
    with sqlite3.connect(Config.DB_PATH) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                source_ip   TEXT    NOT NULL,
                source_port INTEGER,
                dest_port   INTEGER,
                service     TEXT    NOT NULL,
                event_type  TEXT    NOT NULL DEFAULT 'connection',
                username    TEXT,
                password    TEXT,
                payload     TEXT,
                country     TEXT,
                city        TEXT,
                region      TEXT,
                lat         REAL,
                lon         REAL,
                org         TEXT,
                isp         TEXT,
                timezone    TEXT,
                session_id  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ip        ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_ts        ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_service   ON events(service);

            CREATE TABLE IF NOT EXISTS banned_ips (
                ip        TEXT PRIMARY KEY,
                reason    TEXT,
                banned_at TEXT
            );

            CREATE TABLE IF NOT EXISTS geo_cache (
                ip         TEXT PRIMARY KEY,
                country    TEXT,
                city       TEXT,
                region     TEXT,
                lat        REAL,
                lon        REAL,
                org        TEXT,
                isp        TEXT,
                timezone   TEXT,
                cached_at  TEXT
            );
        """)
        conn.commit()
    logger.info("Database initialised at %s", Config.DB_PATH)


# ── Geo lookup ────────────────────────────────────────────────────────────────

_PRIVATE_PREFIXES = ("192.168.", "10.", "172.", "127.", "::1", "0:0:0:0")

def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def get_geo(ip: str) -> dict:
    if _is_private(ip):
        return {"country": "Private/Local", "city": None, "region": None,
                "lat": None, "lon": None, "org": None, "isp": None, "timezone": None}

    with sqlite3.connect(Config.DB_PATH) as conn:
        row = conn.execute(
            "SELECT country,city,region,lat,lon,org,isp,timezone,cached_at FROM geo_cache WHERE ip=?",
            (ip,)
        ).fetchone()
        if row:
            cached_at = datetime.fromisoformat(row[8])
            if datetime.utcnow() - cached_at < timedelta(hours=Config.GEO_CACHE_HOURS):
                return {"country": row[0], "city": row[1], "region": row[2],
                        "lat": row[3], "lon": row[4], "org": row[5],
                        "isp": row[6], "timezone": row[7]}

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            d = resp.json()
            geo = {
                "country":  d.get("country", "Unknown"),
                "city":     d.get("city", "Unknown"),
                "region":   d.get("regionName", "Unknown"),
                "lat":      d.get("lat"),
                "lon":      d.get("lon"),
                "org":      d.get("org"),
                "isp":      d.get("isp"),
                "timezone": d.get("timezone"),
            }
            with _lock:
                with sqlite3.connect(Config.DB_PATH) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO geo_cache VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (ip, geo["country"], geo["city"], geo["region"],
                         geo["lat"], geo["lon"], geo["org"], geo["isp"],
                         geo["timezone"], datetime.utcnow().isoformat())
                    )
                    conn.commit()
            return geo
    except Exception:
        pass

    return {"country": "Unknown", "city": None, "region": None,
            "lat": None, "lon": None, "org": None, "isp": None, "timezone": None}


# ── Event logging ─────────────────────────────────────────────────────────────

def log_event(service: str, source_ip: str, source_port: int = None,
              dest_port: int = None, event_type: str = "connection",
              username: str = None, password: str = None,
              payload: str = None, session_id: str = None):
    ts  = datetime.utcnow().isoformat()
    geo = get_geo(source_ip)

    with _lock:
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute(
                """INSERT INTO events
                   (timestamp,source_ip,source_port,dest_port,service,event_type,
                    username,password,payload,country,city,region,lat,lon,org,isp,timezone,session_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, source_ip, source_port, dest_port, service, event_type,
                 username, password, payload,
                 geo["country"], geo["city"], geo["region"],
                 geo["lat"], geo["lon"], geo["org"], geo["isp"], geo["timezone"],
                 session_id)
            )
            conn.commit()

    logger.info("[%s] %s from %s:%s u=%s", service, event_type, source_ip, source_port, username)

    # Auto-ban check
    count = get_ip_count(source_ip)
    if count >= Config.BAN_THRESHOLD and not is_banned(source_ip):
        ban_ip(source_ip, f"Auto-banned: {count} events")
        logger.warning("Auto-banned %s (%d events)", source_ip, count)

    # Email alert check (import lazily to avoid circular import)
    if Config.ALERT_EMAIL and count == Config.ALERT_THRESHOLD:
        try:
            from email_alert import send_alert
            send_alert(
                f"[SSH Sentinel] High activity from {source_ip}",
                f"IP {source_ip} has triggered {count} events.\nService: {service}\nLocation: {geo['country']}"
            )
        except Exception as exc:
            logger.warning("Email alert failed: %s", exc)


# ── Ban management ────────────────────────────────────────────────────────────

def is_banned(ip: str) -> bool:
    with sqlite3.connect(Config.DB_PATH) as conn:
        return conn.execute("SELECT 1 FROM banned_ips WHERE ip=?", (ip,)).fetchone() is not None


def ban_ip(ip: str, reason: str = "manual"):
    with _lock:
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute("INSERT OR REPLACE INTO banned_ips VALUES (?,?,?)",
                         (ip, reason, datetime.utcnow().isoformat()))
            conn.commit()


def unban_ip(ip: str):
    with _lock:
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
            conn.commit()


def get_banned_ips():
    with sqlite3.connect(Config.DB_PATH) as conn:
        return [{"ip": r[0], "reason": r[1], "banned_at": r[2]}
                for r in conn.execute("SELECT ip,reason,banned_at FROM banned_ips").fetchall()]


# ── Query helpers ─────────────────────────────────────────────────────────────

def get_ip_count(ip: str) -> int:
    with sqlite3.connect(Config.DB_PATH) as conn:
        return conn.execute("SELECT COUNT(*) FROM events WHERE source_ip=?", (ip,)).fetchone()[0]


def get_stats() -> dict:
    with sqlite3.connect(Config.DB_PATH) as conn:
        total        = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        unique_ips   = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM events").fetchone()[0]
        by_service   = conn.execute(
            "SELECT service,COUNT(*) FROM events GROUP BY service ORDER BY COUNT(*) DESC"
        ).fetchall()
        top_ips      = conn.execute(
            "SELECT source_ip,country,COUNT(*) as c FROM events "
            "GROUP BY source_ip ORDER BY c DESC LIMIT 10"
        ).fetchall()
        hourly       = conn.execute(
            "SELECT strftime('%Y-%m-%dT%H:00:00',timestamp) as h,COUNT(*) "
            "FROM events WHERE timestamp > datetime('now','-24 hours') "
            "GROUP BY h ORDER BY h"
        ).fetchall()
        top_creds    = conn.execute(
            "SELECT username,password,COUNT(*) as c FROM events "
            "WHERE username IS NOT NULL AND password IS NOT NULL "
            "GROUP BY username,password ORDER BY c DESC LIMIT 20"
        ).fetchall()
        banned_count = conn.execute("SELECT COUNT(*) FROM banned_ips").fetchone()[0]
        recent_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp > datetime('now','-1 hour')"
        ).fetchone()[0]

    return {
        "total":        total,
        "unique_ips":   unique_ips,
        "by_service":   [{"service": r[0], "count": r[1]} for r in by_service],
        "top_ips":      [{"ip": r[0], "country": r[1], "count": r[2]} for r in top_ips],
        "hourly":       [{"hour": r[0], "count": r[1]} for r in hourly],
        "top_creds":    [{"username": r[0], "password": r[1], "count": r[2]} for r in top_creds],
        "banned_count": banned_count,
        "recent_count": recent_count,
    }


def get_events(limit: int = 200, service: str = None, ip: str = None) -> list:
    query  = "SELECT * FROM events"
    params = []
    conds  = []
    if service:
        conds.append("service=?");  params.append(service)
    if ip:
        conds.append("source_ip=?"); params.append(ip)
    if conds:
        query += " WHERE " + " AND ".join(conds)
    query += f" ORDER BY timestamp DESC LIMIT {int(limit)}"

    with sqlite3.connect(Config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def get_geo_points() -> list:
    """Return lat/lon/count rows for map rendering."""
    with sqlite3.connect(Config.DB_PATH) as conn:
        rows = conn.execute(
            "SELECT lat,lon,country,city,source_ip,COUNT(*) as c "
            "FROM events WHERE lat IS NOT NULL AND lon IS NOT NULL "
            "GROUP BY source_ip"
        ).fetchall()
    return [{"lat": r[0], "lon": r[1], "country": r[2],
             "city": r[3], "ip": r[4], "count": r[5]} for r in rows]
