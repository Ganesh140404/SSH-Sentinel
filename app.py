"""
SSH Sentinel – Flask dashboard.
Run independently from main.py (honeypot).
"""
import os
import csv
import io
import json
import subprocess
import functools
import logging
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, send_file, abort)

from config import Config
from honeypot_logger import (init_db, get_stats, get_events, get_geo_points,
                              ban_ip, unban_ip, get_banned_ips)

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.dashboard")

os.makedirs("static", exist_ok=True)
init_db()


# ── Auth decorator ────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd  = request.form.get("password", "")
        if user == Config.DASHBOARD_USER and pwd == Config.DASHBOARD_PASSWORD:
            session["authenticated"] = True
            session.permanent = False
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."
        logger.warning("Failed login attempt from %s", request.remote_addr)
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Main dashboard ────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    return render_template("index.html")


# ── API: stats ────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())


# ── API: events ───────────────────────────────────────────────────────────────
@app.route("/api/events")
@login_required
def api_events():
    service = request.args.get("service")
    ip      = request.args.get("ip")
    limit   = min(int(request.args.get("limit", 200)), 1000)
    events  = get_events(limit=limit, service=service, ip=ip)
    return jsonify(events)


# ── API: geo points for map ───────────────────────────────────────────────────
@app.route("/api/geo")
@login_required
def api_geo():
    return jsonify(get_geo_points())


# ── API: service status ───────────────────────────────────────────────────────
@app.route("/api/services")
@login_required
def api_services():
    try:
        from honeypot_core import HoneypotManager
        # If honeypot is running in the same process, this would reflect state.
        # For separate processes, we check the DB for recent activity per service.
        from honeypot_logger import get_stats
        stats = get_stats()
        service_counts = {s["service"]: s["count"] for s in stats.get("by_service", [])}
        services = [
            {"service": "ssh",    "port": Config.SSH_PORT,    "count": service_counts.get("ssh", 0)},
            {"service": "ftp",    "port": Config.FTP_PORT,    "count": service_counts.get("ftp", 0)},
            {"service": "http",   "port": Config.HTTP_PORT,   "count": service_counts.get("http", 0)},
            {"service": "telnet", "port": Config.TELNET_PORT, "count": service_counts.get("telnet", 0)},
            {"service": "mysql",  "port": Config.MYSQL_PORT,  "count": service_counts.get("mysql", 0)},
            {"service": "redis",  "port": Config.REDIS_PORT,  "count": service_counts.get("redis", 0)},
            {"service": "smtp",   "port": Config.SMTP_PORT,   "count": service_counts.get("smtp", 0)},
        ]
        return jsonify(services)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── API: ban / unban ──────────────────────────────────────────────────────────
@app.route("/api/ban", methods=["POST"])
@login_required
def api_ban():
    data   = request.get_json(force=True)
    ip_val = data.get("ip", "").strip()
    if not ip_val:
        return jsonify({"error": "ip required"}), 400
    ban_ip(ip_val, "manual-dashboard")
    logger.info("Dashboard user banned %s", ip_val)
    return jsonify({"status": "banned", "ip": ip_val})


@app.route("/api/unban", methods=["POST"])
@login_required
def api_unban():
    data   = request.get_json(force=True)
    ip_val = data.get("ip", "").strip()
    if not ip_val:
        return jsonify({"error": "ip required"}), 400
    unban_ip(ip_val)
    return jsonify({"status": "unbanned", "ip": ip_val})


@app.route("/api/banned")
@login_required
def api_banned():
    return jsonify(get_banned_ips())


# ── Heatmap (Folium) generation ───────────────────────────────────────────────
@app.route("/api/heatmap/generate", methods=["POST"])
@login_required
def api_generate_heatmap():
    try:
        from heatmap import generate_heatmap_from_db
        generate_heatmap_from_db()
        return jsonify({"status": "ok", "file": "attack_heatmap.html"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/heatmap")
@login_required
def view_heatmap():
    if not os.path.exists("static/attack_heatmap.html"):
        try:
            from heatmap import generate_heatmap_from_db
            generate_heatmap_from_db()
        except Exception:
            abort(503)
    return redirect(url_for("static", filename="attack_heatmap.html"))


# ── Legacy analysis (journalctl SSH logs) ────────────────────────────────────
@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    minutes = request.form.get("minutes", "1440")
    try:
        subprocess.run(["python3", "main.py", "analyze", str(minutes)],
                       check=True, timeout=120)
        message = f"Analysis completed for last {minutes} minutes."
    except subprocess.CalledProcessError as exc:
        message = f"Analysis error: {exc}"
    except subprocess.TimeoutExpired:
        message = "Analysis timed out."

    chart      = "chart.png"              if os.path.exists("static/chart.png") else None
    heatmap    = "attack_heatmap.html"    if os.path.exists("static/attack_heatmap.html") else None
    csv_report = "report.csv"             if os.path.exists("static/report.csv") else None

    return render_template("index.html",
                           analyze_message=message,
                           chart=chart, heatmap=heatmap, csv_report=csv_report)


# ── CSV export (honeypot events) ──────────────────────────────────────────────
@app.route("/export/csv")
@login_required
def export_csv():
    events = get_events(limit=10000)
    si  = io.StringIO()
    cw  = csv.writer(si)
    cw.writerow(["id", "timestamp", "source_ip", "source_port", "dest_port",
                 "service", "event_type", "username", "password", "payload",
                 "country", "city", "region", "lat", "lon", "org", "isp", "timezone"])
    for e in events:
        cw.writerow([
            e.get("id"), e.get("timestamp"), e.get("source_ip"),
            e.get("source_port"), e.get("dest_port"), e.get("service"),
            e.get("event_type"), e.get("username"), e.get("password"),
            e.get("payload"), e.get("country"), e.get("city"),
            e.get("region"), e.get("lat"), e.get("lon"),
            e.get("org"), e.get("isp"), e.get("timezone"),
        ])
    output = io.BytesIO(si.getvalue().encode())
    fname  = f"honeypot_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(output, mimetype="text/csv",
                     as_attachment=True, download_name=fname)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=Config.DASHBOARD_HOST, port=Config.DASHBOARD_PORT, debug=debug)
