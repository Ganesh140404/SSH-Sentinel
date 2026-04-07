"""
SSH Sentinel – main entry point.

Usage
-----
  python3 main.py            # start honeypot (Ctrl+C to stop)
  python3 main.py analyze    # run log analysis + charts
  python3 main.py status     # show service status (requires honeypot running)
"""
import sys
import os
import signal
import time
import logging
from dotenv import load_dotenv

# ── Load .env if present ──────────────────────────────────────────────────────
load_dotenv()

from config import Config

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("sentinel")

# ── Ensure static/ directory exists ──────────────────────────────────────────
os.makedirs("static", exist_ok=True)


def run_honeypot():
    from honeypot_core import HoneypotManager

    manager = HoneypotManager()

    def _shutdown(signum, frame):
        print("\n\n🛑  Shutdown signal received. Stopping services...")
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("=" * 60)
    print("  SSH Sentinel — Honeypot Engine")
    print("=" * 60)
    manager.start()

    for svc in manager.status():
        status_icon = "🟢" if svc["running"] else "🔴"
        print(f"  {status_icon}  {svc['service'].upper():8s}  →  port {svc['port']}")

    print("=" * 60)
    print("  Dashboard : python3 app.py")
    print("  Stop      : Ctrl+C")
    print("=" * 60)

    # Keep main thread alive
    while True:
        time.sleep(1)


def run_analysis(minutes=None):
    """Run the legacy log-analysis pipeline (journalctl SSH logs)."""
    if minutes is None:
        minutes = 1440  # 24 h default

    from fetch_logs import fetch_logs
    from parse_logs import parse_logs
    from display_results import display_results
    from export_csv import export_to_csv
    from geoip_lookup import lookup_ip_geolocation
    from accepted_logins import parse_accepted_logins
    from heatmap import generate_heatmap
    from plot_chart import generate_bar_chart

    print(f"\n📥  Running analysis for last {minutes} minute(s)...")

    if not fetch_logs(minutes):
        print("❌  Could not fetch system SSH logs.")
        return

    attempts = parse_logs()
    enriched = lookup_ip_geolocation(attempts)
    display_results(enriched)
    export_to_csv(enriched)
    generate_bar_chart(attempts)
    generate_heatmap(enriched)

    accepted = parse_accepted_logins()
    if accepted:
        print("\n🟢  Accepted SSH Logins:")
        for ip, records in accepted.items():
            print(f"  [{ip}] — {len(records)} login(s)")
            for timestamp, user, method, port in records:
                print(f"     └─ {timestamp} → user: {user} (method: {method}, port: {port})")
    else:
        print("🔴  No accepted SSH logins found.")

    print("\n✅  Analysis completed.")


def show_status():
    from honeypot_logger import get_stats, init_db
    init_db()
    stats = get_stats()
    print("\n📊  SSH Sentinel — Live Stats")
    print(f"  Total events   : {stats['total']}")
    print(f"  Unique IPs     : {stats['unique_ips']}")
    print(f"  Banned IPs     : {stats['banned_count']}")
    print(f"  Last-hour hits : {stats['recent_count']}")
    print("\n  By Service:")
    for entry in stats["by_service"]:
        print(f"    {entry['service']:10s} {entry['count']:>6}")
    print("\n  Top Attackers:")
    for entry in stats["top_ips"][:5]:
        print(f"    {entry['ip']:18s} {entry['country']:20s} {entry['count']:>5} events")


if __name__ == "__main__":
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "start"

    if cmd == "analyze":
        minutes_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 1440
        run_analysis(minutes_arg)
    elif cmd == "status":
        show_status()
    else:
        run_honeypot()
