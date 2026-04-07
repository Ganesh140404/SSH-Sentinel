import csv
import os
from honeypot_logger import get_events


def export_honeypot_to_csv(filename="static/report.csv"):
    """Export all honeypot events from SQLite to CSV."""
    events = get_events(limit=100000)
    if not events:
        print("No honeypot events to export.")
        return

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Timestamp", "Source IP", "Source Port", "Dest Port",
                "Service", "Event Type", "Username", "Password", "Payload",
                "Country", "City", "Region", "Lat", "Lon", "Org", "ISP", "Timezone",
            ])
            for e in events:
                writer.writerow([
                    e.get("id"), e.get("timestamp"), e.get("source_ip"),
                    e.get("source_port"), e.get("dest_port"), e.get("service"),
                    e.get("event_type"), e.get("username"), e.get("password"),
                    e.get("payload"), e.get("country"), e.get("city"),
                    e.get("region"), e.get("lat"), e.get("lon"),
                    e.get("org"), e.get("isp"), e.get("timezone"),
                ])
        print(f"Exported {len(events)} events to {filename}")
    except Exception as exc:
        print(f"CSV export failed: {exc}")


def export_to_csv(enriched_attempts, filename="static/report.csv"):
    """Legacy: export enriched geoip dict from journalctl analysis."""
    if not enriched_attempts:
        print("No data to export.")
        return

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    try:
        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "Timestamp", "Username", "IP Address", "IsInvalidUser",
                "Location", "Latitude", "Longitude", "Organization",
                "ISP", "AS", "Timezone",
            ])
            for ip, data in enriched_attempts.items():
                for record in data.get("records", []):
                    if len(record) == 3:
                        timestamp, username, is_invalid = record
                    else:
                        timestamp, username = record
                        is_invalid = "Unknown"
                    ts_str = timestamp.strftime("%d-%m-%Y %H:%M:%S") if hasattr(timestamp, "strftime") else str(timestamp)
                    writer.writerow([
                        ts_str, username, ip, is_invalid,
                        data.get("location"), data.get("lat"), data.get("lon"),
                        data.get("org"), data.get("isp"), data.get("as"), data.get("timezone"),
                    ])
        print(f"Exported legacy report to {filename}")
    except Exception as exc:
        print(f"CSV export failed: {exc}")
