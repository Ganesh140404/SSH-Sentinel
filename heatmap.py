import folium
from folium.plugins import HeatMap
import os

from honeypot_logger import get_geo_points


def generate_heatmap_from_db(output_file="static/attack_heatmap.html"):
    """Generate heatmap from honeypot SQLite events (primary method)."""
    points = get_geo_points()

    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    heat_data = []

    for p in points:
        lat, lon = p.get("lat"), p.get("lon")
        if lat is None or lon is None:
            continue
        count = p.get("count", 1)
        heat_data.append([lat, lon, count])

        tooltip = (f"<b>IP:</b> {p['ip']}<br>"
                   f"<b>Location:</b> {p.get('country','?')}, {p.get('city','?')}<br>"
                   f"<b>Events:</b> {count}")
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(tooltip, max_width=280),
            icon=folium.Icon(color="red", icon="info-sign"),
        ).add_to(m)

    if heat_data:
        HeatMap(heat_data, radius=15, blur=20, max_zoom=5).add_to(m)

    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else "static", exist_ok=True)
    m.save(output_file)
    print(f"Heatmap saved to {os.path.abspath(output_file)}")


def generate_heatmap(enriched_data, output_file="static/attack_heatmap.html"):
    """Legacy: generate heatmap from enriched geoip dict (journalctl analysis)."""
    heat_data = []
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")

    for ip, info in enriched_data.items():
        lat   = info.get("lat")
        lon   = info.get("lon")
        count = len(info.get("records", []))
        location = info.get("location", "Unknown")

        if lat is not None and lon is not None:
            heat_data.append([lat, lon, count])
            usernames = list(set(u for _, u, *_ in info.get("records", [])))
            tooltip = (f"<b>IP:</b> {ip}<br><b>Location:</b> {location}<br>"
                       f"<b>Attempts:</b> {count}<br>"
                       f"<b>Usernames:</b> {', '.join(usernames)[:100]}")
            folium.Marker(
                location=[lat, lon],
                popup=folium.Popup(tooltip, max_width=300),
                icon=folium.Icon(color="red", icon="info-sign"),
            ).add_to(m)

    if heat_data:
        HeatMap(heat_data, radius=15, blur=20, max_zoom=5).add_to(m)

    m.save(output_file)
    print(f"Heatmap saved to {os.path.abspath(output_file)}")
