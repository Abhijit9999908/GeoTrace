import socket
import requests
from flask import Flask, render_template, request, jsonify
from database import init_db, save_result, get_history, clear_all
from threat_logic import classify_threat

app = Flask(__name__)

# Must run at module level so Gunicorn initialises the DB on startup
try:
    init_db()
except Exception as e:
    print(f"[GeoTrace] WARNING: init_db failed: {e}")

GEO_API = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"
)


def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain.strip()), None
    except socket.gaierror as e:
        return None, f"Could not resolve domain: {e}"


def get_geo(ip):
    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=8)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "fail":
            return None, data.get("message", "Geolocation failed")
        return data, None
    except Exception as e:
        return None, f"Geo API error: {e}"


def clean_domain(raw):
    d = raw.strip().lower()
    for p in ("https://", "http://", "ftp://"):
        if d.startswith(p):
            d = d[len(p):]
    return d.split("/")[0].split("?")[0].split("#")[0]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    raw = body.get("domain", "").strip()
    if not raw:
        return jsonify({"error": "Domain is required."}), 400

    domain = clean_domain(raw)
    if len(domain) < 3:
        return jsonify({"error": "Invalid domain name."}), 400

    ip, err = resolve_ip(domain)
    if err:
        return jsonify({"error": err}), 422

    geo, err = get_geo(ip)
    if err:
        return jsonify({"error": err}), 502

    # classify_threat always returns (level, score, reasons)
    threat_level, threat_score, threat_reasons = classify_threat(domain, ip, geo)

    result = {
        "domain":        domain,
        "ip":            ip,
        "country":       geo.get("country", "Unknown"),
        "region":        geo.get("regionName", "Unknown"),
        "city":          geo.get("city", "Unknown"),
        "lat":           geo.get("lat"),
        "lon":           geo.get("lon"),
        "isp":           geo.get("isp", "Unknown"),
        "org":           geo.get("org", "Unknown"),
        "threat_level":  threat_level,
        "threat_score":  threat_score,
        "threat_reasons": threat_reasons,
    }

    try:
        save_result(result)
    except Exception as e:
        print(f"[GeoTrace] save_result error: {e}")

    return jsonify(result)


@app.route("/history")
def history():
    limit = request.args.get("limit", 50, type=int)
    try:
        rows = get_history(limit)
    except Exception:
        rows = []
    return jsonify(rows)


@app.route("/history/clear", methods=["DELETE"])
def clear_history():
    try:
        clear_all()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"message": "History cleared."})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
        
