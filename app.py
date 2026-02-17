import socket
import requests
from flask import Flask, render_template, request, jsonify
from database import init_db, save_result, get_history
from threat_logic import classify_threat

app = Flask(__name__)

# ── Initialize DB on startup (works with both `python app.py` AND gunicorn) ──
init_db()

GEOLOCATION_API = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"


def resolve_domain(domain: str):
    """Resolve domain to IP address with error handling."""
    try:
        ip = socket.gethostbyname(domain.strip())
        return ip, None
    except socket.gaierror as e:
        return None, f"Could not resolve domain: {str(e)}"


def get_geo_info(ip: str):
    """Fetch geolocation data for an IP address."""
    try:
        resp = requests.get(GEOLOCATION_API.format(ip=ip), timeout=8)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "fail":
            return None, data.get("message", "Geolocation lookup failed")
        return data, None
    except requests.RequestException as e:
        return None, f"Geolocation API error: {str(e)}"


def sanitize_domain(raw: str) -> str:
    """Strip protocol and path, return bare hostname."""
    domain = raw.strip().lower()
    for prefix in ("https://", "http://", "ftp://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split("?")[0]
    return domain


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    raw_domain = data.get("domain", "").strip()

    if not raw_domain:
        return jsonify({"error": "Domain is required."}), 400

    domain = sanitize_domain(raw_domain)

    if not domain or len(domain) < 3:
        return jsonify({"error": "Invalid domain name."}), 400

    # Resolve IP
    ip, err = resolve_domain(domain)
    if err:
        return jsonify({"error": err}), 422

    # Geolocation
    geo, err = get_geo_info(ip)
    if err:
        return jsonify({"error": err}), 502

    # Threat classification
    threat_level, threat_score, threat_reasons = classify_threat(domain, ip, geo)

    result = {
        "domain": domain,
        "ip": ip,
        "country": geo.get("country", "Unknown"),
        "region": geo.get("regionName", "Unknown"),
        "city": geo.get("city", "Unknown"),
        "lat": geo.get("lat"),
        "lon": geo.get("lon"),
        "isp": geo.get("isp", "Unknown"),
        "org": geo.get("org", "Unknown"),
        "threat_level": threat_level,
        "threat_score": threat_score,
        "threat_reasons": threat_reasons,
    }

    save_result(result)

    return jsonify(result)


@app.route("/history")
def history():
    limit = request.args.get("limit", 50, type=int)
    rows = get_history(limit)
    return jsonify(rows)


@app.route("/history/clear", methods=["DELETE"])
def clear_history():
    from database import clear_all
    clear_all()
    return jsonify({"message": "History cleared."})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
        
