"""
app.py — Main Flask application for GeoTrace (Pro Version)
"""
import os
import socket
import requests
from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Custom Modules
from database import init_db, save_analysis, get_history
from threat_logic import classify_domain

app = Flask(__name__)

# ── 🛡️ RATE LIMITING CONFIGURATION ──
# This sets up the "Smart Limiting" to prevent abuse.
# Default: 200 requests per day, 50 per hour.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize DB
init_db()

# ── Routes ──

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per minute")  # ⚡ LIMIT: Allow only 10 scans per minute per user
def analyze():
    data = request.get_json()
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Please enter a domain name."}), 400

    # 1. Input Sanitization
    for prefix in ("http://", "https://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]

    # 2. DNS Resolution (Reliability Fix)
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return jsonify({"error": f"DNS Error: Could not resolve '{domain}'."}), 400

    # 3. Geolocation (with Timeout for Reliability)
    try:
        # Using HTTP for ip-api (free tier)
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        geo_data = response.json()

        if geo_data.get("status") == "fail":
            return jsonify({"error": f"GeoAPI Error: {geo_data.get('message')}"}), 400
        
        country   = geo_data.get("country", "Unknown")
        latitude  = geo_data.get("lat", 0)
        longitude = geo_data.get("lon", 0)

    except requests.exceptions.Timeout:
        return jsonify({"error": "GeoAPI timed out. Try again later."}), 503
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Network connection failed."}), 500

    # 4. Intelligence & Saving
    threat_level = classify_domain(domain)
    save_analysis(domain, ip_address, country, latitude, longitude, threat_level)

    return jsonify({
        "domain": domain,
        "ip_address": ip_address,
        "country": country,
        "latitude": latitude,
        "longitude": longitude,
        "threat_level": threat_level
    })

@app.route("/history")
def history():
    return jsonify(get_history())

# ── Error Handler for Rate Limit ──
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "⚠️ Rate limit exceeded. You are scanning too fast!"}), 429

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
