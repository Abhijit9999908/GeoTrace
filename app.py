"""
app.py — Main Flask application for GeoTrace

Routes:
  GET  /         → Serve the main dashboard page
  POST /analyze  → Resolve a domain, geolocate it, classify it, save & return JSON
  GET  /history  → Return all past analyses as JSON
"""

import socket
import requests
from flask import Flask, render_template, request, jsonify

# Import our custom modules
from database import init_db, save_analysis, get_history
from threat_logic import classify_domain

# ── Create the Flask app ──
app = Flask(__name__)

# ── Initialize the database when the app starts ──
init_db()


# ─────────────────────────────────────────────
# Route 1: Serve the main HTML page
# ─────────────────────────────────────────────
@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


# ─────────────────────────────────────────────
# Route 2: Analyze a domain
# ─────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Expects JSON body: { "domain": "example.com" }

    Steps:
      1. Resolve domain → IP address
      2. Call ip-api.com for geolocation
      3. Classify threat level
      4. Save to database
      5. Return result as JSON
    """
    # Get the domain from the request body
    data = request.get_json()
    domain = data.get("domain", "").strip()

    # Validate input
    if not domain:
        return jsonify({"error": "Please enter a domain name."}), 400

    # Remove protocol prefixes if the user accidentally includes them
    for prefix in ("http://", "https://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]

    # Remove trailing slashes or paths
    domain = domain.split("/")[0]

    # ── Step 1: Resolve domain to IP ──
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return jsonify({"error": f"Could not resolve domain: {domain}"}), 400

    # ── Step 2: Fetch geolocation from ip-api.com ──
    try:
        api_url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(api_url, timeout=10)
        geo_data = response.json()

        # Check if the API returned a failure
        if geo_data.get("status") == "fail":
            return jsonify({"error": f"Geolocation failed: {geo_data.get('message', 'unknown error')}"}), 400

        country   = geo_data.get("country", "Unknown")
        latitude  = geo_data.get("lat", 0)
        longitude = geo_data.get("lon", 0)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error while fetching geolocation: {str(e)}"}), 500

    # ── Step 3: Classify threat level ──
    threat_level = classify_domain(domain)

    # ── Step 4: Save to database ──
    save_analysis(domain, ip_address, country, latitude, longitude, threat_level)

    # ── Step 5: Return the result ──
    result = {
        "domain":       domain,
        "ip_address":   ip_address,
        "country":      country,
        "latitude":     latitude,
        "longitude":    longitude,
        "threat_level": threat_level,
    }

    return jsonify(result)


# ─────────────────────────────────────────────
# Route 3: Get analysis history
# ─────────────────────────────────────────────
@app.route("/history")
def history():
    """Return all stored analyses as a JSON array."""
    return jsonify(get_history())


# ─────────────────────────────────────────────
# Run the app
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # host="0.0.0.0" makes the server accessible on the local network
    # debug=True enables auto-reload during development
       app.run(host="0.0.0.0", port=5000) 


