"""
threat_logic.py — Enhanced Intelligence Engine
"""

# Keywords often found in tracking/ad domains
TRACKER_KEYWORDS = [
    "ad", "ads", "analytics", "pixel", "tracker", "telemetry", 
    "doubleclick", "facebook", "googleadservices", "amazon-adsystem",
    "metrics", "stats", "click", "marketing"
]

# TLDs often used for spam or low-quality sites
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".gq", ".cn", ".ru", ".tk", ".fit", ".rest"
]

SAFE_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org", 
    "python.org", "microsoft.com", "apple.com", "youtube.com"
]

def classify_domain(domain):
    domain = domain.lower()

    # 1. Check Safe List
    if domain in SAFE_DOMAINS or domain.endswith(".gov") or domain.endswith(".edu"):
        return "SAFE"

    # 2. Check Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return "SUSPICIOUS"

    # 3. Check Tracker Keywords
    for keyword in TRACKER_KEYWORDS:
        if keyword in domain:
            return "TRACKER"

    return "UNKNOWN"
