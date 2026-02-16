"""
threat_logic.py — Intelligence Engine for GeoTrace
"""

# Simple lists for demonstration. 
# In a real final year project, you might query an external API like VirusTotal.
TRACKER_KEYWORDS = [
    "ad", "ads", "analytics", "pixel", "tracker", "telemetry", 
    "doubleclick", "facebook", "googleadservices", "amazon-adsystem"
]

SAFE_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org", 
    "python.org", "microsoft.com", "apple.com"
]

def classify_domain(domain):
    """
    Analyzes the domain string to determine a threat level.
    Returns: 'SAFE', 'TRACKER', or 'UNKNOWN'
    """
    domain = domain.lower()

    # Check for known safe domains
    if domain in SAFE_DOMAINS or domain.endswith(".gov") or domain.endswith(".edu"):
        return "SAFE"

    # Check for tracking keywords
    for keyword in TRACKER_KEYWORDS:
        if keyword in domain:
            return "TRACKER"

    # Default if no specific patterns match
    return "UNKNOWN"
