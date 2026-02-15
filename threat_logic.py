"""
threat_logic.py — Simple rule-based threat classification for GeoTrace

Classifies domains into three categories:
  SAFE    (green)  – well-known trusted services
  TRACKER (yellow) – domains associated with tracking/ads
  UNKNOWN (red)    – everything else
"""


# Keywords that indicate a trusted, well-known service
SAFE_KEYWORDS = [
    "google", "microsoft", "github", "youtube", "apple",
    "amazon", "cloudflare", "mozilla", "wikipedia", "stackoverflow",
    "linkedin", "netflix", "dropbox", "ubuntu", "debian",
]

# Keywords that indicate tracking or advertising
TRACKER_KEYWORDS = [
    "ads", "analytics", "track", "pixel", "adserver",
    "doubleclick", "adservice", "metrics", "telemetry", "beacon",
]


def classify_domain(domain):
    """
    Classify a domain based on simple keyword matching.

    How it works:
      1. Convert the domain to lowercase for case-insensitive matching.
      2. Check if any SAFE keyword appears anywhere in the domain → SAFE.
      3. Check if any TRACKER keyword appears anywhere in the domain → TRACKER.
      4. If neither matches → UNKNOWN.

    Parameters:
        domain (str): The domain name to classify.

    Returns:
        str: One of "SAFE", "TRACKER", or "UNKNOWN".
    """
    domain_lower = domain.lower()

    # Step 1: Check for trusted keywords
    for keyword in SAFE_KEYWORDS:
        if keyword in domain_lower:
            return "SAFE"

    # Step 2: Check for tracking keywords
    for keyword in TRACKER_KEYWORDS:
        if keyword in domain_lower:
            return "TRACKER"

    # Step 3: Default – we don't recognize this domain
    return "UNKNOWN"
