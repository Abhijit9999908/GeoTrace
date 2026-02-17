"""
threat_logic.py – Domain threat classification for GeoTrace.

ALWAYS returns a tuple of exactly 3 values:
    (level: str, score: int, reasons: list[str])

Levels:
    0-29  → SAFE
    30-59 → SUSPICIOUS
    60+   → HIGH RISK
"""

import re

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".link", ".gq", ".ml", ".cf", ".ga",
    ".tk", ".pw", ".fun", ".icu", ".monster", ".cyou", ".rest",
}
SAFE_TLDS = {".gov", ".edu", ".mil"}

RISKY_PATTERNS = [
    r"free.?gift", r"click.?here", r"urgent", r"verify.?account",
    r"paypal.?secure", r"bank.?update", r"signin.?secure",
    r"win.?prize", r"malware", r"phish", r"ransomware",
]
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "wallet", "crypto",
    "payment", "invoice", "support", "helpdesk", "download",
    "free", "portal",
]
HIGH_RISK_COUNTRIES = {"North Korea", "Iran"}
SUSPICIOUS_COUNTRIES = {"Russia", "China", "Belarus"}


def classify_threat(domain: str, ip: str, geo: dict):
    """
    Returns (level, score, reasons).
    This function NEVER raises — always returns a valid 3-tuple.
    """
    try:
        return _classify(domain, ip, geo)
    except Exception as e:
        return "UNKNOWN", 0, [f"Classification error: {e}"]


def _classify(domain: str, ip: str, geo: dict):
    score = 0
    reasons = []

    domain_lower = (domain or "").lower()
    country = (geo or {}).get("country", "")
    asn = (geo or {}).get("as", "")

    # Extract TLD
    parts = domain_lower.rstrip(".").split(".")
    tld = f".{parts[-1]}" if len(parts) > 1 else ""

    # Safe TLD bonus
    if tld in SAFE_TLDS:
        score -= 20
        reasons.append(f"Trusted TLD ({tld}) — low risk indicator")

    # Risky TLD
    if tld in SUSPICIOUS_TLDS:
        score += 25
        reasons.append(f"High-risk TLD: {tld}")

    # High-risk patterns
    for pattern in RISKY_PATTERNS:
        if re.search(pattern, domain_lower):
            score += 30
            reasons.append(f"Matches high-risk pattern: {pattern}")
            break

    # Keyword hits
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain_lower]
    if len(hits) >= 2:
        score += 15
        reasons.append(f"Multiple suspicious keywords found: {', '.join(hits[:4])}")
    elif len(hits) == 1:
        score += 8
        reasons.append(f"Suspicious keyword detected: {hits[0]}")

    # Subdomain depth
    if domain_lower.count(".") >= 4:
        score += 10
        reasons.append("Excessive subdomain depth (4+ levels)")

    # IDN / punycode homograph
    if "xn--" in domain_lower:
        score += 20
        reasons.append("Possible IDN homograph attack (punycode detected)")

    # Raw IP as domain
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain_lower):
        score += 15
        reasons.append("Domain is a raw IP address — no hostname")

    # Long hostname
    hostname = parts[0] if parts else ""
    if len(hostname) > 30:
        score += 10
        reasons.append(f"Unusually long hostname ({len(hostname)} chars)")

    # Country risk
    if country in HIGH_RISK_COUNTRIES:
        score += 35
        reasons.append(f"Hosted in high-risk country: {country}")
    elif country in SUSPICIOUS_COUNTRIES:
        score += 15
        reasons.append(f"Hosted in flagged country: {country}")

    # Private/loopback IP
    if ip and ip.startswith(("10.", "192.168.", "127.", "172.16.")):
        score += 5
        reasons.append("Resolves to private or loopback IP address")

    # Clamp 0-100
    score = max(0, min(100, score))

    if score >= 60:
        level = "HIGH RISK"
    elif score >= 30:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    if not reasons:
        reasons.append("No significant threat indicators detected.")

    return level, score, reasons
