"""
threat_logic.py – Domain and IP threat classification for GeoTrace.

Scoring is additive; each rule contributes points up to a maximum of 100.
Levels:
  0–29  → SAFE
 30–59  → SUSPICIOUS
 60–100 → HIGH RISK
"""

from __future__ import annotations
import re

# ── TLD lists ──────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".link", ".gq", ".ml", ".cf", ".ga",
    ".tk", ".pw", ".rest", ".fun", ".icu", ".cyou", ".monster",
}
SAFE_TLDS = {".gov", ".edu", ".mil"}

# ── Keyword patterns ───────────────────────────────────────────────────────
HIGH_RISK_PATTERNS = [
    r"free.?gift", r"click.?here", r"urgent", r"verify.?account",
    r"confirm.?identity", r"paypal.?secure", r"bank.?update",
    r"signin.?secure", r"update.?info", r"win.?prize", r"\bmalware\b",
    r"phish", r"\bransomware\b",
]
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "wallet", "crypto", "payment",
    "invoice", "support", "helpdesk", "portal", "download", "free",
]

# ── High-risk countries (example subset for demo purposes) ─────────────────
HIGH_RISK_COUNTRIES = {
    "North Korea", "Iran",
}

SUSPICIOUS_COUNTRIES = {
    "Russia", "China", "Belarus", "Myanmar",
}

# Known bulletproof/shady ASNs (partial list for demo)
SUSPICIOUS_AS_PREFIXES = [
    "AS49367", "AS57523", "AS3462", "AS16276",  # OVH (often abused)
]


def _extract_tld(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return f".{parts[-1]}" if parts else ""


def _has_excessive_subdomains(domain: str) -> bool:
    return domain.count(".") >= 4


def _looks_like_idn_homograph(domain: str) -> bool:
    """Very simple check for punycode / homograph spoofing."""
    return "xn--" in domain


def _is_ip_literal(domain: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))


def classify_threat(
    domain: str,
    ip: str,
    geo: dict,
) -> tuple[str, int, list[str]]:
    """
    Returns (level, score, reasons).
    level  – 'SAFE' | 'SUSPICIOUS' | 'HIGH RISK'
    score  – 0-100
    reasons – human-readable list of findings
    """
    score = 0
    reasons: list[str] = []

    tld = _extract_tld(domain)
    country = geo.get("country", "")
    asn = geo.get("as", "")

    # ── Safe bonuses (reduce score) ──────────────────────────────────────
    if tld in SAFE_TLDS:
        score -= 15
        reasons.append(f"Trusted TLD ({tld})")

    # ── TLD risk ─────────────────────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        score += 25
        reasons.append(f"High-risk TLD: {tld}")

    # ── Keyword matching ─────────────────────────────────────────────────
    domain_lower = domain.lower()
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, domain_lower):
            score += 30
            reasons.append(f"Matches high-risk pattern: '{pattern}'")
            break

    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain_lower]
    if len(kw_hits) >= 2:
        score += 15
        reasons.append(f"Multiple suspicious keywords: {', '.join(kw_hits)}")
    elif kw_hits:
        score += 8
        reasons.append(f"Suspicious keyword: {kw_hits[0]}")

    # ── Subdomain depth ──────────────────────────────────────────────────
    if _has_excessive_subdomains(domain):
        score += 10
        reasons.append("Excessive subdomain depth (≥4 labels)")

    # ── Homograph / IDN ─────────────────────────────────────────────────
    if _looks_like_idn_homograph(domain):
        score += 20
        reasons.append("Possible IDN homograph attack (punycode detected)")

    # ── IP literal as domain ─────────────────────────────────────────────
    if _is_ip_literal(domain):
        score += 15
        reasons.append("Domain is a raw IP address (no hostname)")

    # ── Domain length ────────────────────────────────────────────────────
    hostname = domain.split(".")[0]
    if len(hostname) > 30:
        score += 10
        reasons.append(f"Unusually long hostname ({len(hostname)} chars)")
    if re.search(r"\d{4,}", hostname):
        score += 5
        reasons.append("Long numeric sequence in hostname")

    # ── Geolocation risk ────────────────────────────────────────────────
    if country in HIGH_RISK_COUNTRIES:
        score += 35
        reasons.append(f"Hosted in high-risk country: {country}")
    elif country in SUSPICIOUS_COUNTRIES:
        score += 15
        reasons.append(f"Hosted in flagged country: {country}")

    # ── ASN / ISP risk ───────────────────────────────────────────────────
    for prefix in SUSPICIOUS_AS_PREFIXES:
        if asn.startswith(prefix):
            score += 10
            reasons.append(f"Hosted on potentially abused network: {asn}")
            break

    # ── Private / loopback IP ────────────────────────────────────────────
    if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
        score += 5
        reasons.append("Resolves to private/loopback IP")

    # ── Clamp ────────────────────────────────────────────────────────────
    score = max(0, min(score, 100))

    if score >= 60:
        level = "HIGH RISK"
    elif score >= 30:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    if not reasons:
        reasons.append("No significant threat indicators found.")

    return level, score, reasons
                
