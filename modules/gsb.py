"""
phish-detector · gsb
Google Safe Browsing v4 Lookup API client.
"""

import json
import requests

from modules.config import get_key, is_enabled
from modules import cache


API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]
PLATFORM_TYPES = ["ANY_PLATFORM"]
ENTRY_TYPES = ["URL"]


def check(url, timeout=8):
    """query GSB for a URL. returns dict like other reputation checks."""
    result = {
        "service": "Google Safe Browsing",
        "available": False,
        "flagged": None,
        "note": "",
    }

    if not is_enabled("gsb"):
        result["note"] = "disabled in settings"
        return result

    key = get_key("gsb")
    if not key:
        result["note"] = "requires API key (set via Settings)"
        return result

    # cache check
    cached = cache.get(url, "gsb")
    if cached:
        return cached

    payload = {
        "client": {
            "clientId": "phish-detector",
            "clientVersion": "0.4",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        # use header-based auth so the key never appears in the URL or tracebacks
        r = requests.post(
            API_URL,
            json=payload,
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "X-Goog-Api-Key": key,
            },
        )
    except requests.exceptions.Timeout:
        result["note"] = "timeout"
        return result
    except requests.exceptions.RequestException as e:
        result["note"] = type(e).__name__
        return result

    if r.status_code == 400:
        result["available"] = True
        result["note"] = "bad request (URL may be malformed)"
        return result
    if r.status_code == 403:
        result["available"] = True
        result["note"] = "invalid API key or quota exceeded"
        return result
    if r.status_code == 429:
        result["available"] = True
        result["note"] = "rate limited"
        return result
    if r.status_code != 200:
        result["available"] = True
        result["note"] = f"HTTP {r.status_code}"
        return result

    try:
        data = r.json()
    except Exception:
        result["available"] = True
        result["note"] = "unparseable response"
        return result

    matches = data.get("matches", [])
    result["available"] = True

    if matches:
        result["flagged"] = True
        threat = matches[0].get("threatType", "unknown")
        result["note"] = f"FLAGGED as {threat}"
    else:
        result["flagged"] = False
        result["note"] = "not flagged"

    cache.put(url, "gsb", result)
    return result
