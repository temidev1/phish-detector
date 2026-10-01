"""
phish-detector · virustotal
VirusTotal v3 API client for URL lookups.
"""

import base64
import requests

from modules.config import get_key, is_enabled
from modules import cache


API_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url):
    """VT requires URL id = base64(url) without padding"""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check(url, timeout=10):
    result = {
        "service": "VirusTotal",
        "available": False,
        "flagged": None,
        "note": "",
    }

    if not is_enabled("virustotal"):
        result["note"] = "disabled in settings"
        return result

    key = get_key("vt")
    if not key:
        result["note"] = "requires API key (set via Settings)"
        return result

    cached = cache.get(url, "virustotal")
    if cached:
        return cached

    headers = {"x-apikey": key}

    try:
        r = requests.get(
            f"{API_BASE}/urls/{_url_id(url)}",
            headers=headers,
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        result["note"] = "timeout"
        return result
    except requests.exceptions.RequestException as e:
        result["note"] = type(e).__name__
        return result

    if r.status_code == 404:
        # not in VT database — could submit, but skip to save quota
        result["available"] = True
        result["flagged"] = None
        result["note"] = "not previously scanned"
        cache.put(url, "virustotal", result)
        return result

    if r.status_code == 401:
        result["available"] = True
        result["note"] = "invalid API key"
        return result

    if r.status_code == 429:
        result["available"] = True
        result["note"] = "rate limited (4/min free)"
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

    stats = (data.get("data") or {}).get("attributes") or {}
    stats = stats.get("last_analysis_stats") or {}

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    result["available"] = True

    if malicious > 0:
        result["flagged"] = True
        result["note"] = f"{malicious}/{total} vendors flagged malicious"
    elif suspicious > 0:
        result["flagged"] = True
        result["note"] = f"{suspicious}/{total} vendors flagged suspicious"
    elif total > 0:
        result["flagged"] = False
        result["note"] = f"0/{total} vendors flagged"
    else:
        result["flagged"] = None
        result["note"] = "no analysis data"

    cache.put(url, "virustotal", result)
    return result
