"""
phish-detector · urlhaus_keyed
URLhaus API client with Auth-Key (abuse.ch).
"""

import requests

from modules.config import get_key, is_enabled
from modules import cache


API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def check(url, timeout=8):
    result = {
        "service": "URLhaus",
        "available": False,
        "flagged": None,
        "note": "",
    }

    if not is_enabled("urlhaus"):
        result["note"] = "disabled in settings"
        return result

    key = get_key("urlhaus")
    if not key:
        result["note"] = "requires AbuseCH Auth-Key"
        return result

    cached = cache.get(url, "urlhaus")
    if cached:
        return cached

    headers = {"Auth-Key": key}

    try:
        r = requests.post(
            API_URL,
            data={"url": url},
            headers=headers,
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        result["note"] = "timeout"
        return result
    except requests.exceptions.RequestException as e:
        result["note"] = type(e).__name__
        return result

    if r.status_code == 401:
        result["available"] = True
        result["note"] = "invalid Auth-Key"
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

    status = data.get("query_status")
    result["available"] = True

    if status == "ok":
        result["flagged"] = True
        threat = data.get("threat", "malware")
        result["note"] = f"listed as {threat}"
    elif status == "no_results":
        result["flagged"] = False
        result["note"] = "not listed"
    else:
        result["flagged"] = None
        result["note"] = status or "unknown status"

    cache.put(url, "urlhaus", result)
    return result
