"""
phish-detector · urlscan_free
URLScan.io search — no API key required.
"""

import requests
from urllib.parse import urlparse

# silence urllib3 retry-warning logs that leak to stderr on timeouts
import logging
logging.getLogger("urllib3").setLevel(logging.ERROR)

from modules import cache


UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
}
TIMEOUT = 8


def check(url, timeout=TIMEOUT):
    result = {
        "service": "URLScan.io",
        "available": False,
        "flagged": None,
        "note": "",
    }

    host = urlparse(url).hostname or ""
    if not host:
        result["note"] = "no host"
        return result

    cached = cache.get(url, "urlscan")
    if cached:
        return cached

    endpoint = f"https://urlscan.io/api/v1/search/?q=domain:{host}"
    try:
        r = requests.get(endpoint, headers=UA, timeout=timeout)
    except requests.exceptions.Timeout:
        result["note"] = "timeout"
        return result
    except requests.exceptions.RequestException as e:
        result["note"] = type(e).__name__
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
        j = r.json()
    except Exception:
        result["available"] = True
        result["note"] = "unparseable response"
        return result

    total = j.get("total", 0)
    results = j.get("results", [])
    malicious = sum(1 for entry in results
                    if (entry.get("verdicts") or {}).get("overall", {}).get("malicious"))

    result["available"] = True
    if malicious > 0:
        result["flagged"] = True
        result["note"] = f"{malicious} malicious detections"
    elif total == 0:
        result["flagged"] = False
        result["note"] = "no previous scans"
    else:
        result["flagged"] = False
        result["note"] = f"{total} scans, no detections"

    cache.put(url, "urlscan", result)
    return result
