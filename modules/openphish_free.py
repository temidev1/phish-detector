"""
phish-detector · openphish_free
OpenPhish public feed — cached in memory.
"""

import requests

import logging
logging.getLogger("urllib3").setLevel(logging.ERROR)

from modules import cache


UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
}
TIMEOUT = 8

_FEED_CACHE = {"data": None, "loaded_at": 0}
_FEED_TTL = 1800  # 30 min


def _load_feed():
    import time
    now = time.time()
    if _FEED_CACHE["data"] and (now - _FEED_CACHE["loaded_at"]) < _FEED_TTL:
        return _FEED_CACHE["data"]
    feed = "https://openphish.com/feed.txt"
    try:
        r = requests.get(feed, headers=UA, timeout=TIMEOUT)
        if r.status_code == 200:
            urls = set(u.strip() for u in r.text.splitlines() if u.strip())
            _FEED_CACHE["data"] = urls
            _FEED_CACHE["loaded_at"] = now
            return urls
    except Exception:
        pass
    _FEED_CACHE["data"] = set()
    _FEED_CACHE["loaded_at"] = now
    return _FEED_CACHE["data"]


def check(url, timeout=TIMEOUT):
    result = {
        "service": "OpenPhish",
        "available": False,
        "flagged": None,
        "note": "",
    }

    cached = cache.get(url, "openphish")
    if cached:
        return cached

    feed = _load_feed()
    if not feed:
        result["note"] = "feed unavailable"
        return result

    result["available"] = True
    if url in feed:
        result["flagged"] = True
        result["note"] = "listed in feed"
    else:
        # check host
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        if any(host in u for u in feed):
            result["flagged"] = True
            result["note"] = "host appears in feed"
        else:
            result["flagged"] = False
            result["note"] = "not listed"

    cache.put(url, "openphish", result)
    return result
