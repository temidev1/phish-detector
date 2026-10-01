"""
phish-detector · cache
JSON-backed response cache keyed by URL hash, with per-service TTL.
"""

import os
import json
import hashlib
import time
from pathlib import Path


CACHE_DIR = Path.home() / ".cache" / "phish-detector"
CACHE_FILE = CACHE_DIR / "cache.json"

# TTL in seconds per service
TTL = {
    "urlscan":   3600,          # 1 hour
    "openphish": 1800,          # 30 min
    "urlhaus":   21600,         # 6 hours
    "gsb":       3600,          # 1 hour
    "virustotal": 86400,        # 24 hours
    "hybrid":    86400,         # 24 hours
}

# cache size cap (entries). when exceeded, oldest entries are pruned.
MAX_ENTRIES = 2000


def _ensure_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _url_hash(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _load_all():
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_all(data):
    _ensure_dir()
    # prune if too large
    if len(data) > MAX_ENTRIES:
        items = sorted(data.items(), key=lambda kv: kv[1].get("ts", 0))
        # keep newest MAX_ENTRIES
        data = dict(items[-MAX_ENTRIES:])
    tmp = CACHE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    tmp.replace(CACHE_FILE)


def get(url, service):
    """return cached response for (url, service) or None if expired/missing"""
    data = _load_all()
    key = f"{service}:{_url_hash(url)}"
    entry = data.get(key)
    if not entry:
        return None
    ttl = TTL.get(service, 3600)
    age = time.time() - entry.get("ts", 0)
    if age > ttl:
        # expired — remove lazily
        del data[key]
        _save_all(data)
        return None
    return entry.get("payload")


def put(url, service, payload):
    """store a response for (url, service)"""
    data = _load_all()
    key = f"{service}:{_url_hash(url)}"
    data[key] = {"ts": time.time(), "payload": payload}
    _save_all(data)


def clear():
    """wipe the entire cache"""
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()


def stats():
    """return {'entries': N, 'services': {service: count}, 'size_bytes': N, 'path': str}"""
    data = _load_all()
    svc_count = {}
    for k in data:
        svc = k.split(":", 1)[0]
        svc_count[svc] = svc_count.get(svc, 0) + 1
    size = 0
    if CACHE_FILE.exists():
        size = CACHE_FILE.stat().st_size
    return {
        "entries": len(data),
        "services": svc_count,
        "size_bytes": size,
        "path": str(CACHE_FILE),
    }


def prune_expired():
    """remove expired entries. returns number removed."""
    data = _load_all()
    now = time.time()
    before = len(data)
    to_keep = {}
    for key, entry in data.items():
        svc = key.split(":", 1)[0]
        ttl = TTL.get(svc, 3600)
        if now - entry.get("ts", 0) <= ttl:
            to_keep[key] = entry
    _save_all(to_keep)
    return before - len(to_keep)
