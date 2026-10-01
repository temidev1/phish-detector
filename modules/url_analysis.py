"""
phish-detector · url_analysis
parses URLs, checks TLDs, typosquatting, homoglyphs, domain age, redirects.
"""

import os
import re
import socket
import unicodedata
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from datetime import datetime

import requests

try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


DATA_DIR = Path(__file__).resolve().parent.parent / "data"



# ---------- suspicious path words ----------
SUSPICIOUS_PATH_WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "confirm", "account", "secure", "update", "validate",
    "auth", "authenticate", "reset", "recover",
]


# ---------- data loaders ----------
def load_brands():
    fp = DATA_DIR / "brands.txt"
    if not fp.exists():
        return []
    return [l.strip().lower() for l in fp.read_text().splitlines() if l.strip()]


def load_suspicious_tlds():
    fp = DATA_DIR / "suspicious_tlds.txt"
    if not fp.exists():
        return set()
    return set(l.strip().lower() for l in fp.read_text().splitlines() if l.strip())


# ---------- levenshtein (pure python) ----------
def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j - 1] + 1,       # insert
                prev[j] + 1,           # delete
                prev[j - 1] + cost     # substitute
            ))
        prev = curr
    return prev[-1]


# ---------- homoglyph detection ----------
# cyrillic and greek chars that look like latin
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ӏ": "l", "ԁ": "d",
    "α": "a", "β": "b", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "τ": "t",
}


def has_homoglyph(host):
    return any(ch in HOMOGLYPHS for ch in host)


def normalize_homoglyphs(host):
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in host)


def normalize_digits(host):
    """leet / digit-for-letter substitution used in typosquats.
    paypa1 -> paypal, g00gle -> google, faceb00k -> facebook."""
    return (str(host or "").lower()
            .replace("0", "o").replace("1", "l").replace("3", "e")
            .replace("4", "a").replace("5", "s").replace("7", "t")
            .replace("8", "b").replace("@", "a").replace("$", "s"))


AUTH_LURE_WORDS = ["login", "signin", "verify", "verification",
                   "secure", "security", "account", "update",
                   "confirm", "confirming", "authenticate", "validation"]


def has_auth_lure(label):
    """true if the label contains a login/verify-style word"""
    if not label:
        return False
    l = str(label).lower()
    return any(w in l for w in AUTH_LURE_WORDS)


# ---------- typosquatting ----------
def typosquat_score(host, brands):
    """return (best_brand, score 0-100) where score = 100 - normalized_levenshtein"""
    # strip TLD
    parts = host.lower().split(".")
    if len(parts) < 2:
        return (None, 0)
    label = parts[0]
    # also check each dot-separated label
    labels = [p for p in parts if p]
    best = (None, 0)
    for brand in brands:
        for lbl in labels:
            # skip exact match — that would be the real domain
            if lbl == brand:
                continue
            # v0.7: compare raw and digit-normalized forms
            candidates = [lbl]
            nd = normalize_digits(lbl)
            if nd != lbl:
                candidates.append(nd)
            for cand in candidates:
                d = levenshtein(cand, brand)
                m = max(len(cand), len(brand))
                if m == 0:
                    continue
                sim = int((1 - d / m) * 100)
                if brand in cand and cand != brand:
                    sim = max(sim, 75)
                if sim >= 60 and sim > best[1]:
                    best = (brand, sim)
    return best


# ---------- domain age ----------
def domain_age(host):
    """returns dict {age_days, created, registrar, error}"""
    if not WHOIS_AVAILABLE:
        return {"error": "python-whois not installed", "age_days": None,
                "created": None, "registrar": None}

    parts = host.lower().split(".")
    if len(parts) < 2:
        return {"error": "invalid host", "age_days": None,
                "created": None, "registrar": None}

    # silence python-whois chatter — it prints errors to stdout AND stderr
    # line 255 of whois/whois.py has a raw print() for socket errors
    import io
    import sys as _sys
    _saved_out = _sys.stdout
    _saved_err = _sys.stderr
    _sys.stdout = io.StringIO()
    _sys.stderr = io.StringIO()
    result = None
    try:
        candidates = [".".join(parts[-2:]), host]
        for dom in candidates:
            try:
                w = pywhois.whois(dom)
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                if created:
                    age = (datetime.now() - created).days
                    result = {
                        "age_days": age,
                        "created": created.strftime("%Y-%m-%d"),
                        "registrar": (w.registrar or "unknown")[:40],
                        "error": None,
                    }
                    break
            except Exception:
                continue
    finally:
        _sys.stdout = _saved_out
        _sys.stderr = _saved_err

    if result:
        return result

    return {"error": "whois lookup failed", "age_days": None,
            "created": None, "registrar": None}

# ---------- redirect chain ----------
def check_redirects(url, max_hops=5):
    """follow HEAD requests, return list of hops"""
    # strip fragment — fragments aren't sent over HTTP
    from urllib.parse import urldefrag
    url, _ = urldefrag(url)
    hops = []
    current = url
    for _ in range(max_hops):
        try:
            r = requests.head(current, allow_redirects=False, timeout=6,
                              headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code in (301, 302, 303, 307, 308):
                nxt = r.headers.get("Location", "")
                if not nxt:
                    break
                if nxt.startswith("/"):
                    p = urlparse(current)
                    nxt = f"{p.scheme}://{p.netloc}{nxt}"
                hops.append((current, r.status_code, nxt))
                current = nxt
            else:
                break
        except Exception as e:
            hops.append((current, 0, f"error: {type(e).__name__}"))
            break
    return hops, current


# ---------- main analysis ----------
def analyze_url(url):
    """returns a dict of findings for a single URL"""
    result = {
        "input": url,
        "scheme": None,
        "host": None,
        "port": None,
        "path": None,
        "query": None,
        "has_https": False,
        "tld": None,
        "tld_suspicious": False,
        "has_homoglyph": False,
        "homoglyph_decoded": None,
        "typosquat_brand": None,
        "typosquat_score": 0,
        "auth_lure": False,
        "domain_age_days": None,
        "domain_created": None,
        "registrar": None,
        "dns_resolves": False,
        "resolved_ip": None,
        "redirects": [],
        "final_url": None,
        "suspicious_path_words": [],
        "errors": [],
    }

    try:
        p = urlparse(url)
    except Exception as e:
        result["errors"].append(f"urlparse: {e}")
        return result

    result["scheme"] = p.scheme
    result["host"] = p.hostname or ""
    result["port"] = p.port
    result["path"] = p.path
    result["query"] = p.query
    result["has_https"] = p.scheme == "https"

    # path word analysis
    path_lower = (p.path or "").lower()
    for word in SUSPICIOUS_PATH_WORDS:
        if word in path_lower:
            result["suspicious_path_words"].append(word)

    host = (p.hostname or "").lower()
    if not host:
        result["errors"].append("no host in URL")
        return result

    # TLD
    parts = host.split(".")
    if len(parts) >= 2:
        tld = "." + parts[-1]
        result["tld"] = tld
        result["tld_suspicious"] = tld in load_suspicious_tlds()

    # homoglyph
    if has_homoglyph(host):
        result["has_homoglyph"] = True
        result["homoglyph_decoded"] = normalize_homoglyphs(host)

    # typosquat
    brand, score = typosquat_score(host, load_brands())
    result["typosquat_brand"] = brand
    result["typosquat_score"] = score
    # v0.7: auth-lure word in the label
    parts = host.lower().split(".")
    if parts and has_auth_lure(parts[0]):
        result["auth_lure"] = True

    # DNS resolve
    try:
        ip = socket.gethostbyname(host)
        result["dns_resolves"] = True
        result["resolved_ip"] = ip
    except socket.gaierror:
        result["errors"].append("DNS resolution failed")
    except Exception as e:
        result["errors"].append(f"DNS: {type(e).__name__}")

    # domain age
    age_info = domain_age(host)
    result["domain_age_days"] = age_info.get("age_days")
    result["domain_created"] = age_info.get("created")
    result["registrar"] = age_info.get("registrar")
    if age_info.get("error"):
        result["errors"].append(f"whois: {age_info['error']}")

    # redirects
    hops, final = check_redirects(url)
    result["redirects"] = hops
    result["final_url"] = final

    return result
