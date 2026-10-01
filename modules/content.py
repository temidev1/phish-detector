"""
phish-detector · content
fetches a page and analyzes it for phishing indicators.
"""

import re
from urllib.parse import urlparse, urljoin
from pathlib import Path

import requests
from bs4 import BeautifulSoup


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# ---------- known brands ----------
def load_brands():
    fp = DATA_DIR / "brands.txt"
    if not fp.exists():
        return []
    return [l.strip().lower() for l in fp.read_text().splitlines() if l.strip()]


# ---------- suspicious JS patterns ----------
SUSPICIOUS_JS = [
    (r"eval\s*\(", "eval()"),
    (r"atob\s*\(", "atob() base64 decode"),
    (r"unescape\s*\(", "unescape()"),
    (r"String\.fromCharCode\s*\(", "String.fromCharCode"),
    (r"document\.write\s*\(\s*unescape", "document.write(unescape"),
    (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "hex obfuscation"),
    (r"window\.location\s*=\s*atob", "redirect via atob"),
    # note: "long inline script" pattern was removed — every modern site has them.
    # Only flag inline scripts if they ALSO contain obfuscation indicators.
]


# ---------- suspicious path words ----------
SUSPICIOUS_PATH_WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "confirm", "account", "secure", "update", "validate",
    "auth", "authenticate", "reset", "recover",
]


# ---------- main ----------


# ---------- javascript analysis ----------
JS_URL_PATTERN = re.compile(
    r"""(?:"|')(https?://[^"'\s]{6,200})(?:"|')""",
    re.IGNORECASE
)

JS_REDIRECT_PATTERNS = [
    (r"window\.location\s*=", "window.location assignment"),
    (r"document\.location\s*=", "document.location assignment"),
    (r"location\.href\s*=", "location.href assignment"),
    (r"location\.replace\s*\(", "location.replace() call"),
    (r"location\.assign\s*\(", "location.assign() call"),
    (r"top\.location\s*=", "top.location assignment"),
    (r"self\.location\s*=", "self.location assignment"),
    (r"\.submit\s*\(\s*\)", "form.submit()"),
    (r"meta\s+http-equiv\s*=\s*[\"']?refresh", "meta refresh in JS"),
]


def analyze_javascript(soup, html):
    """extract URLs and redirect patterns from all <script> tags."""
    result = {
        "script_count": 0,
        "inline_script_count": 0,
        "external_script_count": 0,
        "external_script_sources": [],
        "urls_in_js": [],
        "redirect_patterns": [],
        "base64_blobs": [],
        "obfuscated_strings": [],
    }

    scripts = soup.find_all("script")
    result["script_count"] = len(scripts)

    seen_urls = set()

    for script in scripts:
        src_attr = script.get("src")
        if src_attr:
            result["external_script_count"] += 1
            result["external_script_sources"].append(src_attr[:150])
            continue

        result["inline_script_count"] += 1
        content = script.string or ""
        if not content:
            continue

        # find URLs
        for m in JS_URL_PATTERN.finditer(content):
            url = m.group(1)
            if url not in seen_urls:
                seen_urls.add(url)
                result["urls_in_js"].append(url[:200])

        # find redirect patterns
        for pat, label in JS_REDIRECT_PATTERNS:
            if re.search(pat, content, re.IGNORECASE):
                if label not in result["redirect_patterns"]:
                    result["redirect_patterns"].append(label)

        # find base64 blobs (long strings of base64 chars)
        for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", content):
            blob = m.group(0)
            if blob not in result["base64_blobs"]:
                # try to decode
                try:
                    import base64
                    decoded = base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
                    if decoded and any(c.isprintable() for c in decoded):
                        result["base64_blobs"].append({
                            "encoded": blob[:60],
                            "decoded": decoded[:120],
                        })
                except Exception:
                    pass
                if len(result["base64_blobs"]) >= 5:
                    break

        # hex-encoded strings (\x41\x42\x43)
        hex_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
        for m in hex_pattern.finditer(content):
            blob = m.group(0)
            if blob not in result["obfuscated_strings"]:
                # try to decode
                try:
                    decoded = blob.encode().decode("unicode_escape")
                    if decoded and decoded.isprintable():
                        result["obfuscated_strings"].append({
                            "encoded": blob[:60],
                            "decoded": decoded[:120],
                        })
                except Exception:
                    pass

    # dedupe lists
    result["urls_in_js"] = list(dict.fromkeys(result["urls_in_js"]))[:20]
    result["external_script_sources"] = list(dict.fromkeys(result["external_script_sources"]))[:10]

    return result


def analyze_content(url, timeout=8):
    """fetch page + analyze. returns dict."""
    result = {
        "fetched": False,
        "status_code": None,
        "content_length": 0,
        "title": None,
        "favicon": None,
        "logo_hints": [],
        "password_fields": 0,
        "forms": [],
        "form_actions_external": False,
        "suspicious_js": [],
        "brands_mentioned": [],
        "brands_weak": [],
        "brand_mismatch": False,
        "claimed_brand": None,
        "domain_brand": None,
        "suspicious_path_words": [],
        "hidden_inputs": 0,
        "iframes": 0,
        "meta_refresh": False,
        "errors": [],
        "js": {
            "script_count": 0,
            "inline_script_count": 0,
            "external_script_count": 0,
            "external_script_sources": [],
            "urls_in_js": [],
            "redirect_patterns": [],
            "base64_blobs": [],
            "obfuscated_strings": [],
        },
    }

    # strip fragment — fragments aren't sent over HTTP
    from urllib.parse import urldefrag as _urldefrag
    fetch_url, _ = _urldefrag(url)
    try:
        r = requests.get(
            fetch_url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; phish-detector/0.6)"}
        )
        result["fetched"] = True
        result["status_code"] = r.status_code
        result["content_length"] = len(r.text)
        html = r.text
    except requests.exceptions.Timeout:
        result["errors"].append("request timed out")
        return result
    except requests.exceptions.SSLError as e:
        result["errors"].append(f"SSL error: {e}")
        return result
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"request error: {type(e).__name__}")
        return result
    except Exception as e:
        result["errors"].append(f"unexpected: {type(e).__name__}")
        return result

    # parse
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        result["errors"].append(f"parse: {e}")
        return result

    # title
    if soup.title and soup.title.string:
        result["title"] = soup.title.string.strip()[:200]

    # favicon
    for link in soup.find_all("link", rel=True):
        rels = [r.lower() for r in (link.get("rel") or [])]
        if "icon" in rels or "shortcut" in rels:
            href = link.get("href")
            if href:
                result["favicon"] = urljoin(url, href)[:200]
                break

    # forms + password fields
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        action_full = urljoin(url, action) if action else url
        action_host = urlparse(action_full).hostname or ""
        url_host = urlparse(url).hostname or ""
        external = bool(action_host and url_host and action_host != url_host)
        n_pass = len(form.find_all("input", {"type": "password"}))
        n_hidden = len(form.find_all("input", {"type": "hidden"}))
        result["forms"].append({
            "action": action_full[:200],
            "method": method,
            "external": external,
            "passwords": n_pass,
            "hidden": n_hidden,
        })
        result["password_fields"] += n_pass
        result["hidden_inputs"] += n_hidden
        if external:
            result["form_actions_external"] = True

    # iframes
    result["iframes"] = len(soup.find_all("iframe"))

    # meta refresh
    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").lower() == "refresh":
            result["meta_refresh"] = True
            break

    # suspicious JS
    for pattern, label in SUSPICIOUS_JS:
        if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
            result["suspicious_js"].append(label)

    # javascript content analysis
    result["js"] = analyze_javascript(soup, html)
    # merge any JS-discovered redirects into suspicious_js
    for rp in result["js"].get("redirect_patterns", []):
        if rp not in result["suspicious_js"]:
            result["suspicious_js"].append(f"JS: {rp}")

    # brands mentioned in the page — but ONLY count as "claimed brand" if
    # the brand appears in the <title> or in a prominent image alt/src.
    # random mentions in body text are not strong enough signal.
    brands = load_brands()
    title_lower = (result["title"] or "").lower()
    strong_brands = []
    weak_brands = []
    for brand in brands:
        pat = r"\b" + re.escape(brand) + r"\b"
        # strong: appears in <title>
        if re.search(pat, title_lower):
            strong_brands.append(brand)
            continue
        # strong: appears in an img alt or src
        for img in soup.find_all("img", src=True):
            alt = (img.get("alt") or "").lower()
            src = (img.get("src") or "").lower()
            if re.search(pat, alt) or re.search(pat, src):
                strong_brands.append(brand)
                break
    result["brands_mentioned"] = strong_brands
    # also record "weak" mentions for informational purposes only
    text_lower = html.lower()
    for brand in brands:
        if brand in strong_brands:
            continue
        pat = r"\b" + re.escape(brand) + r"\b"
        if re.search(pat, text_lower):
            weak_brands.append(brand)
    result["brands_weak"] = weak_brands[:10]

    # brand mismatch
    domain = urlparse(url).hostname or ""
    domain_lower = domain.lower()
    domain_brand = None
    for brand in brands:
        if brand in domain_lower:
            domain_brand = brand
            break
    result["domain_brand"] = domain_brand

    # claimed brand = first strong brand in title
    claimed = None
    for b in result["brands_mentioned"]:
        if b in title_lower:
            claimed = b
            break
    if not claimed and result["brands_mentioned"]:
        claimed = result["brands_mentioned"][0]
    result["claimed_brand"] = claimed

    if claimed and claimed != domain_brand:
        result["brand_mismatch"] = True

    # suspicious path words
    path = urlparse(url).path.lower()
    for word in SUSPICIOUS_PATH_WORDS:
        if word in path:
            result["suspicious_path_words"].append(word)

    # logo hints (look for img tags with brand-ish filenames)
    for img in soup.find_all("img", src=True):
        src = img.get("src", "").lower()
        alt = (img.get("alt") or "").lower()
        for brand in brands:
            if brand in src or brand in alt:
                result["logo_hints"].append({
                    "brand": brand,
                    "src": img.get("src", "")[:150],
                    "alt": img.get("alt", "")[:60],
                })
                break

    return result
