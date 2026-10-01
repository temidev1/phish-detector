"""
phish-detector · visual
extracts a structural "visual fingerprint" from a page.
compares against known brand fingerprints to detect clones.
"""

import hashlib
import re
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}
TIMEOUT = 10

BRANDS_DIR = Path(__file__).resolve().parent.parent / "data" / "brand_fingerprints"

# brand name -> URL to fingerprint
# brands with working fingerprints (JS-rendered or blocked ones excluded)
BRANDS = {
    "google": "https://accounts.google.com/signin",
    "twitter": "https://twitter.com/i/flow/login",
    "linkedin": "https://www.linkedin.com/login",
    "opay": "https://www.opayweb.com/",
    "moniepoint": "https://moniepoint.com/",
    "access": "https://www.accessbankplc.com/",
    "github": "https://github.com/login",
}


# ---------- color extraction ----------
_HEX_COLOR_RE = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b")
_RGB_COLOR_RE = re.compile(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)")


def _extract_colors(text):
    colors = set()
    for m in _HEX_COLOR_RE.finditer(text or ""):
        h = m.group(1).lower()
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        colors.add("#" + h)
    for m in _RGB_COLOR_RE.finditer(text or ""):
        r, g, b = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # quantize to reduce false variation
        colors.add(f"#{r//16*16:02x}{g//16*16:02x}{b//16*16:02x}")
    return colors


# ---------- font extraction ----------
_FONT_RE = re.compile(r"font-family\s*:\s*([^;}\"']+)", re.IGNORECASE)


def _extract_fonts(text):
    fonts = set()
    for m in _FONT_RE.finditer(text or ""):
        raw = m.group(1)
        for f in raw.split(","):
            name = f.strip().strip("'\"").lower()
            if name and len(name) < 40 and name not in (
                "serif", "sans-serif", "monospace", "cursive", "fantasy"
            ):
                fonts.add(name)
    return fonts


# ---------- class extraction ----------
def _extract_css_classes(soup):
    classes = set()
    for tag in soup.find_all(attrs={"class": True}):
        for c in tag.get("class", []):
            c = c.strip()
            if c and len(c) < 60:
                classes.add(c)
    return classes


# ---------- image hashes ----------
def _hash_bytes(b):
    return hashlib.sha256(b).hexdigest()[:16]


def _fetch_image_hash(url, session, timeout=6):
    try:
        r = session.get(url, timeout=timeout, stream=True)
        if r.status_code != 200:
            return None
        # cap at 500 KB
        data = r.raw.read(500_000, decode_content=True)
        return _hash_bytes(data)
    except Exception:
        return None


def _extract_image_hashes(soup, base_url, session, max_images=6):
    """hash up to N images (logos, favicons, etc.)"""
    hashes = set()
    candidates = []

    # favicon first
    for link in soup.find_all("link", rel=True):
        rels = [r.lower() for r in (link.get("rel") or [])]
        if "icon" in rels or "shortcut" in rels:
            href = link.get("href")
            if href:
                candidates.append(urljoin(base_url, href))

    # img tags with logo-ish src
    for img in soup.find_all("img", src=True):
        src = img.get("src", "")
        low = src.lower()
        if any(k in low for k in ("logo", "icon", "brand", "sprite")):
            candidates.append(urljoin(base_url, src))
        elif len(candidates) < max_images:
            candidates.append(urljoin(base_url, src))

    for url in candidates[:max_images]:
        h = _fetch_image_hash(url, session)
        if h:
            hashes.add(h)

    return hashes


# ---------- layout hints ----------
def _extract_layout(soup):
    layout = {
        "has_form": bool(soup.find("form")),
        "has_password": bool(soup.find("input", {"type": "password"})),
        "has_iframe": bool(soup.find("iframe")),
        "uses_grid": "grid" in str(soup)[:50000].lower(),
        "uses_flex": "flex" in str(soup)[:50000].lower(),
        "table_count": len(soup.find_all("table")),
        "button_count": len(soup.find_all("button")),
        "input_count": len(soup.find_all("input")),
    }
    return layout


# ---------- main fingerprint ----------
def fingerprint(url, timeout=TIMEOUT):
    """fetch page and return a structural fingerprint dict.
    returns dict or {'error': str}."""
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers=UA)
    except Exception as e:
        return {"error": type(e).__name__}

    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}

    html = r.text
    soup = BeautifulSoup(html, "html.parser")

    # gather inline + linked CSS text (for color + font extraction)
    css_text = ""
    for style in soup.find_all("style"):
        css_text += (style.string or "") + "\n"
    # limited external CSS — first 2
    session = requests.Session()
    session.headers.update(UA)
    css_links = [l.get("href") for l in soup.find_all("link", rel=True)
                 if any("stylesheet" in (x or "").lower() for x in (l.get("rel") or []))]
    for href in css_links[:2]:
        try:
            css_url = urljoin(url, href)
            cr = session.get(css_url, timeout=4)
            if cr.status_code == 200:
                css_text += cr.text[:100_000] + "\n"
        except Exception:
            pass

    fp = {
        "url": url,
        "classes": sorted(_extract_css_classes(soup))[:300],
        "colors": sorted(_extract_colors(html + "\n" + css_text))[:80],
        "fonts": sorted(_extract_fonts(css_text))[:15],
        "image_hashes": sorted(_extract_image_hashes(soup, url, session)),
        "layout": _extract_layout(soup),
        "title": (soup.title.string if soup.title else "") or "",
        "favicon_hash": None,
        "error": None,
    }

    # favicon hash extracted as part of image_hashes already
    return fp


# ---------- similarity ----------
def _jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def compare(fp_a, fp_b):
    """compare two fingerprints. returns dict of per-dimension scores."""
    if not fp_a or not fp_b:
        return {"score": 0}

    class_sim = _jaccard(fp_a.get("classes", []), fp_b.get("classes", []))
    color_sim = _jaccard(fp_a.get("colors", []), fp_b.get("colors", []))
    font_sim = _jaccard(fp_a.get("fonts", []), fp_b.get("fonts", []))
    img_sim = _jaccard(fp_a.get("image_hashes", []), fp_b.get("image_hashes", []))

    # layout: exact boolean match
    la = fp_a.get("layout", {})
    lb = fp_b.get("layout", {})
    layout_keys = set(la) | set(lb)
    layout_matches = sum(1 for k in layout_keys if la.get(k) == lb.get(k))
    layout_sim = layout_matches / len(layout_keys) if layout_keys else 0

    # weighted total — image hash match is strongest signal
    total = (
        img_sim * 0.40 +
        class_sim * 0.25 +
        color_sim * 0.15 +
        font_sim * 0.10 +
        layout_sim * 0.10
    )

    return {
        "score": round(total * 100, 1),
        "classes": round(class_sim * 100, 1),
        "colors": round(color_sim * 100, 1),
        "fonts": round(font_sim * 100, 1),
        "images": round(img_sim * 100, 1),
        "layout": round(layout_sim * 100, 1),
    }


# ---------- brand fingerprint storage ----------
def _brand_path(brand):
    return BRANDS_DIR / f"{brand}.json"


def load_brand_fingerprint(brand):
    p = _brand_path(brand)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def save_brand_fingerprint(brand, fp):
    BRANDS_DIR.mkdir(parents=True, exist_ok=True)
    p = _brand_path(brand)
    p.write_text(json.dumps(fp, indent=2))


def refresh_brand_fingerprints():
    """fetch every brand page and store its fingerprint.
    returns list of (brand, status)."""
    results = []
    for brand, url in BRANDS.items():
        fp = fingerprint(url)
        if fp.get("error"):
            results.append((brand, f"error: {fp['error']}"))
        else:
            save_brand_fingerprint(brand, fp)
            results.append((brand, f"ok ({len(fp.get('classes', []))} classes)"))
    return results


def check_clone(url):
    """fingerprint the URL, compare against all stored brands.
    returns list of (brand, scores_dict) sorted by score desc."""
    fp = fingerprint(url)
    if fp.get("error"):
        return fp.get("error")

    matches = []
    for brand in BRANDS:
        stored = load_brand_fingerprint(brand)
        if not stored:
            continue
        cmp = compare(fp, stored)
        if cmp["score"] >= 30:  # only keep meaningful matches
            matches.append((brand, cmp))

    matches.sort(key=lambda x: x[1]["score"], reverse=True)
    return matches
