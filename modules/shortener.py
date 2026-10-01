"""
phish-detector · shortener
expands URL shorteners by following redirect chains.
"""

import requests
from urllib.parse import urlparse, urljoin


UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
    "tiny.cc", "s.id", "shorte.st", "adf.ly", "lnkd.in", "t.ly",
    "soo.gd", "v.gd", "surl.li", "snip.ly", "bc.vc", "mcaf.ee",
    "po.st", "u.to", "x.co", "youtu.be",
}


def is_shortener(url):
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    host = host.lower()
    if host in SHORTENER_DOMAINS:
        return True
    for s in SHORTENER_DOMAINS:
        if host.endswith("." + s):
            return True
    return False


def expand(url, max_hops=8, timeout=6):
    """follow the redirect chain with HEAD requests.
    returns { 'hops': [url, url, ...], 'final': url, 'error': None }"""
    result = {"hops": [], "final": url, "error": None}

    if not is_shortener(url):
        result["hops"] = [url]
        return result

    seen = set()
    current = url
    for _ in range(max_hops):
        if current in seen:
            result["error"] = "loop detected"
            break
        seen.add(current)
        result["hops"].append(current)

        try:
            # many shorteners require a real browser GET; HEAD is often blocked
            r = requests.get(
                current, allow_redirects=False, timeout=timeout,
                headers=UA, stream=True
            )
            # close the response body — we only need headers
            r.close()
        except requests.exceptions.Timeout:
            result["error"] = "timeout"
            break
        except requests.exceptions.TooManyRedirects:
            result["error"] = "too many redirects"
            break
        except requests.exceptions.RequestException as e:
            result["error"] = type(e).__name__
            break

        if r.status_code in (301, 302, 303, 307, 308):
            nxt = r.headers.get("Location", "")
            if not nxt:
                break
            # relative redirects
            if nxt.startswith("/"):
                p = urlparse(current)
                nxt = f"{p.scheme}://{p.netloc}{nxt}"
            elif not nxt.startswith(("http://", "https://")):
                nxt = urljoin(current, nxt)
            current = nxt
        else:
            # no more redirects — current is the final URL
            break

    result["final"] = current
    return result


def format_chain(exp):
    """returns list of (depth, url) tuples for display"""
    hops = exp.get("hops") or []
    final = exp.get("final")
    out = []
    for i, h in enumerate(hops):
        out.append((i, h))
    if final and (not hops or hops[-1] != final):
        out.append((len(hops), final))
    return out
