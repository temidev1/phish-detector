"""
phish-detector · email
parses raw email — headers, auth results, urgency language, attachments, URLs.
"""

import re
import hashlib
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


URGENCY_WORDS = [
    "urgent", "immediately", "asap", "right away", "action required",
    "final notice", "last chance", "expires", "expiring", "time sensitive",
    "within 24 hours", "within 48 hours", "act now", "verify now",
    "confirm now", "update now", "click now", "act immediately",
    "immediate action", "deadline", "limited time", "respond immediately",
]

THREAT_WORDS = [
    "account will be closed", "account suspended", "account disabled",
    "account locked", "access denied", "access revoked", "will be deleted",
    "will be terminated", "legal action", "lawsuit", "suspend your",
    "close your account", "delete your account", "revoke your",
    "unauthorized access", "security breach", "unusual activity",
    "suspicious activity", "compromised", "failed login",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear member",
    "dear client", "dear account holder", "hello user",
    "dear sir/madam", "to whom it may concern",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
    "tiny.cc", "s.id", "shorte.st", "adf.ly",
]


def _shorten(text, n=50):
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= n else text[:n-3] + "..."


# ---------- header parsing ----------
def parse_email(raw, headers_only=False):
    """parse raw email source. returns dict."""
    out = {
        "from": "",
        "reply_to": None,
        "return_path": None,
        "subject": None,
        "date": None,
        "to": None,
        "message_id": None,
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "sender_ip": None,
        "received": [],
        "auth_results_raw": None,
        "headers": {},
    }

    # normalize line endings
    raw = raw.replace("\r\n", "\n")
    # strip ---END--- sentinel if present
    if "---END---" in raw:
        raw = raw.split("---END---")[0]
    # strip leading blank lines (breaks email parser if present)
    raw = raw.lstrip("\n")
    if headers_only:
        # ensure a blank line at the end so the parser treats it as headers
        if not raw.endswith("\n\n"):
            raw = raw.rstrip("\n") + "\n\n"

    try:
        msg = email.message_from_string(raw, policy=policy.default)
    except Exception:
        return out

    # headers
    for k in ("From", "Reply-To", "Return-Path", "Subject", "Date",
              "To", "Message-ID"):
        v = msg.get(k)
        if v:
            out[k.lower().replace("-", "_")] = str(v).strip()

    # Received headers (routing chain)
    for h in msg.get_all("Received", []):
        out["received"].append(str(h).strip().replace("\n", " ")[:200])

    # Authentication-Results — check for SPF, DKIM, DMARC results
    auth_hdr = msg.get("Authentication-Results", "") or ""
    out["auth_results_raw"] = auth_hdr[:300] if auth_hdr else None

    # also check Received-SPF
    spf_hdr = msg.get("Received-SPF", "") or ""
    if spf_hdr:
        if "pass" in spf_hdr.lower():
            out["spf"] = "pass"
        elif "fail" in spf_hdr.lower():
            out["spf"] = "fail"
        elif "softfail" in spf_hdr.lower():
            out["spf"] = "softfail"
        elif "neutral" in spf_hdr.lower():
            out["spf"] = "neutral"
        elif "none" in spf_hdr.lower():
            out["spf"] = "none"

    # parse Authentication-Results for spf/dkim/dmarc
    if auth_hdr:
        for service in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{service}\s*=\s*(\w+)", auth_hdr, re.IGNORECASE)
            if m:
                out[service] = m.group(1).lower()

    # sender IP from received headers (first IP mentioned in top Received)
    if out["received"]:
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out["received"][0])
        if ips:
            out["sender_ip"] = ips[0]

    return out, msg


# ---------- analysis helpers ----------
def extract_sender_domain(addr):
    if not addr:
        return None
    m = re.search(r"@([a-zA-Z0-9.\-]+)", addr)
    if m:
        return m.group(1).lower().strip(">").strip()
    return None


def extract_email_addr(addr):
    if not addr:
        return None
    m = re.search(r"<([^>]+)>", addr)
    if m:
        return m.group(1).strip().lower()
    return addr.strip().lower()


def check_sender_mismatch(parsed):
    from_addr = extract_email_addr(parsed.get("from"))
    reply_to = extract_email_addr(parsed.get("reply_to"))
    return_path = extract_email_addr(parsed.get("return_path"))

    if from_addr and reply_to and from_addr != reply_to:
        return True
    if from_addr and return_path and from_addr != return_path:
        return True
    return False


def detect_urgency(text):
    if not text:
        return []
    low = text.lower()
    return [w for w in URGENCY_WORDS if w in low]


def detect_threats(text):
    if not text:
        return []
    low = text.lower()
    return [w for w in THREAT_WORDS if w in low]


def detect_generic_greeting(text):
    if not text:
        return False
    low = text.lower()
    return any(g in low for g in GENERIC_GREETINGS)


def extract_urls(text):
    if not text:
        return []
    urls = re.findall(r"https?://[^\s<>\"']+", text)
    # dedupe preserving order
    seen = set()
    out = []
    for u in urls:
        # strip trailing punctuation
        u = u.rstrip(".,;:)]}")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def classify_url(url):
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return "unknown"
    host = host.lower()
    for s in SHORTENER_DOMAINS:
        if host == s or host.endswith("." + s):
            return "shortener"
    return "normal"


def check_link_text_mismatch(msg):
    """look for <a href='X'>Y</a> where X and Y are different domains."""
    mismatches = []
    if msg is None:
        return mismatches
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/html", "text/plain"):
            continue
        try:
            body = part.get_content()
        except Exception:
            continue
        if not isinstance(body, str):
            continue
        # find <a href="...">TEXT</a>
        pattern = re.compile(
            r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )
        for m in pattern.finditer(body):
            href = m.group(1).strip()
            text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            if not href.startswith(("http://", "https://")):
                continue
            # if text looks like a URL or domain and doesn't match href host
            text_domain_match = re.search(r"(?:https?://)?([a-z0-9.\-]+\.[a-z]{2,})",
                                          text, re.IGNORECASE)
            if not text_domain_match:
                continue
            text_domain = text_domain_match.group(1).lower()
            try:
                href_domain = urlparse(href).hostname or ""
            except Exception:
                continue
            href_domain = href_domain.lower()
            # compare base domains
            def base(d):
                parts = d.split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else d
            if base(text_domain) and base(href_domain) and \
               base(text_domain) != base(href_domain):
                mismatches.append((text_domain, href_domain, href))
        break  # only first html part
    return mismatches


def get_body_text(msg):
    """extract plain-text body from email message"""
    if msg is None:
        return ""
    text_parts = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "text/plain":
            try:
                text_parts.append(part.get_content())
            except Exception:
                pass
        elif ctype == "text/html":
            try:
                html = part.get_content()
                # strip tags
                plain = re.sub(r"<[^>]+>", " ", html)
                text_parts.append(plain)
            except Exception:
                pass
    return "\n".join(text_parts)


def extract_attachments(msg):
    if msg is None:
        return []
    out = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disp = part.get("Content-Disposition", "") or ""
        if "attachment" not in disp.lower():
            # also check filename presence
            if not part.get_filename():
                continue
        fn = part.get_filename()
        if not fn:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
            size = len(payload)
            sha = hashlib.sha256(payload).hexdigest()
        except Exception:
            size = 0
            sha = ""
        out.append({
            "filename": fn[:100],
            "size": size,
            "sha256": sha,
        })
    return out


def check_dnsbl(sender_ip):
    """query Spamhaus SBL via DNS. returns blocklist name or None."""
    if not sender_ip:
        return None
    import socket
    try:
        reversed_ip = ".".join(reversed(sender_ip.split(".")))
        query = f"{reversed_ip}.sbl.spamhaus.org"
        socket.gethostbyname(query)
        return "Spamhaus SBL"
    except socket.gaierror:
        return None
    except Exception:
        return None


# ---------- main entry ----------
def analyze_email(raw, headers_only=False):
    parsed_res = parse_email(raw, headers_only=headers_only)
    if isinstance(parsed_res, tuple):
        parsed, msg = parsed_res
    else:
        parsed, msg = parsed_res, None

    result = dict(parsed)

    # sender mismatch
    result["sender_mismatch"] = check_sender_mismatch(parsed)
    result["sender_domain"] = extract_sender_domain(parsed.get("from"))

    # body text
    body = "" if headers_only else get_body_text(msg)

    # urgency + threats + generic greeting
    result["urgency_words"] = detect_urgency(body) if body else []
    result["threat_words"] = detect_threats(body) if body else []
    result["generic_greeting"] = detect_generic_greeting(body) if body else False

    # URLs in body
    urls_found = extract_urls(body) if body else []
    result["urls"] = [(u, classify_url(u)) for u in urls_found]

    # link text mismatch
    result["link_text_mismatch"] = []
    if not headers_only and msg is not None:
        mismatches = check_link_text_mismatch(msg)
        result["link_text_mismatch"] = mismatches

    # attachments
    result["attachments"] = [] if headers_only else extract_attachments(msg)

    # DNSBL
    result["sender_ip_blocklisted"] = check_dnsbl(parsed.get("sender_ip"))

    # auth dict
    result["auth"] = {
        "spf": parsed.get("spf") or "unknown",
        "dkim": parsed.get("dkim") or "unknown",
        "dmarc": parsed.get("dmarc") or "unknown",
    }

    return result
