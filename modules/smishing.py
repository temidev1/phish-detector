"""
phish-detector · smishing
analyzes SMS / WhatsApp messages for Nigerian smishing patterns.
"""

import re
from pathlib import Path
from urllib.parse import urlparse


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# ---------- data loaders ----------
def _load_lines(filename):
    fp = DATA_DIR / filename
    if not fp.exists():
        return []
    return [l.strip().lower() for l in fp.read_text().splitlines()
            if l.strip() and not l.startswith("#")]


def load_banks():
    return _load_lines("ng_banks.txt")


def load_telcos():
    return _load_lines("ng_telcos.txt")


def load_agencies():
    return _load_lines("ng_agencies.txt")


def load_keywords():
    """returns list of (keyword, category, severity)"""
    out = []
    for line in _load_lines("smishing_keywords.txt"):
        parts = line.split("|")
        if len(parts) == 3:
            out.append((parts[0], parts[1], parts[2]))
    return out


# ---------- extraction ----------
NIGERIAN_PHONE_RE = re.compile(
    r"\b(?:\+?234|0)[789][01]\d{8}\b"
)

ACCOUNT_NUMBER_RE = re.compile(
    r"\b\d{10}\b"
)

AMOUNT_RE = re.compile(
    r"(?:₦|N|NGN)\s?([0-9][0-9,]*\.?\d*)"
)

URL_RE = re.compile(r"https?://[^\s<>\"']+")

# shortener domains (subset for quick check — main module has full list)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
    "tiny.cc", "s.id", "shorte.st", "adf.ly", "lnkd.in", "t.ly",
    "soo.gd", "v.gd", "surl.li", "snip.ly", "bc.vc", "mcaf.ee",
}


def extract_phone_numbers(text):
    """extract Nigerian phone numbers"""
    return list(set(NIGERIAN_PHONE_RE.findall(text)))


def extract_account_numbers(text):
    """extract 10-digit sequences (Nigerian account number format)"""
    nums = ACCOUNT_NUMBER_RE.findall(text)
    # filter out things that look like phone fragments or years
    out = []
    for n in nums:
        if n in text:
            # skip if it's inside a phone number
            if not any(n in p for p in extract_phone_numbers(text)):
                out.append(n)
    return list(set(out))


def extract_amounts(text):
    """extract Nigerian naira amounts"""
    found = AMOUNT_RE.findall(text)
    return list(set(a.replace(",", "") for a in found))


def extract_urls(text):
    urls = URL_RE.findall(text)
    # strip trailing punctuation
    urls = [u.rstrip(".,;:)]}") for u in urls]
    # dedupe, preserving order
    seen = set()
    out = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def classify_url(url):
    """returns 'shortener' | 'normal'"""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return "normal"
    host = host.lower()
    if host in SHORTENER_DOMAINS:
        return "shortener"
    for s in SHORTENER_DOMAINS:
        if host.endswith("." + s):
            return "shortener"
    return "normal"


# ---------- pattern matching ----------
def match_banks(text):
    """find bank names in the message"""
    text_lower = text.lower()
    found = []
    for bank in load_banks():
        # whole-word match
        if re.search(r"\b" + re.escape(bank) + r"\b", text_lower):
            if bank not in found:
                found.append(bank)
    return found


def match_telcos(text):
    text_lower = text.lower()
    found = []
    for telco in load_telcos():
        if re.search(r"\b" + re.escape(telco) + r"\b", text_lower):
            if telco not in found:
                found.append(telco)
    return found


def match_agencies(text):
    text_lower = text.lower()
    found = []
    for agency in load_agencies():
        if re.search(r"\b" + re.escape(agency) + r"\b", text_lower):
            if agency not in found:
                found.append(agency)
    return found


def match_keywords(text):
    """returns list of (keyword, category, severity) that matched"""
    text_lower = text.lower()
    matches = []
    seen = set()
    for keyword, category, severity in load_keywords():
        # keyword may contain spaces — check as substring
        if keyword in text_lower:
            key = (category, keyword)
            if key not in seen:
                seen.add(key)
                matches.append((keyword, category, severity))
    return matches


# ---------- composite analysis ----------
def analyze_message(text):
    """parse + pattern-match a SMS/WhatsApp message.
    returns dict of findings."""
    result = {
        "text": text,
        "length": len(text),
        "phone_numbers": extract_phone_numbers(text),
        "account_numbers": extract_account_numbers(text),
        "amounts": extract_amounts(text),
        "urls": [(u, classify_url(u)) for u in extract_urls(text)],
        "banks_mentioned": match_banks(text),
        "telcos_mentioned": match_telcos(text),
        "agencies_mentioned": match_agencies(text),
        "keyword_matches": match_keywords(text),
        "categories": {},
        "errors": [],
    }

    # roll up by category
    cats = {}
    for kw, cat, sev in result["keyword_matches"]:
        if cat not in cats:
            cats[cat] = {"count": 0, "keywords": [], "severity": "low"}
        cats[cat]["count"] += 1
        cats[cat]["keywords"].append(kw)
        # escalate severity
        if sev == "high":
            cats[cat]["severity"] = "high"
        elif sev == "med" and cats[cat]["severity"] != "high":
            cats[cat]["severity"] = "med"
    result["categories"] = cats

    return result


def compute_smishing_score(analysis):
    """returns (score 0-100, reasons list). higher = more likely smishing."""
    score = 0
    reasons = []

    cats = analysis.get("categories", {})
    urls = analysis.get("urls", [])

    # BVN / OTP requests — the strongest signal
    if "bvn_request" in cats:
        score += 35
        kws = cats["bvn_request"]["keywords"][:2]
        reasons.append(f"requests BVN or personal identifier ({', '.join(kws)})")

    if "otp_request" in cats:
        score += 35
        kws = cats["otp_request"]["keywords"][:2]
        reasons.append(f"requests OTP or verification code ({', '.join(kws)})")

    if "card_request" in cats:
        score += 30
        reasons.append("requests card details or PIN")

    # impersonation — only scores HIGH if combined with another phishing signal
    # a bank name alone isn't suspicious (real bank SMS mentions the bank)
    # bank name + (BVN request | OTP request | urgency | threat | shortener | action)
    # = phishing

    high_signal_cats = {"bvn_request", "otp_request", "card_request",
                        "threat", "urgency", "action", "whatsapp_hijack",
                        "loan_scam", "reward_scam", "cbn_grant", "gov_grant",
                        "scam_crypto", "job_scam", "pin_request"}
    has_high_signal = bool(high_signal_cats & set(cats.keys()))

    # short URLs also count as a signal
    urls = analysis.get("urls", [])
    short_urls = [u for u, k in urls if k == "shortener"]
    if short_urls:
        has_high_signal = True

    if analysis.get("banks_mentioned"):
        banks = analysis["banks_mentioned"][:2]
        if has_high_signal:
            score += 20
            reasons.append(f"impersonates {', '.join(banks)}")
        else:
            # informational only, no score
            score += 0
            reasons.append(f"mentions {', '.join(banks)} (no phishing pattern)")

    if analysis.get("telcos_mentioned"):
        telcos = analysis["telcos_mentioned"][:2]
        if has_high_signal:
            score += 10
            reasons.append(f"references {', '.join(telcos)}")

    if analysis.get("agencies_mentioned"):
        ag = analysis["agencies_mentioned"][:2]
        if has_high_signal:
            score += 15
            reasons.append(f"impersonates government agency ({', '.join(ag)})")

    # urgency — pressure tactic
    if "urgency" in cats:
        score += 15
        kws = cats["urgency"]["keywords"][:2]
        reasons.append(f"uses urgency ({', '.join(kws)})")

    # threats
    if "threat" in cats:
        score += 20
        kws = cats["threat"]["keywords"][:2]
        reasons.append(f"threatens account action ({', '.join(kws)})")

    # action — click / verify
    if "action" in cats:
        score += 10
        kws = cats["action"]["keywords"][:2]
        reasons.append(f"asks to click or verify ({', '.join(kws)})")

    # money
    if "money" in cats:
        score += 15
        kws = cats["money"]["keywords"][:2]
        reasons.append(f"payment-related ({', '.join(kws)})")

    if "cbn_grant" in cats or "gov_grant" in cats:
        score += 25
        reasons.append("claims government grant or CBN scheme")

    if "loan_scam" in cats:
        score += 20
        reasons.append("fake loan offer")

    if "gov_scam" in cats:
        # government scheme scams stack with politician name-drops
        n_kw = cats["gov_scam"]["count"]
        base = 30
        extra = min(20, (n_kw - 1) * 5)
        weight = base + extra
        score += weight
        kws = cats["gov_scam"]["keywords"][:3]
        reasons.append(f"government scheme scam ({', '.join(kws)})")

    if "chain" in cats:
        score += 10
        reasons.append("asks to forward / share with others")

    if "reward_scam" in cats:
        score += 25
        reasons.append("fake reward / prize claim")

    if "scam_crypto" in cats:
        score += 25
        reasons.append("crypto scam pattern")

    if "job_scam" in cats:
        # task/recruitment scams stack — more keywords = higher confidence
        n_kw = cats["job_scam"]["count"]
        base = 25
        extra = min(25, (n_kw - 1) * 8)  # up to +25 for extra keywords
        weight = base + extra
        score += weight
        kws = cats["job_scam"]["keywords"][:3]
        reasons.append(f"task / recruitment scam ({', '.join(kws)})")

    if "whatsapp_hijack" in cats:
        score += 30
        reasons.append("WhatsApp account takeover attempt")

    if "pin_request" in cats:
        score += 15
        reasons.append("requests PIN")

    # invite-code / referral pattern — task scam fingerprint
    if "invite_code" in cats or "referral" in cats:
        score += 15
        reasons.append("uses invite/referral code (task scam pattern)")

    # URLs present
    if urls:
        score += 5
        reasons.append(f"contains {len(urls)} link(s)")

    # shortened URLs — masks destination
    short = [u for u, k in urls if k == "shortener"]
    if short:
        score += 15
        reasons.append(f"shortened link hides destination ({len(short)})")

    # has Nigerian account number (unusual in legit messages)
    if analysis.get("account_numbers"):
        score += 10
        reasons.append(f"includes account number ({analysis['account_numbers'][0]})")

    return min(100, score), reasons


def verdict_from_score(score):
    if score >= 60:
        return "smishing"
    if score >= 25:
        return "suspicious"
    return "clean"
