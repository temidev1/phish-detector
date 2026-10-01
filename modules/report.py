"""
phish-detector · report
combines url_analysis + content + email + reputation, computes verdict, renders output.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.url_analysis import analyze_url
from modules.content import analyze_content
from modules.reputation import check_all, summary as rep_summary
from modules.email import analyze_email
from modules.shortener import is_shortener, expand, format_chain
from modules.tls import analyze_tls
from modules.visual import check_clone as check_visual_clone

from phishdetect import C, Progress, term_width, pad, vlen
import re as _re


# ============ LAYOUT PRIMITIVES ============

def _strip_ansi(s):
    return _re.sub(r"\033\[[0-9;]*m", "", s)


def compute_confidence(url_f, content_f, rep_results, email_f=None):
    """confidence = how much data did we actually get to work with.
    separate from risk score. returns 20-100."""
    conf = 100

    # page did not load - big hit
    if not content_f or not content_f.get("fetched"):
        conf -= 30

    # whois failed
    if not url_f or url_f.get("domain_age_days") is None:
        conf -= 20

    # how many reputation sources actually answered
    answered = sum(1 for r in (rep_results or [])
                   if r.get("flagged") is not None)
    if answered == 0:
        conf -= 25
    elif answered == 1:
        conf -= 15
    elif answered == 2:
        conf -= 5

    # dns did not resolve
    if url_f and not url_f.get("dns_resolves"):
        conf -= 10

    # email-specific: no auth headers present
    if email_f:
        a = email_f.get("auth") or {}
        if a.get("spf") in (None, "unknown"):
            conf -= 10
        if a.get("dmarc") in (None, "unknown"):
            conf -= 10

    return max(20, min(100, conf))


def header_block(target, verdict, risk, confidence, ts=None):
    """compact verdict box - risk score + verdict + confidence as separate concepts."""
    from datetime import datetime
    ts = ts or datetime.now().strftime("%Y-%m-%d %H:%M")

    if verdict == "phish":
        color, dot, label = C.RED, "🔴", "PHISHING"
    elif verdict == "suspicious":
        color, dot, label = C.YELLOW, "🟡", "SUSPICIOUS"
    elif verdict == "clean":
        color, dot, label = C.GREEN, "🟢", "CLEAN"
    else:
        color, dot, label = C.GREY, "⚪", "UNKNOWN"

    w = 54
    print()
    print(f"  {color}┌{'─' * w}┐{C.RESET}")
    print(f"  {color}│{C.RESET} {dot}  {C.BOLD}{label}{C.RESET}"
          f"{' ' * (w - vlen(label) - 6)}{color}│{C.RESET}")
    # URL target_line — cap and pad to inner width
    inner = w - 2
    if len(target) > inner:
        target_line = target[:inner - 3] + "..."
    else:
        target_line = target
    pad_right = inner - len(target_line)
    if pad_right < 0:
        pad_right = 0
    print(f"  {color}│{C.RESET}{C.WHITE} {target_line}{C.RESET}"
          f"{' ' * pad_right}{color}│{C.RESET}")
    print(f"  {color}│{C.RESET}")
    risk_line = f"Risk score:   {risk} / 100"
    print(f"  {color}│{C.RESET} {C.GREY_DIM}{risk_line}{C.RESET}"
          f"{' ' * (w - vlen(risk_line) - 2)}{color}│{C.RESET}")
    conf_line = f"Confidence:   {confidence}%"
    print(f"  {color}│{C.RESET} {C.GREY_DIM}{conf_line}{C.RESET}"
          f"{' ' * (w - vlen(conf_line) - 2)}{color}│{C.RESET}")
    print(f"  {color}│{C.RESET}")
    ts_line = f"Checked: {ts}"
    print(f"  {color}│{C.RESET} {C.GREY_DIM}{ts_line}{C.RESET}"
          f"{' ' * (w - vlen(ts_line) - 2)}{color}│{C.RESET}")
    print(f"  {color}└{'─' * w}┘{C.RESET}")
    print()


def section(title):
    print(f"\r  {C.BLUE}▎{C.RESET} {C.BOLD}{C.WHITE}{title}{C.RESET}")


def two_col(items, col_sep=3):
    """items: list of (state, label) where state in ok/warn/bad/info.
    render two items per row. lines wrap when odd count."""
    marks = {
        "ok":   f"{C.GREEN}✓{C.RESET}",
        "warn": f"{C.YELLOW}⚠{C.RESET}",
        "bad":  f"{C.RED}✗{C.RESET}",
        "info": f"{C.GREY}·{C.RESET}",
    }
    colors = {
        "ok":   C.WHITE_SOFT,
        "warn": C.YELLOW,
        "bad":  C.RED,
        "info": C.GREY,
    }

    # split into two columns
    half = (len(items) + 1) // 2
    left = items[:half]
    right = items[half:]

    # find max label width in each column
    def widest(col):
        w = 0
        for _, label in col:
            w = max(w, vlen(label))
        return w

    lw = widest(left)
    rw = widest(right)

    rows = max(len(left), len(right))
    for i in range(rows):
        line = "    "
        if i < len(left):
            state, label = left[i]
            line += f"{marks[state]}  {colors[state]}{pad(label, lw)}{C.RESET}"
        else:
            line += " " * (4 + lw)
        line += " " * col_sep
        if i < len(right):
            state, label = right[i]
            line += f"{marks[state]}  {colors[state]}{label}{C.RESET}"
        print(line)


def stacked(items):
    """one item per row - for long content that doesn't fit two columns."""
    marks = {
        "ok":   f"{C.GREEN}✓{C.RESET}",
        "warn": f"{C.YELLOW}⚠{C.RESET}",
        "bad":  f"{C.RED}✗{C.RESET}",
        "info": f"{C.GREY}·{C.RESET}",
    }
    colors = {
        "ok":   C.WHITE_SOFT,
        "warn": C.YELLOW,
        "bad":  C.RED,
        "info": C.GREY,
    }
    for state, label in items:
        print(f"    {marks[state]}  {colors[state]}{label}{C.RESET}")


# ============ SCORING ============

def _merge_reputation(primary, secondary):
    """merge two reputation result lists; for each service, prefer the flagged version."""
    merged = {}
    for r in primary:
        merged[r.get("service")] = r
    for r in secondary:
        svc = r.get("service")
        if svc in merged:
            # replace if the new one is flagged and the existing is not
            if r.get("flagged") is True and merged[svc].get("flagged") is not True:
                merged[svc] = r
        else:
            merged[svc] = r
    return list(merged.values())


def _base_url(url):
    """strip path/query/fragment — return scheme://host/"""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return None
        base = f"{p.scheme}://{p.netloc}/"
        if base == url:
            return None
        return base
    except Exception:
        return None


def compute_score(url_f, content_f, rep_results, email_f=None):
    """return (score 0-100, reasons list). higher = more likely phishing."""
    score = 0
    reasons = []

    # ---- URL signals ----
    if url_f.get("tld_suspicious") is True:
        score += 15
        reasons.append(f"suspicious domain ending ({url_f.get('tld')})")

    if url_f.get("has_homoglyph") is True:
        score += 25
        reasons.append(f"fake lookalike characters in domain "
                       f"(reads as {url_f.get('homoglyph_decoded')})")

    tsq = url_f.get("typosquat_score", 0)
    # v0.7: match web version ladder (78/70/60) and use info-only for low tiers
    if tsq >= 85:
        score += 50
        reasons.append(f"impersonates '{url_f.get('typosquat_brand')}' "
                       f"({tsq}% similar) — do not trust")
    elif tsq >= 78:
        score += 30
        reasons.append(f"almost matches '{url_f.get('typosquat_brand')}' "
                       f"({tsq}% similar)")
    elif tsq >= 70:
        score += 5
        reasons.append(f"somewhat similar to '{url_f.get('typosquat_brand')}' "
                       f"({tsq}% similar) — could be coincidence")
    elif tsq >= 60:
        score += 5
        reasons.append(f"similar to '{url_f.get('typosquat_brand')}' "
                       f"({tsq}%)")

    # v0.7: auth-lure word + typosquat = strong phishing signal
    if url_f.get("auth_lure") and url_f.get("typosquat_brand"):
        score += 25
        reasons.append(f"combines '{url_f.get('typosquat_brand')}' "
                       f"with a login/verify word in the domain")

    # v0.7: three-signal stacking (typosquat + bad TLD + auth-lure)
    if (url_f.get("typosquat_score", 0) >= 70
            and url_f.get("tld_suspicious")
            and url_f.get("auth_lure")):
        score += 35
        reasons.append("impersonates a brand, uses a scammer TLD, "
                       "and pairs it with a login/verify word")

    age = url_f.get("domain_age_days")
    if age is not None:
        if age < 7:
            score += 25
            reasons.append(f"domain is only {age} days old")
        elif age < 30:
            score += 15
            reasons.append(f"domain is {age} days old")
        elif age < 90:
            score += 5
            reasons.append(f"domain is {age} days old")

    if url_f.get("has_https") is False:
        score += 10
        reasons.append("no HTTPS")

    if url_f.get("dns_resolves") is False:
        score += 5
        reasons.append("domain does not resolve")

    # ---- page signals ----
    if content_f.get("brand_mismatch") is True:
        score += 30
        reasons.append(f"page pretends to be "
                       f"'{content_f.get('claimed_brand')}'")

    if content_f.get("password_fields", 0) > 0 and url_f.get("has_https") is False:
        score += 15
        reasons.append("asks for a password over a non-secure connection")

    if content_f.get("form_actions_external") is True:
        score += 20
        reasons.append("login form sends data to a different website")

    if content_f.get("suspicious_js"):
        score += 15
        reasons.append(f"hides code ({', '.join(content_f['suspicious_js'][:2])})")

    if content_f.get("meta_refresh") is True:
        score += 10
        reasons.append("silently redirects to another page")

    if content_f.get("suspicious_path_words"):
        score += 2
        reasons.append(f"URL path has login-ish word: "
                       f"{', '.join(content_f['suspicious_path_words'])}")

    # ---- email signals ----
    if email_f:
        auth = email_f.get("auth", {})
        if auth.get("spf") == "fail":
            score += 20
            reasons.append("sender failed SPF check (email may be spoofed)")
        if auth.get("dkim") in ("fail", "none"):
            score += 15
            reasons.append(f"DKIM: {auth.get('dkim')}")
        if auth.get("dmarc") == "fail":
            score += 20
            reasons.append("sender failed DMARC check")

        if email_f.get("sender_mismatch"):
            score += 20
            reasons.append("reply-to address differs from sender")

        if email_f.get("urgency_words"):
            score += 10
            reasons.append(f"urgent language: "
                           f"{', '.join(email_f['urgency_words'][:3])}")

        if email_f.get("threat_words"):
            score += 10
            reasons.append(f"threatening language: "
                           f"{', '.join(email_f['threat_words'][:3])}")

        if email_f.get("generic_greeting"):
            score += 5
            reasons.append("generic greeting (not personalized)")

        if email_f.get("link_text_mismatch"):
            score += 25
            reasons.append("link text doesn't match where it actually goes")

        if email_f.get("sender_ip_blocklisted"):
            score += 25
            reasons.append(f"sender IP is on a spam blocklist "
                           f"({email_f.get('sender_ip_blocklisted')})")

    # ---- TLS cert signals ----
    tls = (url_f.get("tls") or {})
    if tls.get("age_days") is not None:
        if tls["age_days"] < 3:
            score += 10
            reasons.append(f"TLS certificate issued {tls['age_days']} days ago")
        elif tls["age_days"] < 30:
            score += 5
            reasons.append(f"TLS certificate is {tls['age_days']} days old")

    # ---- reputation ----
    for r in rep_results:
        if r.get("flagged") is True:
            score += 40
            reasons.append(f"{r['service']}: {r['note']}")

    return min(100, score), reasons


def verdict_from_score(score):
    if score >= 60:
        return "phish"
    if score >= 25:
        return "suspicious"
    return "clean"


# ============ RENDERERS ============

def render_url(url_f):
    """compact two-column items from url findings"""
    items = []
    # https
    if url_f.get("has_https"):
        items.append(("ok", "Uses HTTPS"))
    else:
        items.append(("bad", "No HTTPS"))

    # tld - accurate label, no false "safe" claim
    tld = url_f.get("tld") or "?"
    if url_f.get("tld_suspicious"):
        items.append(("bad", f"TLD: {tld} (commonly abused)"))
    else:
        items.append(("ok", f"TLD: {tld} (not commonly abused)"))

    # homoglyph
    if url_f.get("has_homoglyph"):
        items.append(("bad", "Fake lookalike chars"))
    else:
        items.append(("ok", "No fake chars"))

    # typosquat - spell out what was checked
    if url_f.get("typosquat_brand") and url_f.get("typosquat_score", 0) >= 60:
        items.append(("bad",
                     f"Impersonates {url_f['typosquat_brand']} "
                     f"({url_f['typosquat_score']}% match)"))
    else:
        items.append(("ok", "No brand impersonation detected"))

    # redirects
    hops = url_f.get("redirects") or []
    if hops:
        items.append(("warn", f"{len(hops)} redirect(s)"))
    else:
        items.append(("ok", "No redirects"))

    # domain age
    age = url_f.get("domain_age_days")
    if age is None:
        items.append(("info", "Domain age unknown"))
    elif age < 30:
        items.append(("bad", f"New domain ({age}d)"))
    elif age < 90:
        items.append(("warn", f"Young domain ({age}d)"))
    else:
        items.append(("ok", f"Old domain ({age}d)"))

    # dns
    if url_f.get("dns_resolves"):
        items.append(("ok", "Domain resolves"))
    else:
        items.append(("warn", "Does not resolve"))

    return items


def render_content(content_f):
    items = []
    if not content_f.get("fetched"):
        items.append(("warn", "Could not load page"))
        return items

    items.append(("ok", f"Page loads ({content_f.get('status_code')})"))

    if content_f.get("password_fields"):
        items.append(("warn", "Has password field"))
    else:
        items.append(("ok", "No password field"))

    if content_f.get("form_actions_external"):
        items.append(("bad", "Form sends data elsewhere"))
    else:
        items.append(("ok", "Form stays on site"))

    if content_f.get("brand_mismatch"):
        items.append(("bad",
                     f"Pretends to be {content_f.get('claimed_brand')}"))
    else:
        items.append(("ok", "No fake brand"))

    if content_f.get("suspicious_js"):
        items.append(("warn", "Hidden code"))
    else:
        items.append(("ok", "No hidden code"))

    if content_f.get("meta_refresh"):
        items.append(("warn", "Auto-redirects"))
    else:
        items.append(("ok", "No auto-redirect"))

    return items


def render_reputation(rep_results):
    items = []
    short_map = {
        "URLScan.io": "URLScan",
        "OpenPhish": "OpenPhish",
        "URLhaus": "URLhaus",
        "Google Safe Browsing": "Google SB",
    }
    # per-service wording - "clean" means different things in different DBs
    CLEAN_LABEL = {
        "URLScan.io": "No malicious detections",
        "OpenPhish": "Not listed",
        "URLhaus": "Not listed",
        "Google Safe Browsing": "Not flagged",
    }
    FLAG_LABEL = {
        "URLScan.io": "Malicious detections found",
        "OpenPhish": "Listed in feed",
        "URLhaus": "Listed as malware",
        "Google Safe Browsing": "Flagged as unsafe",
    }
    for r in rep_results:
        name = short_map.get(r.get("service"), r.get("service", "?"))
        flagged = r.get("flagged")
        avail = r.get("available")
        note = r.get("note", "")
        svc = r.get("service", "")
        if not avail:
            if "key" in note.lower():
                items.append(("info", f"{name}: Requires API key"))
            elif "unavailable" in note.lower():
                items.append(("info", f"{name}: Service unavailable"))
            else:
                items.append(("info", f"{name}: {note[:30]}"))
        elif flagged is True:
            label = FLAG_LABEL.get(svc, "Flagged")
            items.append(("bad", f"{name}: {label}"))
        elif flagged is False:
            label = CLEAN_LABEL.get(svc, "No detections")
            items.append(("ok", f"{name}: {label}"))
        else:
            items.append(("warn", f"{name}: Unable to determine"))
    return items


def render_email(email_f):
    """returns dict of section_name -> items list"""
    sections = {}

    # EMAIL HEADERS
    hdr = []
    frm = email_f.get("from", "unknown")
    hdr.append(("info", f"From: {(frm or 'unknown')[:40]}"))
    if email_f.get("reply_to") and email_f.get("sender_mismatch"):
        hdr.append(("bad", f"Reply-to: {email_f['reply_to'][:35]}"))
    elif email_f.get("reply_to"):
        hdr.append(("ok", f"Reply-to matches sender"))
    if email_f.get("subject"):
        hdr.append(("info", f"Subject: {email_f['subject'][:45]}"))
    sections["EMAIL"] = hdr

    # AUTHENTICATION
    auth = []
    a = email_f.get("auth", {})
    spf = (a.get("spf") or "unknown").lower()
    dkim = (a.get("dkim") or "unknown").lower()
    dmarc = (a.get("dmarc") or "unknown").lower()

    def auth_state(r):
        if r in ("pass", "ok"): return "ok"
        if r in ("fail", "error"): return "bad"
        if r in ("none", "missing"): return "bad"
        return "info"

    auth.append((auth_state(spf), f"SPF: {spf}"))
    auth.append((auth_state(dkim), f"DKIM: {dkim}"))
    auth.append((auth_state(dmarc), f"DMARC: {dmarc}"))
    sections["AUTHENTICATION"] = auth

    # LANGUAGE
    lang = []
    if email_f.get("urgency_words"):
        lang.append(("warn",
                     f"Urgent words: {', '.join(email_f['urgency_words'][:3])}"))
    else:
        lang.append(("ok", "No urgent language"))
    if email_f.get("threat_words"):
        lang.append(("warn",
                     f"Threats: {', '.join(email_f['threat_words'][:3])}"))
    else:
        lang.append(("ok", "No threats"))
    if email_f.get("generic_greeting"):
        lang.append(("warn", "Generic greeting"))
    sections["LANGUAGE"] = lang

    # ATTACHMENTS
    atts = email_f.get("attachments") or []
    if atts:
        att_items = []
        for att in atts[:10]:
            nm = att.get("filename", "?")[:30]
            sz = att.get("size", 0)
            if sz > 1024 * 1024:
                szs = f"{sz // (1024*1024)} MB"
            elif sz > 1024:
                szs = f"{sz // 1024} KB"
            else:
                szs = f"{sz} B"
            att_items.append(("info", f"{nm} ({szs})"))
        sections["ATTACHMENTS"] = att_items
    else:
        sections["ATTACHMENTS"] = [("ok", "No attachments")]

    # URLS IN BODY
    urls = email_f.get("urls") or []
    if urls:
        url_items = []
        for u, short_kind in urls[:15]:
            state = "bad" if short_kind == "shortener" else "info"
            prefix = "[short]" if short_kind == "shortener" else ""
            url_items.append((state, f"{prefix} {u[:70]}"))
        sections["LINKS IN EMAIL"] = url_items

    return sections


# ============ TOP-LEVEL ============



def render_shortener(url, exp):
    """render the redirect chain for a shortener URL"""
    chain = format_chain(exp)
    if not chain:
        return [("info", "no chain")]
    items = []
    for depth, hop in chain:
        prefix = "  " * depth + ("└─ " if depth > 0 else "")
        # cap at 55 to be safe on any width
        short_hop = hop if len(hop) <= 55 else hop[:52] + "..."
        if depth == 0:
            items.append(("info", f"[shortener] {short_hop}"))
        else:
            items.append(("warn", f"→ {short_hop}"))
    if exp.get("error"):
        items.append(("bad", f"error: {exp['error']}"))
    return items




def render_js(js_data):
    """compact items for javascript analysis"""
    items = []
    count = js_data.get("script_count", 0)
    if count == 0:
        items.append(("ok", "No scripts"))
        return items
    items.append(("info", f"{count} script(s)"))

    inl = js_data.get("inline_script_count", 0)
    ext = js_data.get("external_script_count", 0)
    if inl:
        items.append(("info", f"{inl} inline"))
    if ext:
        items.append(("info", f"{ext} external"))

    if js_data.get("redirect_patterns"):
        for p in js_data["redirect_patterns"][:2]:
            items.append(("warn", f"JS redirect: {p}"))
    else:
        items.append(("ok", "No JS redirects"))

    urls = js_data.get("urls_in_js", [])
    if urls:
        items.append(("info", f"{len(urls)} URL(s) in JS"))
    else:
        items.append(("ok", "No URLs in JS"))

    b64 = js_data.get("base64_blobs", [])
    if b64:
        items.append(("warn", f"{len(b64)} base64 blob(s)"))
    else:
        items.append(("ok", "No base64 blobs"))

    hexes = js_data.get("obfuscated_strings", [])
    if hexes:
        items.append(("warn", f"{len(hexes)} hex-encoded string(s)"))
    return items




def render_tls(host):
    """returns (items, cert_dict)"""
    return analyze_tls(host)




def run_sms_check(raw):
    """analyze an SMS / WhatsApp message for smishing."""
    from modules.smishing import (
        analyze_message, compute_smishing_score, verdict_from_score
    )

    print()
    print(f"  {C.GREY}analyzing message{C.RESET}")
    print()

    prog = Progress()
    prog.start("parsing message")
    analysis = analyze_message(raw)
    prog.ok(f"parsed ({analysis['length']} chars)")

    prog.start("matching patterns")
    cats = analysis.get("categories", {})
    prog.ok(f"{len(cats)} pattern categories matched")

    prog.start("analyzing links")
    links = analysis.get("urls", [])
    if links:
        prog.ok(f"{len(links)} link(s) found")
    else:
        prog.ok("no links")

    prog.start("scoring")
    score, reasons = compute_smishing_score(analysis)
    prog.ok(f"score: {score}/100")

    v = verdict_from_score(score)

    # adapt verdict for header block
    verdict_map = {
        "smishing": "phish",
        "suspicious": "suspicious",
        "clean": "clean",
    }
    v_display = verdict_map.get(v, "unknown")

    # compute a naive confidence
    conf = 100
    if not links:
        conf -= 15
    if not analysis.get("banks_mentioned") and not analysis.get("agencies_mentioned"):
        conf -= 10
    conf = max(30, conf)

    header_block("(SMS / WhatsApp message)", v_display, score, conf)

    # ---- WHY ----
    if reasons:
        section("WHY")
        print()
        stacked([("bad" if v == "smishing" else "warn", r) for r in reasons])
        print()

    # ---- MESSAGE DETAILS ----
    section("MESSAGE ANALYSIS")
    print()
    details = []
    if analysis["phone_numbers"]:
        details.append(("warn", f"Phone number(s): {', '.join(analysis['phone_numbers'])}"))
    if analysis["account_numbers"]:
        details.append(("warn", f"Account number(s): {', '.join(analysis['account_numbers'])}"))
    if analysis["amounts"]:
        details.append(("info", f"Amount(s): NGN " + ", ".join(analysis["amounts"])))
    if analysis["banks_mentioned"]:
        details.append(("info", f"Banks: {', '.join(analysis['banks_mentioned'])}"))
    if analysis["telcos_mentioned"]:
        details.append(("info", f"Telcos: {', '.join(analysis['telcos_mentioned'])}"))
    if analysis["agencies_mentioned"]:
        details.append(("info", f"Agencies: {', '.join(analysis['agencies_mentioned'])}"))
    if not details:
        details.append(("ok", "No structural patterns detected"))
    stacked(details)
    print()

    # ---- LINKS ----
    if links:
        section("LINKS")
        print()
        for u, kind in links:
            if kind == "shortener":
                print(f"    {C.YELLOW}[short]{C.RESET} {C.WHITE}{u[:70]}{C.RESET}")
            else:
                print(f"    {C.GREY}[link] {C.RESET} {C.WHITE}{u[:70]}{C.RESET}")
        print()
        # expand shorteners
        from modules.shortener import is_shortener, expand
        for u, kind in links[:3]:
            if is_shortener(u):
                exp = expand(u)
                if exp.get("final") and exp["final"] != u:
                    print(f"    {C.YELLOW}→{C.RESET}  {C.WHITE}{exp['final'][:70]}{C.RESET}")
        print()

    # ---- CATEGORIES ----
    if cats:
        section("PATTERN MATCHES")
        print()
        items = []
        for cat, info in cats.items():
            state = "bad" if info["severity"] == "high" else "warn"
            name = cat.replace("_", " ").title()
            kws = ", ".join(info["keywords"][:3])
            items.append((state, f"{name}: {kws}"))
        stacked(items)
        print()




def render_visual_clone(matches):
    """matches: list of (brand, scores) or an error string."""
    items = []
    if isinstance(matches, str):
        items.append(("info", f"skip: {matches}"))
        return items, None, None
    if not matches:
        items.append(("ok", "No brand clone detected"))
        return items, None, None
    top_brand, top_scores = matches[0]
    score = top_scores.get("score", 0)
    if score >= 70:
        items.append(("bad", f"High similarity with {top_brand} ({score:.0f}%)"))
    elif score >= 50:
        items.append(("warn", f"Medium similarity with {top_brand} ({score:.0f}%)"))
    else:
        items.append(("info", f"Low similarity with {top_brand} ({score:.0f}%)"))
    items.append(("info", f"  classes {top_scores.get('classes',0):.0f}%  "
                         f"colors {top_scores.get('colors',0):.0f}%"))
    items.append(("info", f"  images {top_scores.get('images',0):.0f}%  "
                         f"fonts {top_scores.get('fonts',0):.0f}%  "
                         f"layout {top_scores.get('layout',0):.0f}%"))
    return items, top_brand, top_scores


def run_url_check(url):
    print()
    print(f"  {C.GREY}analyzing{C.RESET} {C.WHITE}{url}{C.RESET}")
    print()

    prog = Progress()

    prog.start("parsing URL")
    url_f = analyze_url(url)
    prog.ok("URL parsed")

    prog.start("fetching page")
    content_f = analyze_content(url)
    if content_f.get("fetched"):
        prog.ok(f"page fetched ({content_f.get('content_length')} bytes)")
    else:
        prog.fail("page could not be loaded")

    prog.start("checking reputation")
    rep = check_all(url)
    # v7.13: domain-level reputation is more stable than per-URL.
    # A phishing domain may be flagged at the root while a specific path is not.
    base = _base_url(url)
    if base:
        try:
            base_rep = check_all(base)
            rep = _merge_reputation(rep, base_rep)
        except Exception:
            pass
    _, _, avail = rep_summary(rep)
    prog.ok(f"reputation checked ({avail} services answered)")

    # visual clone detection - only if page fetched
    visual_matches = None
    if content_f.get("fetched"):
        prog.start("visual clone detection")
        try:
            visual_matches = check_visual_clone(url)
            if isinstance(visual_matches, str):
                prog.ok("fingerprint skipped")
                visual_matches = None
            elif visual_matches:
                top_brand, top_scores = visual_matches[0]
                prog.ok(f"top match: {top_brand} ({top_scores['score']:.0f}%)")
            else:
                prog.ok("no clone detected")
        except Exception as e:
            prog.fail(f"visual: {type(e).__name__}")
            visual_matches = None

    prog.start("scoring")
    score, reasons = compute_score(url_f, content_f, rep)
    prog.ok(f"score: {score}/100")

    v = verdict_from_score(score)
    conf = compute_confidence(url_f, content_f, rep)
    header_block(url, v, score, conf)

    if reasons:
        section("WHY")
        print()
        stacked([("bad" if v == "phish" else "warn", r) for r in reasons])
        print()

    section("URL SIGNALS")
    print()
    two_col(render_url(url_f))
    print()

    section("PAGE SIGNALS")
    print()
    two_col(render_content(content_f))
    print()

    js = content_f.get("js") or {}
    if js.get("script_count", 0) > 0:
        section("JAVASCRIPT")
        print()
        two_col(render_js(js))
        print()
        if js.get("urls_in_js"):
            # hard cap: 60 chars is safe on any terminal width
            print(f"    {C.GREY}URLs found in JS:{C.RESET}")
            for u in js["urls_in_js"][:5]:
                short = u if len(u) <= 60 else u[:57] + "..."
                print(f"      {C.WHITE}{short}{C.RESET}")
            print()

    # TLS cert analysis
    host = url_f.get("host") or ""
    if host:
        try:
            tls_items, tls_cert = analyze_tls(host)
            if tls_cert.get("available"):
                section("TLS CERTIFICATE")
                print()
                two_col(tls_items)
                print()
        except Exception as e:
            # silently skip if TLS fails - don't break the whole flow
            pass

    section("REPUTATION")
    print()
    stacked(render_reputation(rep))
    print()

    # visual clone detection
    if visual_matches:
        try:
            items, top_brand, top_scores = render_visual_clone(visual_matches)
            if top_scores and top_scores.get("score", 0) >= 50:
                section("VISUAL CLONE")
                print()
                stacked(items)
                print()
        except Exception:
            pass

    # shortener expansion - only if the input URL is a shortener
    if is_shortener(url):
        prog.start("expanding shortener")
        exp = expand(url)
        if exp.get("final") and exp["final"] != url:
            prog.ok("shortener expanded")
        else:
            prog.ok("no expansion found")
        section("SHORTENER EXPANSION")
        print()
        for state, label in render_shortener(url, exp):
            if state == "warn":
                print(f"    {C.YELLOW}→{C.RESET}  {C.WHITE}{label[2:]}{C.RESET}")
            elif state == "bad":
                print(f"    {C.RED}✗{C.RESET}  {C.RED}{label}{C.RESET}")
            else:
                print(f"    {C.GREY}[short]{C.RESET}  {C.WHITE}{label[11:] if label.startswith('[shortener]') else label}{C.RESET}")
        print()

        # analyze final destination if different from input
        if exp.get("final") and exp["final"] != url:
            final_url = exp["final"]
            section("DESTINATION ANALYSIS")
            print()
            print(f"    {C.GREY}analyzing{C.RESET} {C.WHITE}{final_url[:70]}{C.RESET}")
            print()
            final_uf = analyze_url(final_url)
            final_cf = analyze_content(final_url)
            final_rep = check_all(final_url)
            final_score, final_reasons = compute_score(final_uf, final_cf, final_rep)
            final_v = verdict_from_score(final_score)
            if final_v == "phish":
                vtag = f"{C.RED}🔴 PHISHING{C.RESET}"
            elif final_v == "suspicious":
                vtag = f"{C.YELLOW}🟡 SUSPICIOUS{C.RESET}"
            else:
                vtag = f"{C.GREEN}🟢 CLEAN{C.RESET}"
            print(f"    {vtag}  {C.GREY_DIM}risk {final_score}/100{C.RESET}")
            print()
            two_col(render_url(final_uf))
            print()


def run_batch_check(file_path):
    import os
    print()
    print(f"  {C.GREY}batch check{C.RESET} {C.WHITE}{file_path}{C.RESET}")
    print()
    try:
        with open(file_path) as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except Exception as e:
        print(f"  {C.RED}error: {e}{C.RESET}")
        return

    if not urls:
        print(f"  {C.YELLOW}no URLs in file{C.RESET}")
        return

    print(f"  {C.GREY_DIM}{len(urls)} URLs to check{C.RESET}")
    print()

    phish = susp = clean = 0
    for i, u in enumerate(urls, 1):
        print(f"  {C.BLUE}[{i}/{len(urls)}]{C.RESET} {C.GREY}{u[:70]}{C.RESET}")
        url_f = analyze_url(u)
        content_f = analyze_content(u)
        rep = check_all(u)
        score, _ = compute_score(url_f, content_f, rep)
        v = verdict_from_score(score)
        if v == "phish":
            phish += 1
            tag = f"{C.RED}PHISHING{C.RESET}"
        elif v == "suspicious":
            susp += 1
            tag = f"{C.YELLOW}SUSPICIOUS{C.RESET}"
        else:
            clean += 1
            tag = f"{C.GREEN}CLEAN{C.RESET}"
        print(f"           {tag}  {C.GREY_DIM}score {score}/100{C.RESET}")

    print()
    section("SUMMARY")
    print()
    print(f"    {C.RED}phishing   {C.RESET}  {phish}")
    print(f"    {C.YELLOW}suspicious {C.RESET}  {susp}")
    print(f"    {C.GREEN}clean      {C.RESET}  {clean}")
    print(f"    {C.GREY}total      {C.RESET}  {len(urls)}")
    print()


def run_email_check(raw, headers_only=False):
    print()
    print(f"  {C.GREY}analyzing email{C.RESET}")
    print()

    prog = Progress()

    prog.start("parsing email")
    email_f = analyze_email(raw, headers_only=headers_only)
    prog.ok("email parsed")

    prog.start("checking authentication")
    a = email_f.get("auth", {})
    results = [a.get("spf"), a.get("dkim"), a.get("dmarc")]
    passed = sum(1 for r in results if r == "pass")
    prog.ok(f"auth checked ({passed}/3 passed)")

    # URL analysis on any extracted URLs (only if full email, not headers-only)
    url_scores = []
    if not headers_only and email_f.get("urls"):
        prog.start(f"analyzing {len(email_f['urls'])} link(s)")
        for u, _ in email_f["urls"][:5]:
            uf = analyze_url(u)
            cf = analyze_content(u)
            rep = check_all(u)
            base = _base_url(u)
            if base:
                try:
                    base_rep = check_all(base)
                    rep = _merge_reputation(rep, base_rep)
                except Exception:
                    pass
            s, _ = compute_score(uf, cf, rep)
            url_scores.append(s)
        prog.ok("links analyzed")

    prog.start("scoring")
    score, reasons = compute_score({}, {}, [], email_f=email_f)
    if url_scores:
        # blend: email score + url contribution, but never less than the highest URL
        avg_url = sum(url_scores) / len(url_scores)
        blended = min(100, int(score + avg_url * 0.5))
        blended = max(blended, int(avg_url))
        score = blended
    prog.ok(f"score: {score}/100")

    v = verdict_from_score(score)
    conf = compute_confidence({}, {}, [], email_f=email_f)
    header_block(email_f.get("from") or "unknown sender", v, score, conf)

    if reasons:
        section("WHY")
        print()
        stacked([("bad" if v == "phish" else "warn", r) for r in reasons])
        print()

    sections = render_email(email_f)
    for sec_name, items in sections.items():
        section(sec_name)
        print()
        if sec_name in ("EMAIL", "LINKS IN EMAIL"):
            stacked(items)
        else:
            two_col(items)
        print()
