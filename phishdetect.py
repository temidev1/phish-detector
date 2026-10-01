#!/usr/bin/env python3
"""
phish-detector — defensive phishing URL + email analyzer
v0.7 · Built by Maverick
"""

import sys
import os
import re
import time
import logging

# silence third-party library noise
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)
from pathlib import Path
from datetime import datetime


# ============ PALETTE ============
class C:
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"

    BLUE        = "\033[38;5;39m"
    BLUE_DARK   = "\033[38;5;33m"
    BLUE_DEEP   = "\033[38;5;25m"
    BLUE_DIM    = "\033[38;5;60m"

    RED         = "\033[38;5;203m"
    RED_DARK    = "\033[38;5;160m"
    RED_DIM     = "\033[38;5;95m"

    YELLOW      = "\033[38;5;221m"
    GREEN       = "\033[38;5;77m"
    GREEN_DARK  = "\033[38;5;35m"

    GREY        = "\033[38;5;245m"
    GREY_DIM    = "\033[38;5;240m"
    GREY_DEEP   = "\033[38;5;236m"
    WHITE       = "\033[38;5;255m"
    WHITE_SOFT  = "\033[38;5;252m"


def supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


if not supports_color():
    for attr in dir(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")


ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def vlen(s):
    return len(ANSI_RE.sub("", s))


def pad(s, width, align="left"):
    n = width - vlen(s)
    if n < 0:
        s = ANSI_RE.sub("", s)[:width]
        n = 0
    if align == "center":
        l = n // 2
        r = n - l
        return " " * l + s + " " * r
    if align == "right":
        return " " * n + s
    return s + " " * n


# ============ TERMINAL WIDTH ============
def term_width():
    try:
        return os.get_terminal_size().columns
    except (OSError, ValueError, AttributeError):
        return 80


def center_line(text):
    """print text centered on terminal width"""
    w = term_width()
    print(pad(text, w, "center"))


# ============ BOX PRIMITIVES ============
def box_top(width, color=None):
    color = color or C.BLUE
    return f"{color}╔{'═' * (width - 2)}╗{C.RESET}"


def box_bot(width, color=None):
    color = color or C.BLUE
    return f"{color}╚{'═' * (width - 2)}╝{C.RESET}"


def box_mid(width, color=None):
    color = color or C.BLUE
    return f"{color}╠{'═' * (width - 2)}╣{C.RESET}"


def box_row(content, width, color=None, align="left"):
    color = color or C.BLUE
    inner = width - 4
    return f"{color}║{C.RESET} {pad(content, inner, align)} {color}║{C.RESET}"


def center_box(width):
    """return number of spaces to indent so box is centered"""
    tw = term_width()
    if width >= tw:
        return 0
    return (tw - width) // 2


# ============ BANNER (CENTERED) ============
def banner():
    w = term_width()
    print()
    logo = [
        "██████╗ ██╗  ██╗██╗███████╗██╗  ██╗",
        "██╔══██╗██║  ██║██║██╔════╝██║  ██║",
        "██████╔╝███████║██║███████╗███████║",
        "██╔═══╝ ██╔══██║██║╚════██║██╔══██║",
        "██║     ██║  ██║██║███████║██║  ██║",
        "╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝",
    ]
    for line in logo:
        print(pad(f"{C.BLUE}{line}{C.RESET}", w, "center"))
    print()
    print(pad(f"{C.BOLD}{C.WHITE}D E T E C T O R{C.RESET}", w, "center"))
    print(pad(f"{C.GREY_DIM}{'─' * 32}{C.RESET}", w, "center"))
    print()
    # aligned metadata block — both lines same width, so they align as columns
    line1 = f"{C.BLUE}{C.BOLD}v0.7{C.RESET}     {C.GREY_DIM}defensive phishing analyzer{C.RESET}"
    line2 = (f"{C.BLUE}{C.BOLD}built by{C.RESET} "
             f"{C.BLUE}{C.BOLD}Maverick{C.RESET}     "
             f"{C.GREY_DIM}github.com/temidev1/phish-detector{C.RESET}")
    print(pad(line1, w, "center"))
    print(pad(line2, w, "center"))
    print()


# ============ SECTION HEADERS (CENTERED) ============
def section(title, subtitle=None):
    print()
    print(f"  {C.BLUE}▎{C.RESET} {C.BOLD}{C.WHITE}{title.upper()}{C.RESET}")
    if subtitle:
        print(f"    {C.GREY_DIM}{subtitle}{C.RESET}")
    print()


# ============ MENU (CENTERED) ============
def show_menu():
    width = 68
    indent = center_box(width)
    ind = " " * indent

    print()
    print(ind + box_top(width))
    print(ind + box_row(
        f"{C.BOLD}{C.BLUE}MAIN MENU{C.RESET}", width, align="center"
    ))
    print(ind + box_mid(width))
    print(ind + box_row("", width))

    rows = [
        ("1", "Check a URL", "analyze a single link"),
        ("2", "Check a batch", "feed a list of URLs"),
        ("3", "Check an email", "paste full raw source"),
        ("4", "Check headers", "sender authenticity only"),
        ("5", "Check a message", "SMS / WhatsApp smishing"),
    ]
    for num, label, hint in rows:
        line = (f"{C.BLUE}[{num}]{C.RESET}  "
                f"{C.WHITE}{pad(label, 22)}{C.RESET}"
                f"{C.GREY_DIM}{hint}{C.RESET}")
        print(ind + box_row(line, width))

    print(ind + box_row("", width))
    print(ind + box_mid(width))

    rows2 = [
        ("6", "Settings", "output, alerts, defaults"),
        ("7", "About", "version + credits"),
        ("8", "Exit", "close phish-detector"),
    ]
    for num, label, hint in rows2:
        line = (f"{C.BLUE}[{num}]{C.RESET}  "
                f"{C.WHITE}{pad(label, 22)}{C.RESET}"
                f"{C.GREY_DIM}{hint}{C.RESET}")
        print(ind + box_row(line, width))

    print(ind + box_bot(width))


# ============ VERDICT BAND (CENTERED) ============
def verdict_band(level, confidence=None, timestamp=None, url=None):
    width = 70
    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M")

    if level == "phish":
        color, icon, label = C.RED, "🔴", "PHISHING"
    elif level == "suspicious":
        color, icon, label = C.YELLOW, "🟡", "SUSPICIOUS"
    elif level == "clean":
        color, icon, label = C.GREEN, "🟢", "CLEAN"
    else:
        color, icon, label = C.GREY, "⚪", "UNKNOWN"

    conf_str = f"confidence {confidence}%" if confidence is not None else ""
    left = f"{icon}  {C.BOLD}{label}{C.RESET}"

    print()
    print(f"  {color}╔{'═' * (width - 4)}╗{C.RESET}")
    print(f"  {color}║{C.RESET}  {pad(left, width - 8)}  {color}║{C.RESET}")
    if url:
        print(f"  {color}║{C.RESET}  {C.GREY}{pad(url[:width-10], width - 8)}{C.RESET}  {color}║{C.RESET}")
    if conf_str:
        print(f"  {color}║{C.RESET}  {C.WHITE}{pad(conf_str, width - 8)}{C.RESET}  {color}║{C.RESET}")
    print(f"  {color}║{C.RESET}  {C.GREY_DIM}{pad(ts, width - 8)}{C.RESET}  {color}║{C.RESET}")
    print(f"  {color}╚{'═' * (width - 4)}╝{C.RESET}")
    print()


# ============ CHECKLIST (CENTERED) ============
def checklist(title, items):
    if title:
        print()
        print(f"  {C.BLUE}▎{C.RESET} {C.BOLD}{C.WHITE}{title.upper()}{C.RESET}")
    for state, key, value in items:
        if state == "ok":
            mark = f"{C.GREEN}✓{C.RESET}"
            vcolor = C.WHITE_SOFT
        elif state == "warn":
            mark = f"{C.YELLOW}⚠{C.RESET}"
            vcolor = C.YELLOW
        elif state == "bad":
            mark = f"{C.RED}✗{C.RESET}"
            vcolor = C.RED
        else:
            mark = f"{C.GREY}·{C.RESET}"
            vcolor = C.GREY
        print(f"    {mark}  {C.GREY}{pad(key, 26)}{C.RESET} {vcolor}{value}{C.RESET}")


# ============ SPINNER (CENTERED OUTPUT) ============
SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Progress:
    def __init__(self):
        self.i = 0
        self.last = ""

    def start(self, msg):
        self.last = msg
        f = SPIN[self.i % len(SPIN)]
        print(f"\r    {C.BLUE}{f}{C.RESET}  {C.GREY}{msg}...{C.RESET}                ",
              end="", flush=True)
        self.i += 1

    def ok(self, msg=None):
        m = msg or self.last
        print(f"\r    {C.GREEN}✓{C.RESET}  {C.GREY}{m}{C.RESET}                ")

    def fail(self, msg=None):
        m = msg or self.last
        print(f"\r    {C.RED}✗{C.RESET}  {C.GREY}{m}{C.RESET}                ")


# ============ DISPATCHER ============
def prompt(label):
    return input(f"  {C.BLUE}{label}{C.RESET} ❯ ")


def run_check_url():
    from modules.report import run_url_check
    url = prompt("url").strip()
    if not url:
        print()
        center_line(f"{C.YELLOW}no URL provided{C.RESET}")
        print()
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    run_url_check(url)


def run_check_batch():
    from modules.report import run_batch_check
    fp = prompt("file").strip()
    if not fp:
        return
    fp = os.path.expanduser(fp)
    if not Path(fp).exists():
        print()
        center_line(f"{C.RED}✗ not found: {fp}{C.RESET}")
        print()
        return
    run_batch_check(fp)


def _read_multiline(prompt_text):
    print()
    center_line(f"{C.GREY_DIM}{prompt_text}{C.RESET}")
    center_line(f"{C.GREY_DIM}end with a line containing only '---END---'{C.RESET}")
    print()
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().lower() in ("---end---", "--end--", "end"):
            break
        lines.append(line)
    return "\n".join(lines)


def run_check_email():
    from modules.report import run_email_check
    raw = _read_multiline("paste the raw email (headers + body)")
    if raw.strip():
        run_email_check(raw, headers_only=False)


def run_check_headers():
    from modules.report import run_email_check
    raw = _read_multiline("paste raw email headers")
    if raw.strip():
        run_email_check(raw, headers_only=True)




def run_check_sms():
    from modules.report import run_sms_check
    raw = _read_multiline("paste the SMS or WhatsApp message")
    if raw.strip():
        run_sms_check(raw)



def run_settings():
    while True:
        section("Settings")
        submenu = [
            ("1", "API keys", "view and update service keys"),
            ("2", "Cache", "stats and clear"),
            ("3", "Output", "display preferences"),
            ("4", "About the tool", ""),
            ("5", "Back to main menu", ""),
        ]
        for num, name, hint in submenu:
            print(f"    {C.BLUE}[{num}]{C.RESET}  "
                  f"{C.WHITE}{pad(name, 18)}{C.RESET}"
                  f"{C.GREY_DIM}{hint}{C.RESET}")
        print()
        try:
            choice = input(f"  {C.BLUE}❯{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice == "1":
            run_settings_keys()
        elif choice == "2":
            run_settings_cache()
        elif choice == "3":
            print()
            print(f"    {C.GREY}output            {C.RESET}{C.WHITE}terminal{C.RESET}")
            print(f"    {C.GREY}color             {C.RESET}{C.WHITE}auto{C.RESET}")
            print(f"    {C.GREY}save reports      {C.RESET}{C.GREY_DIM}disabled (v0.9){C.RESET}")
            print()
        elif choice == "4":
            run_about()
        elif choice == "5":
            return
        else:
            print(f"  {C.RED}invalid choice{C.RESET}")

    # ensure config file is 600 on exit
    try:
        from modules.config import secure_config_file
        secure_config_file()
    except Exception:
        pass


def run_settings_keys():
    from modules.config import load, redacted, set_key, get_key
    while True:
        print()
        section("API Keys")
        print()
        cfg = load()
        rows = [
            ("GSB", "Google Safe Browsing", "gsb_api_key"),
            ("VT",  "VirusTotal",           "vt_api_key"),
            ("URLhaus", "URLhaus (abuse.ch)", "urlhaus_auth_key"),
            ("Hybrid", "Hybrid Analysis",   "hybrid_api_key"),
        ]
        for short, name, key in rows:
            v = cfg.get(key, "")
            if v:
                masked = v[:6] + "..." + v[-4:] if len(v) > 12 else "(set)"
                status = f"{C.GREEN}✓ {masked}{C.RESET}"
            else:
                status = f"{C.GREY_DIM}(empty){C.RESET}"
            print(f"    {C.GREY}{pad(name, 24)}{C.RESET} {status}")
        print()
        print(f"    {C.BLUE}[1]{C.RESET} {C.WHITE}set GSB key{C.RESET}")
        print(f"    {C.BLUE}[2]{C.RESET} {C.WHITE}set VirusTotal key{C.RESET}")
        print(f"    {C.BLUE}[3]{C.RESET} {C.WHITE}set URLhaus key{C.RESET}")
        print(f"    {C.BLUE}[4]{C.RESET} {C.WHITE}set Hybrid Analysis key{C.RESET}")
        print(f"    {C.BLUE}[5]{C.RESET} {C.WHITE}clear a key{C.RESET}")
        print(f"    {C.BLUE}[6]{C.RESET} {C.WHITE}back{C.RESET}")
        print()
        try:
            choice = input(f"  {C.BLUE}❯{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        key_map = {
            "1": ("gsb_api_key", "GSB API key"),
            "2": ("vt_api_key", "VirusTotal API key"),
            "3": ("urlhaus_auth_key", "URLhaus Auth-Key"),
            "4": ("hybrid_api_key", "Hybrid Analysis API key"),
        }
        if choice in key_map:
            cfg_key, label = key_map[choice]
            try:
                val = input(f"  {C.BLUE}{label}{C.RESET} ❯ ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if val:
                set_key(cfg_key, val)
                print(f"  {C.GREEN}✓ saved{C.RESET}")
        elif choice == "5":
            try:
                which = input(f"  {C.BLUE}which key? [1-4]{C.RESET} ❯ ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if which in key_map:
                cfg_key, label = key_map[which]
                set_key(cfg_key, "")
                print(f"  {C.GREEN}✓ cleared {label}{C.RESET}")
        elif choice == "6":
            return
        else:
            print(f"  {C.RED}invalid choice{C.RESET}")


def run_settings_cache():
    from modules import cache
    print()
    section("Cache")
    print()
    s = cache.stats()
    print(f"    {C.GREY}{pad('entries', 20)}{C.RESET} {C.WHITE}{s['entries']}{C.RESET}")
    print(f"    {C.GREY}{pad('size', 20)}{C.RESET} {C.WHITE}{s['size_bytes']} bytes{C.RESET}")
    print(f"    {C.GREY}{pad('path', 20)}{C.RESET} {C.GREY_DIM}{s['path']}{C.RESET}")
    if s['services']:
        print(f"    {C.GREY}per-service:{C.RESET}")
        for svc, n in s['services'].items():
            print(f"      {C.GREY_DIM}{svc:14s}{C.RESET} {C.WHITE}{n}{C.RESET}")
    print()
    print(f"    {C.BLUE}[1]{C.RESET} {C.WHITE}prune expired entries{C.RESET}")
    print(f"    {C.BLUE}[2]{C.RESET} {C.WHITE}clear entire cache{C.RESET}")
    print(f"    {C.BLUE}[3]{C.RESET} {C.WHITE}back{C.RESET}")
    print()
    try:
        choice = input(f"  {C.BLUE}❯{C.RESET} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if choice == "1":
        n = cache.prune_expired()
        print(f"  {C.GREEN}✓ removed {n} expired entries{C.RESET}")
    elif choice == "2":
        cache.clear()
        print(f"  {C.GREEN}✓ cache cleared{C.RESET}")


def run_about():
    section("About")
    rows = [
        ("name", "phish-detector"),
        ("version", "v0.7"),
        ("built by", "Maverick"),
        ("repo", "github.com/temidev1/phish-detector"),
    ]
    for k, v in rows:
        color = C.BLUE if k == "repo" else C.WHITE
        print(f"    {C.GREY}{pad(k, 24)}{C.RESET} {color}{v}{C.RESET}")
    print()


# ============ MAIN ============
def main():
    # ensure config file is 600 at startup
    try:
        from modules.config import secure_config_file
        secure_config_file()
    except Exception:
        pass
    banner()
    while True:
        show_menu()
        try:
            choice = input(f"\n  {C.BLUE}❯{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "1":
            run_check_url()
        elif choice == "2":
            run_check_batch()
        elif choice == "3":
            run_check_email()
        elif choice == "4":
            run_check_headers()
        elif choice == "5":
            run_check_sms()
        elif choice == "6":
            run_settings()
        elif choice == "7":
            run_about()
        elif choice == "8":
            print()
            center_line(f"{C.BLUE}👋 goodbye.{C.RESET}")
            print()
            break
        else:
            print()
            center_line(f"{C.RED}invalid choice{C.RESET}")
            print()


if __name__ == "__main__":
    main()
