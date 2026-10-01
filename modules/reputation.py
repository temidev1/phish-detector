"""
phish-detector · reputation
aggregates all reputation sources.
"""

from modules.config import is_enabled, get_key

from modules import urlscan_free
from modules import openphish_free


def _try(name, fn):
    """call a client, catch import/runtime errors"""
    try:
        return fn()
    except Exception as e:
        return {
            "service": name,
            "available": False,
            "flagged": None,
            "note": f"error: {type(e).__name__}",
        }


def check_all(url):
    results = []

    # free sources — always on
    results.append(_try("URLScan.io", lambda: urlscan_free.check(url)))
    results.append(_try("OpenPhish", lambda: openphish_free.check(url)))

    # keyed — GSB
    if is_enabled("gsb") and get_key("gsb"):
        try:
            from modules.gsb import check as gsb_check
            results.append(_try("Google Safe Browsing", lambda: gsb_check(url)))
        except ImportError:
            results.append({"service": "Google Safe Browsing",
                            "available": False, "flagged": None,
                            "note": "module missing"})
    else:
        results.append({"service": "Google Safe Browsing",
                        "available": False, "flagged": None,
                        "note": "requires API key"})

    # keyed — VirusTotal
    if is_enabled("virustotal") and get_key("vt"):
        try:
            from modules.virustotal import check as vt_check
            results.append(_try("VirusTotal", lambda: vt_check(url)))
        except ImportError:
            results.append({"service": "VirusTotal",
                            "available": False, "flagged": None,
                            "note": "module missing"})
    else:
        results.append({"service": "VirusTotal",
                        "available": False, "flagged": None,
                        "note": "requires API key"})

    # keyed — URLhaus
    if is_enabled("urlhaus") and get_key("urlhaus"):
        try:
            from modules.urlhaus_keyed import check as uh_check
            results.append(_try("URLhaus", lambda: uh_check(url)))
        except ImportError:
            results.append({"service": "URLhaus",
                            "available": False, "flagged": None,
                            "note": "module missing"})
    else:
        results.append({"service": "URLhaus",
                        "available": False, "flagged": None,
                        "note": "requires API key"})

    return results


def summary(results):
    flagged = sum(1 for r in results if r.get("flagged") is True)
    checked = sum(1 for r in results if r.get("flagged") is not None)
    available = sum(1 for r in results if r.get("available"))
    return flagged, checked, available
