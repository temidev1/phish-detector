"""
phish-detector · tls
fetches the TLS certificate and analyzes it for phishing indicators.
"""

import socket
import ssl
from datetime import datetime, timezone


def fetch_certificate(host, port=443, timeout=6):
    """connect to host:port, grab the cert. returns parsed cert data or error."""
    result = {
        "available": False,
        "error": None,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "age_days": None,
        "expires_in_days": None,
        "sans": [],
        "serial": None,
        "version": None,
        "verified": None,
        "protocol": None,
        "cipher": None,
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = f"{cipher[0]} ({cipher[1]}b)"
                result["verified"] = True
                result["available"] = True
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"cert verification failed: {e.verify_message}"
        # try to get the cert anyway (unverified)
        try:
            ctx2 = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["verified"] = False
                    result["available"] = True
        except Exception as e2:
            result["error"] = f"unverified fetch failed: {e2}"
            return result
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    if not result["available"]:
        return result

    # parse issuer
    issuer_parts = []
    for tup in cert.get("issuer", ()):
        for k, v in tup:
            if k == "organizationName":
                issuer_parts.append(v)
            elif k == "commonName":
                issuer_parts.append(v)
    result["issuer"] = " / ".join(issuer_parts) if issuer_parts else "unknown"

    # parse subject
    subj_parts = []
    for tup in cert.get("subject", ()):
        for k, v in tup:
            if k == "commonName":
                subj_parts.append(v)
    result["subject"] = " / ".join(subj_parts) if subj_parts else "unknown"

    # parse dates
    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    now = datetime.now(timezone.utc)

    def _parse_date(s):
        try:
            return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except Exception:
            return None

    if nb:
        d = _parse_date(nb)
        if d:
            result["not_before"] = d.strftime("%Y-%m-%d")
            result["age_days"] = (now - d).days
    if na:
        d = _parse_date(na)
        if d:
            result["not_after"] = d.strftime("%Y-%m-%d")
            result["expires_in_days"] = (d - now).days

    # SANs
    sans = cert.get("subjectAltName", ())
    result["sans"] = [v for (k, v) in sans if k == "DNS"][:20]

    # serial
    result["serial"] = cert.get("serialNumber")

    # cert version
    result["version"] = cert.get("version")

    return result


def analyze_tls(host, port=443):
    """returns list of (state, label) tuples for display."""
    c = fetch_certificate(host, port)
    items = []

    if not c["available"]:
        items.append(("info", f"TLS: not available ({c['error'] or 'unknown'})"))
        return items, c

    # protocol + cipher
    if c["protocol"]:
        proto = c["protocol"]
        if proto in ("TLSv1.3", "TLSv1.2"):
            items.append(("ok", f"Protocol: {proto}"))
        else:
            items.append(("bad", f"Protocol: {proto} (outdated)"))
    else:
        items.append(("info", "Protocol: unknown"))

    # verification
    if c["verified"] is True:
        items.append(("ok", "Certificate verified"))
    elif c["verified"] is False:
        items.append(("bad", "Certificate NOT verified"))

    # issuer
    issuer = c["issuer"] or "unknown"
    if "let's encrypt" in issuer.lower():
        items.append(("info", f"Issuer: {issuer[:40]}"))
    elif "unknown" in issuer.lower():
        items.append(("warn", f"Issuer: {issuer}"))
    else:
        items.append(("ok", f"Issuer: {issuer[:40]}"))

    # age
    age = c["age_days"]
    if age is None:
        items.append(("info", "Cert age: unknown"))
    elif age < 3:
        items.append(("bad", f"Cert age: {age}d (brand new)"))
    elif age < 30:
        items.append(("warn", f"Cert age: {age}d (recent)"))
    else:
        items.append(("ok", f"Cert age: {age}d"))

    # expiry
    exp = c["expires_in_days"]
    if exp is None:
        items.append(("info", "Expires: unknown"))
    elif exp < 0:
        items.append(("bad", "Certificate EXPIRED"))
    elif exp < 7:
        items.append(("warn", f"Expires in {exp}d"))
    else:
        items.append(("ok", f"Expires in {exp}d"))

    # SANs count
    nsan = len(c["sans"])
    if nsan == 0:
        items.append(("warn", "No alternative names"))
    elif nsan == 1:
        items.append(("info", f"1 alternative name"))
    else:
        items.append(("ok", f"{nsan} alternative names"))

    return items, c
