"""
phish-detector · config
manages API keys + persistent settings.
"""

import os
import json
from pathlib import Path


CONFIG_DIR = Path.home() / ".config" / "phish-detector"
CONFIG_FILE = CONFIG_DIR / "keys.json"

DEFAULT = {
    "gsb_api_key": "",
    "vt_api_key": "",
    "urlhaus_auth_key": "",
    "hybrid_api_key": "",
    "enabled_services": {
        "urlscan": True,
        "openphish": True,
        "urlhaus": True,
        "gsb": True,
        "virustotal": True,
    },
}


def _ensure_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load():
    if not CONFIG_FILE.exists():
        return dict(DEFAULT)
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        merged = dict(DEFAULT)
        merged.update(cfg)
        es = dict(DEFAULT["enabled_services"])
        es.update(cfg.get("enabled_services", {}))
        merged["enabled_services"] = es
        return merged
    except Exception:
        return dict(DEFAULT)


def save(cfg):
    _ensure_dir()
    tmp = CONFIG_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(CONFIG_FILE)


def get(key, default=""):
    return load().get(key, default)


def set_key(key, value):
    cfg = load()
    cfg[key] = value
    save(cfg)


def get_key(name):
    env_map = {
        "gsb": "PHISHDETECT_GSB_KEY",
        "vt": "PHISHDETECT_VT_KEY",
        "urlhaus": "PHISHDETECT_ABUSECH_KEY",
        "hybrid": "PHISHDETECT_HYBRID_KEY",
    }
    cfg_map = {
        "gsb": "gsb_api_key",
        "vt": "vt_api_key",
        "urlhaus": "urlhaus_auth_key",
        "hybrid": "hybrid_api_key",
    }
    env_name = env_map.get(name)
    if env_name:
        v = os.environ.get(env_name, "").strip()
        if v:
            return v
    cfg_name = cfg_map.get(name)
    if not cfg_name:
        return ""
    return load().get(cfg_name, "").strip()


def is_enabled(service):
    return load().get("enabled_services", {}).get(service, True)


def redacted(cfg=None):
    cfg = cfg or load()
    out = dict(cfg)
    for k in ("gsb_api_key", "vt_api_key", "urlhaus_auth_key", "hybrid_api_key"):
        v = out.get(k, "")
        if v:
            out[k] = v[:6] + "..." + v[-4:] if len(v) > 10 else "(set)"
        else:
            out[k] = "(empty)"
    return out


# ---------- secret sanitization ----------

import re as _re

# patterns that look like API keys
_KEY_PATTERNS = [
    _re.compile(r"AIzaSy[A-Za-z0-9_\-]{33}"),           # Google API key
    _re.compile(r"[a-f0-9]{32,64}"),                     # hex keys (abuse.ch, VT)
    _re.compile(r"key=[A-Za-z0-9_\-]+", _re.IGNORECASE),
    _re.compile(r"apikey[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", _re.IGNORECASE),
    _re.compile(r"Auth-Key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", _re.IGNORECASE),
    _re.compile(r"x-apikey[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", _re.IGNORECASE),
]


def sanitize(text):
    """replace anything that looks like an API key with <REDACTED>."""
    if not isinstance(text, str):
        text = str(text)
    for pat in _KEY_PATTERNS:
        text = pat.sub("<REDACTED>", text)
    # also strip anything matching the actual stored keys
    try:
        cfg = load()
        for k in ("gsb_api_key", "vt_api_key", "urlhaus_auth_key", "hybrid_api_key"):
            v = cfg.get(k, "")
            if v and len(v) > 8:
                text = text.replace(v, "<REDACTED>")
    except Exception:
        pass
    return text


def secure_config_file():
    """ensure the config file has 600 perms. returns True if fixed, False if already OK."""
    if not CONFIG_FILE.exists():
        return False
    try:
        st = CONFIG_FILE.stat()
        mode = st.st_mode & 0o777
        if mode != 0o600:
            os.chmod(CONFIG_FILE, 0o600)
            return True
    except OSError:
        pass
    return False

