"""
sources.py
----------
Intelligence source functions for ThreatLens.

Responsibilities (and ONLY these):
    - Reading API keys / secrets
    - Talking to external intelligence APIs (VirusTotal, WHOIS, ...)
    - Normalizing each source's response into a predictable dictionary
    - Exposing the SOURCES registry that app.py iterates over

This file must never import from app.py and must never contain
Streamlit UI code or Gemini prompt/orchestration logic.

--------------------------------------------------------------------
HOW TO ADD A NEW SOURCE (e.g. AbuseIPDB) LATER:

    1. Write one function with the standard signature:

        def get_abuseipdb(target: str, target_type: str) -> dict:
            ...
            return {
                "source": "AbuseIPDB",
                "success": True,
                "data": {...},
                "error": None,
            }

    2. Register it:

        SOURCES["AbuseIPDB"] = get_abuseipdb

That's it. app.py, the Gemini prompt builder, the verdict logic, and
the result-rendering code all iterate over SOURCES dynamically, so
nothing else needs to change.
--------------------------------------------------------------------
"""

from __future__ import annotations

import base64
import os
from typing import Any, Optional
from urllib.parse import urlparse

import requests

try:
    import whois as pywhois  # python-whois
except ImportError:  # pragma: no cover
    pywhois = None

try:
    import streamlit as st
except ImportError:  # pragma: no cover
    st = None


VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Secrets / config helpers
# ---------------------------------------------------------------------------

def get_secret(name: str) -> Optional[str]:
    """Read a secret from Streamlit secrets first, then environment variables."""
    if st is not None:
        try:
            if name in st.secrets:
                return str(st.secrets[name])
        except Exception:
            pass
    return os.environ.get(name)


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _ok(source: str, data: dict) -> dict:
    return {"source": source, "success": True, "data": data, "error": None}


def _fail(source: str, error: str) -> dict:
    return {"source": source, "success": False, "data": {}, "error": error}


def _extract_domain(target: str, target_type: str) -> str:
    """Best-effort extraction of a bare domain/host from any target type."""
    if target_type == "url":
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.netloc.split(":")[0]
    return target


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def _vt_url_id(url: str) -> str:
    """VirusTotal v3 identifies URLs by URL-safe base64 (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_virustotal(target: str, target_type: str) -> dict:
    """
    Query VirusTotal for an IP, domain, or URL and return a compact,
    normalized summary of the detection stats.
    """
    source_name = "VirusTotal"
    api_key = get_secret("VT_API_KEY")
    if not api_key:
        return _fail(source_name, "API key not configured (VT_API_KEY missing)")

    headers = {"x-apikey": api_key}

    if target_type == "ip":
        endpoint = f"{VT_BASE_URL}/ip_addresses/{target}"
    elif target_type == "domain":
        endpoint = f"{VT_BASE_URL}/domains/{target}"
    elif target_type == "url":
        endpoint = f"{VT_BASE_URL}/urls/{_vt_url_id(target)}"
    else:
        return _fail(source_name, f"Unsupported target type: {target_type}")

    try:
        response = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting VirusTotal: {exc}")

    if response.status_code == 401:
        return _fail(source_name, "VirusTotal rejected the API key (unauthorized)")
    if response.status_code == 404:
        return _fail(source_name, "Target not found in VirusTotal")
    if response.status_code == 429:
        return _fail(source_name, "VirusTotal rate limit exceeded")
    if response.status_code != 200:
        return _fail(source_name, f"VirusTotal returned status {response.status_code}")

    try:
        payload = response.json()
        attributes = payload["data"]["attributes"]
    except (ValueError, KeyError) as exc:
        return _fail(source_name, f"Unexpected VirusTotal response format: {exc}")

    normalized: dict[str, Any] = {}

    stats = attributes.get("last_analysis_stats")
    if stats:
        normalized["malicious"] = stats.get("malicious")
        normalized["suspicious"] = stats.get("suspicious")
        normalized["harmless"] = stats.get("harmless")
        normalized["undetected"] = stats.get("undetected")
        normalized["total_engines"] = sum(v for v in stats.values() if isinstance(v, int))

    if "reputation" in attributes:
        normalized["reputation"] = attributes.get("reputation")

    if "last_analysis_date" in attributes:
        normalized["last_analysis_date"] = attributes.get("last_analysis_date")

    if not normalized:
        return _fail(source_name, "VirusTotal returned no usable analysis data")

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def get_whois(target: str, target_type: str) -> dict:
    """
    Query WHOIS for a domain (or the domain portion of a URL).
    WHOIS is not meaningful for raw IP addresses, so that case is
    reported as a clean failure rather than crashing.
    """
    source_name = "WHOIS"

    if pywhois is None:
        return _fail(source_name, "python-whois library is not installed")

    if target_type == "ip":
        return _fail(source_name, "WHOIS lookups are not supported for IP addresses")

    domain = _extract_domain(target, target_type)
    if not domain:
        return _fail(source_name, "Could not determine a domain to query")

    try:
        record = pywhois.whois(domain)
    except Exception as exc:  # python-whois can raise several different errors
        return _fail(source_name, f"WHOIS lookup failed: {exc}")

    if not record or not getattr(record, "domain_name", None):
        return _fail(source_name, "No WHOIS data found for this domain")

    def _first(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    normalized = {
        "domain": _first(record.domain_name),
        "registrar": record.registrar,
        "creation_date": str(_first(record.creation_date)) if record.creation_date else None,
        "expiration_date": str(_first(record.expiration_date)) if record.expiration_date else None,
        "updated_date": str(_first(record.updated_date)) if record.updated_date else None,
        "name_servers": record.name_servers if record.name_servers else None,
    }
    normalized = {k: v for k, v in normalized.items() if v not in (None, [], "")}

    if not normalized:
        return _fail(source_name, "WHOIS response contained no usable fields")

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# Source registry — the heart of the extensibility architecture
# ---------------------------------------------------------------------------

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
