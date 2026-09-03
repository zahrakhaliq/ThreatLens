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
Streamlit UI rendering code.

API keys are never hardcoded here. They are read from Streamlit secrets
(st.secrets, configured in the Streamlit Cloud dashboard or a local
.streamlit/secrets.toml) or, as a fallback, from environment variables.

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
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Optional
from urllib.parse import quote, urlparse

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
WHOIS_TIMEOUT = 8  # seconds — WHOIS servers can be slow/unresponsive


# ---------------------------------------------------------------------------
# Secrets / config helpers
# ---------------------------------------------------------------------------

def get_secret(name: str) -> Optional[str]:
    """
    Resolve a config value / API key. Priority order:
      1. Streamlit secrets (st.secrets) — set via the Streamlit Cloud
         dashboard ("Settings -> Secrets") or a local .streamlit/secrets.toml
      2. Environment variable — useful for local development
    Never hardcode a key as a fallback here.
    """
    if st is not None:
        try:
            if name in st.secrets:
                value = st.secrets[name]
                return str(value).strip() if value else None
        except Exception:
            pass
    value = os.environ.get(name)
    return value.strip() if value else None


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
        return _fail(source_name, "API key not configured (VT_API_KEY missing in secrets)")

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
    reported as a clean failure rather than crashing. WHOIS needs no API key.
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
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(pywhois.whois, domain)
            record = future.result(timeout=WHOIS_TIMEOUT)
    except FuturesTimeoutError:
        return _fail(source_name, f"WHOIS lookup timed out after {WHOIS_TIMEOUT}s")
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
# AlienVault OTX
# ---------------------------------------------------------------------------

def get_alienvault_otx(target: str, target_type: str) -> dict:
    """Query AlienVault OTX for pulse/reputation data on an IP, domain, or URL."""
    source_name = "AlienVault OTX"
    api_key = get_secret("OTX_API_KEY")
    if not api_key:
        return _fail(source_name, "API key not configured (OTX_API_KEY missing in secrets)")

    ioc_type_map = {"ip": "IPv4", "domain": "domain", "url": "url"}
    ioc_type = ioc_type_map.get(target_type)
    if not ioc_type:
        return _fail(source_name, f"Unsupported target type: {target_type}")

    indicator = quote(target, safe="")
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting AlienVault OTX: {exc}")

    if response.status_code == 401:
        return _fail(source_name, "AlienVault OTX rejected the API key (unauthorized)")
    if response.status_code == 404:
        return _fail(source_name, "Target not found in AlienVault OTX")
    if response.status_code != 200:
        return _fail(source_name, f"AlienVault OTX returned status {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        return _fail(source_name, f"Unexpected AlienVault OTX response format: {exc}")

    pulse_info = payload.get("pulse_info", {})
    normalized: dict[str, Any] = {}
    if "count" in pulse_info:
        normalized["pulse_count"] = pulse_info.get("count")
    if payload.get("reputation") is not None:
        normalized["reputation"] = payload.get("reputation")
    if payload.get("country"):
        normalized["country"] = payload.get("country")
    if payload.get("asn"):
        normalized["asn"] = payload.get("asn")

    if not normalized:
        return _fail(source_name, "AlienVault OTX returned no usable data")

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# abuse.ch URLhaus
# ---------------------------------------------------------------------------

def get_urlhaus(target: str, target_type: str) -> dict:
    """Query abuse.ch URLhaus for known malware-distribution URLs/hosts."""
    source_name = "URLhaus"
    auth_key = get_secret("URLHAUS_AUTH_KEY")
    if not auth_key:
        return _fail(source_name, "API key not configured (URLHAUS_AUTH_KEY missing in secrets)")

    headers = {"Auth-Key": auth_key}

    if target_type == "url":
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": target}
    else:
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        data = {"host": target}

    try:
        response = requests.post(endpoint, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting URLhaus: {exc}")

    if response.status_code != 200:
        return _fail(source_name, f"URLhaus returned status {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        return _fail(source_name, f"Unexpected URLhaus response format: {exc}")

    query_status = payload.get("query_status")
    if query_status == "no_results":
        return _ok(source_name, {"status": "not listed in URLhaus"})
    if query_status != "ok":
        return _fail(source_name, f"URLhaus query status: {query_status}")

    normalized: dict[str, Any] = {"status": "LISTED in URLhaus"}
    if "url_status" in payload:
        normalized["url_status"] = payload.get("url_status")
    if "threat" in payload:
        normalized["threat"] = payload.get("threat")
    if "date_added" in payload:
        normalized["date_added"] = payload.get("date_added")
    if "tags" in payload and payload.get("tags"):
        normalized["tags"] = payload.get("tags")
    if "url_count" in payload:
        normalized["url_count"] = payload.get("url_count")

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# URLScan.io
# ---------------------------------------------------------------------------

def get_urlscan(target: str, target_type: str) -> dict:
    """Search URLScan.io's public archive for prior scans of this target. No API key required for search."""
    source_name = "URLScan.io"

    if target_type == "ip":
        query = f"ip:{target}"
    elif target_type == "url":
        domain = _extract_domain(target, target_type)
        query = f"domain:{domain}"
    else:
        query = f"domain:{target}"

    endpoint = "https://urlscan.io/api/v1/search/"
    params = {"q": query, "size": 5}

    try:
        response = requests.get(endpoint, params=params, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting URLScan.io: {exc}")

    if response.status_code == 429:
        return _fail(source_name, "URLScan.io rate limit exceeded")
    if response.status_code != 200:
        return _fail(source_name, f"URLScan.io returned status {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        return _fail(source_name, f"Unexpected URLScan.io response format: {exc}")

    results = payload.get("results", [])
    if not results:
        return _ok(source_name, {"status": "no prior scans found"})

    malicious_count = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious"))
    normalized = {
        "prior_scans_found": payload.get("total", len(results)),
        "malicious_scans_in_sample": malicious_count,
        "most_recent_scan": results[0].get("page", {}).get("url") if results else None,
    }
    normalized = {k: v for k, v in normalized.items() if v not in (None, "")}

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def get_shodan(target: str, target_type: str) -> dict:
    """Query Shodan for exposed services/infrastructure on an IP address."""
    source_name = "Shodan"

    if target_type != "ip":
        return _fail(source_name, "Shodan only supports IP address lookups")

    api_key = get_secret("SHODAN_API_KEY")
    if not api_key:
        return _fail(source_name, "API key not configured (SHODAN_API_KEY missing in secrets)")

    endpoint = f"https://api.shodan.io/shodan/host/{target}"
    params = {"key": api_key}

    try:
        response = requests.get(endpoint, params=params, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting Shodan: {exc}")

    if response.status_code == 401:
        return _fail(source_name, "Shodan rejected the API key (unauthorized)")
    if response.status_code == 404:
        return _fail(source_name, "No Shodan data found for this IP")
    if response.status_code != 200:
        return _fail(source_name, f"Shodan returned status {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        return _fail(source_name, f"Unexpected Shodan response format: {exc}")

    normalized: dict[str, Any] = {}
    if payload.get("org"):
        normalized["organization"] = payload.get("org")
    if payload.get("isp"):
        normalized["isp"] = payload.get("isp")
    if payload.get("ports"):
        normalized["open_ports"] = payload.get("ports")
    if payload.get("vulns"):
        normalized["known_vulnerabilities"] = list(payload.get("vulns"))
    if payload.get("hostnames"):
        normalized["hostnames"] = payload.get("hostnames")
    if payload.get("country_name"):
        normalized["country"] = payload.get("country_name")

    if not normalized:
        return _fail(source_name, "Shodan returned no usable data for this IP")

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def get_abuseipdb(target: str, target_type: str) -> dict:
    """Query AbuseIPDB for abuse reports/confidence score on an IP address."""
    source_name = "AbuseIPDB"

    if target_type != "ip":
        return _fail(source_name, "AbuseIPDB only supports IP address lookups")

    api_key = get_secret("ABUSEIPDB_API_KEY")
    if not api_key:
        return _fail(source_name, "API key not configured (ABUSEIPDB_API_KEY missing in secrets)")

    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": target, "maxAgeInDays": 90}

    try:
        response = requests.get(endpoint, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting AbuseIPDB: {exc}")

    if response.status_code == 401:
        return _fail(source_name, "AbuseIPDB rejected the API key (unauthorized)")
    if response.status_code == 429:
        return _fail(source_name, "AbuseIPDB rate limit exceeded")
    if response.status_code != 200:
        return _fail(source_name, f"AbuseIPDB returned status {response.status_code}")

    try:
        data = response.json().get("data", {})
    except ValueError as exc:
        return _fail(source_name, f"Unexpected AbuseIPDB response format: {exc}")

    normalized = {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "country": data.get("countryCode"),
        "is_whitelisted": data.get("isWhitelisted"),
    }
    normalized = {k: v for k, v in normalized.items() if v is not None}

    if not normalized:
        return _fail(source_name, "AbuseIPDB returned no usable data")

    return _ok(source_name, normalized)


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

def get_google_safe_browsing(target: str, target_type: str) -> dict:
    """Check a URL or domain against Google's Safe Browsing threat lists."""
    source_name = "Google Safe Browsing"

    if target_type == "ip":
        return _fail(source_name, "Google Safe Browsing does not support raw IP lookups")

    api_key = get_secret("GSB_API_KEY")
    if not api_key:
        return _fail(source_name, "API key not configured (GSB_API_KEY missing in secrets)")

    check_url = target if target_type == "url" else f"http://{target}"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "threatlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": check_url}],
        },
    }

    try:
        response = requests.post(endpoint, json=body, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting Google Safe Browsing: {exc}")

    if response.status_code == 400:
        return _fail(source_name, "Google Safe Browsing rejected the request (check API key/config)")
    if response.status_code != 200:
        return _fail(source_name, f"Google Safe Browsing returned status {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        return _fail(source_name, f"Unexpected Google Safe Browsing response format: {exc}")

    matches = payload.get("matches", [])
    if not matches:
        return _ok(source_name, {"status": "no known threats found"})

    threat_types = sorted({m.get("threatType") for m in matches if m.get("threatType")})
    return _ok(source_name, {"status": "THREAT MATCH FOUND", "threat_types": threat_types})


# ---------------------------------------------------------------------------
# VirusTotal — file scanning (separate contract: takes file bytes, not a
# string target/target_type; kept in its own FILE_SOURCES registry so file
# scanning is just as extensible as target scanning)
# ---------------------------------------------------------------------------

def get_virustotal_file(file_bytes: bytes, filename: str) -> dict:
    """
    Look up a file's hash on VirusTotal. If VT has already seen the file,
    returns its existing detection stats immediately. If not, uploads the
    file and briefly polls for the analysis to complete.
    """
    source_name = "VirusTotal (File)"
    api_key = get_secret("VT_API_KEY")
    if not api_key:
        return _fail(source_name, "API key not configured (VT_API_KEY missing in secrets)")

    headers = {"x-apikey": api_key}
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    def _normalize_file_attributes(attributes: dict) -> dict:
        normalized: dict[str, Any] = {"sha256": sha256}
        stats = attributes.get("last_analysis_stats")
        if stats:
            normalized["malicious"] = stats.get("malicious")
            normalized["suspicious"] = stats.get("suspicious")
            normalized["harmless"] = stats.get("harmless")
            normalized["undetected"] = stats.get("undetected")
            normalized["total_engines"] = sum(v for v in stats.values() if isinstance(v, int))
        if attributes.get("type_description"):
            normalized["file_type"] = attributes.get("type_description")
        if attributes.get("size"):
            normalized["size_bytes"] = attributes.get("size")
        return normalized

    # 1. Check if VirusTotal has already seen this exact file (by hash).
    try:
        lookup = requests.get(
            f"{VT_BASE_URL}/files/{sha256}", headers=headers, timeout=REQUEST_TIMEOUT
        )
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error contacting VirusTotal: {exc}")

    if lookup.status_code == 200:
        try:
            attributes = lookup.json()["data"]["attributes"]
        except (ValueError, KeyError) as exc:
            return _fail(source_name, f"Unexpected VirusTotal response format: {exc}")
        normalized = _normalize_file_attributes(attributes)
        if normalized.get("total_engines"):
            return _ok(source_name, normalized)

    if len(file_bytes) > 32 * 1024 * 1024:
        return _fail(source_name, "File exceeds 32MB — too large for the standard upload endpoint")

    # 2. Not seen before — upload it for a fresh analysis.
    try:
        upload = requests.post(
            f"{VT_BASE_URL}/files",
            headers=headers,
            files={"file": (filename, file_bytes)},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        return _fail(source_name, f"Network error uploading to VirusTotal: {exc}")

    if upload.status_code == 401:
        return _fail(source_name, "VirusTotal rejected the API key (unauthorized)")
    if upload.status_code == 429:
        return _fail(source_name, "VirusTotal rate limit exceeded")
    if upload.status_code not in (200, 202):
        return _fail(source_name, f"VirusTotal upload returned status {upload.status_code}")

    try:
        analysis_id = upload.json()["data"]["id"]
    except (ValueError, KeyError) as exc:
        return _fail(source_name, f"Unexpected VirusTotal upload response: {exc}")

    # 3. Briefly poll for the analysis to finish (VT scans can take longer
    # than this — if it's not done yet, we say so honestly rather than guess).
    for _ in range(5):
        time.sleep(3)
        try:
            poll = requests.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers, timeout=REQUEST_TIMEOUT
            )
        except requests.exceptions.RequestException:
            continue
        if poll.status_code != 200:
            continue
        try:
            poll_data = poll.json()["data"]["attributes"]
        except (ValueError, KeyError):
            continue
        if poll_data.get("status") == "completed":
            normalized = _normalize_file_attributes(poll_data)
            if normalized.get("total_engines"):
                return _ok(source_name, normalized)

    return _fail(
        source_name,
        "File submitted to VirusTotal but the scan hasn't finished yet — "
        "try again in a minute for full results.",
    )


FILE_SOURCES = {
    "VirusTotal (File)": get_virustotal_file,
}


# ---------------------------------------------------------------------------
# Source registry — the heart of the extensibility architecture
# ---------------------------------------------------------------------------

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
    "AlienVault OTX": get_alienvault_otx,
    "URLhaus": get_urlhaus,
    "URLScan.io": get_urlscan,
    "Shodan": get_shodan,
    "AbuseIPDB": get_abuseipdb,
    "Google Safe Browsing": get_google_safe_browsing,
}
