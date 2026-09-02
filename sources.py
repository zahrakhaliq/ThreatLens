"""
sources.py
----------
Threat intelligence source functions for ThreatLens.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Optional
from urllib.parse import urlparse

import requests

try:
    import streamlit as st
except ImportError:
    st = None

try:
    import whois as pywhois
except ImportError:
    pywhois = None


VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15


def get_secret(name: str) -> Optional[str]:
    """
    Resolve configuration values in this order:

    1. Streamlit session_state
    2. Streamlit secrets
    3. Environment variables
    """

    if st is not None:

        try:
            value = st.session_state.get(name)

            if value:
                value = str(value).strip()

                if value:
                    return value

        except Exception:
            pass

        try:
            value = st.secrets.get(name)

            if value:
                value = str(value).strip()

                if value:
                    return value

        except Exception:
            pass

    value = os.environ.get(name)

    if value:
        value = str(value).strip()

        if value:
            return value

    return None


def _ok(
    source: str,
    data: dict
) -> dict:

    return {
        "source": source,
        "success": True,
        "data": data,
        "error": None,
    }


def _fail(
    source: str,
    error: str
) -> dict:

    return {
        "source": source,
        "success": False,
        "data": {},
        "error": error,
    }


def _extract_domain(
    target: str,
    target_type: str
) -> str:

    if target_type == "url":

        parsed = urlparse(
            target
            if "://" in target
            else f"http://{target}"
        )

        return parsed.netloc.split(":")[0]

    return target


def _vt_url_id(
    url: str
) -> str:

    return (
        base64.urlsafe_b64encode(
            url.encode()
        )
        .decode()
        .strip("=")
    )


def get_virustotal(
    target: str,
    target_type: str
) -> dict:

    source_name = "VirusTotal"

    api_key = get_secret(
        "VT_API_KEY"
    )

    if not api_key:
        return _fail(
            source_name,
            "No VirusTotal API key provided."
        )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    if target_type == "ip":

        endpoint = (
            f"{VT_BASE_URL}/ip_addresses/{target}"
        )

    elif target_type == "domain":

        endpoint = (
            f"{VT_BASE_URL}/domains/{target}"
        )

    elif target_type == "url":

        endpoint = (
            f"{VT_BASE_URL}/urls/"
            f"{_vt_url_id(target)}"
        )

    else:

        return _fail(
            source_name,
            f"Unsupported target type: {target_type}"
        )

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

    except requests.exceptions.Timeout:

        return _fail(
            source_name,
            "VirusTotal request timed out."
        )

    except requests.exceptions.RequestException as exc:

        return _fail(
            source_name,
            f"Network error contacting VirusTotal: {exc}"
        )

    if response.status_code == 401:

        return _fail(
            source_name,
            "VirusTotal rejected the API key (unauthorized)."
        )

    if response.status_code == 403:

        return _fail(
            source_name,
            "VirusTotal denied access to this request."
        )

    if response.status_code == 404:

        return _fail(
            source_name,
            "Target not found in VirusTotal."
        )

    if response.status_code == 429:

        return _fail(
            source_name,
            "VirusTotal rate limit exceeded."
        )

    if response.status_code != 200:

        return _fail(
            source_name,
            f"VirusTotal returned HTTP status "
            f"{response.status_code}."
        )

    try:

        payload = response.json()

        attributes = (
            payload["data"]["attributes"]
        )

    except (
        ValueError,
        KeyError,
        TypeError
    ) as exc:

        return _fail(
            source_name,
            f"Unexpected VirusTotal response format: {exc}"
        )

    normalized: dict[str, Any] = {}

    stats = attributes.get(
        "last_analysis_stats"
    )

    if isinstance(stats, dict):

        normalized["malicious"] = stats.get(
            "malicious",
            0
        )

        normalized["suspicious"] = stats.get(
            "suspicious",
            0
        )

        normalized["harmless"] = stats.get(
            "harmless",
            0
        )

        normalized["undetected"] = stats.get(
            "undetected",
            0
        )

        normalized["total_engines"] = sum(
            value
            for value in stats.values()
            if isinstance(value, int)
        )

    if "reputation" in attributes:

        normalized["reputation"] = (
            attributes.get("reputation")
        )

    if "last_analysis_date" in attributes:

        normalized["last_analysis_date"] = (
            attributes.get("last_analysis_date")
        )

    if not normalized:

        return _fail(
            source_name,
            "VirusTotal returned no usable analysis data."
        )

    return _ok(
        source_name,
        normalized
    )


def get_whois(
    target: str,
    target_type: str
) -> dict:

    source_name = "WHOIS"

    if pywhois is None:

        return _fail(
            source_name,
            "python-whois library is not installed."
        )

    if target_type == "ip":

        return _fail(
            source_name,
            "WHOIS lookups are not supported for IP addresses."
        )

    domain = _extract_domain(
        target,
        target_type
    )

    if not domain:

        return _fail(
            source_name,
            "Could not determine a domain to query."
        )

    try:

        record = pywhois.whois(
            domain
        )

    except Exception as exc:

        return _fail(
            source_name,
            f"WHOIS lookup failed: {exc}"
        )

    if not record:

        return _fail(
            source_name,
            "No WHOIS data found for this domain."
        )

    if not getattr(
        record,
        "domain_name",
        None
    ):

        return _fail(
            source_name,
            "WHOIS response did not contain domain information."
        )

    def _first(value):

        if isinstance(value, list):
            return value[0] if value else None

        return value

    normalized = {

        "domain": _first(
            record.domain_name
        ),

        "registrar": getattr(
            record,
            "registrar",
            None
        ),

        "creation_date": (
            str(
                _first(
                    record.creation_date
                )
            )
            if getattr(
                record,
                "creation_date",
                None
            )
            else None
        ),

        "expiration_date": (
            str(
                _first(
                    record.expiration_date
                )
            )
            if getattr(
                record,
                "expiration_date",
                None
            )
            else None
        ),

        "updated_date": (
            str(
                _first(
                    record.updated_date
                )
            )
            if getattr(
                record,
                "updated_date",
                None
            )
            else None
        ),

        "name_servers": getattr(
            record,
            "name_servers",
            None
        ),
    }

    normalized = {
        key: value
        for key, value in normalized.items()
        if value not in (
            None,
            [],
            ""
        )
    }

    if not normalized:

        return _fail(
            source_name,
            "WHOIS response contained no usable fields."
        )

    return _ok(
        source_name,
        normalized
    )


SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
