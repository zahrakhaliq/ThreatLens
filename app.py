"""
app.py
------
ThreatLens — AI-powered threat intelligence dashboard (Streamlit).

Responsible for:
    UI  ->  input validation  ->  source orchestration (via sources.SOURCES)
        ->  Gemini prompt construction  ->  Gemini call
        ->  verdict rendering  ->  AI insight rendering  ->  source result rendering

API keys are configured via Streamlit secrets (Streamlit Cloud dashboard ->
"Settings" -> "Secrets", or a local .streamlit/secrets.toml). They are never
hardcoded in this file or in sources.py.

This file may import from sources.py. sources.py must never import from here.
"""

from __future__ import annotations

import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

import streamlit as st

from sources import FILE_SOURCES, SOURCES, get_secret

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:  # pragma: no cover
    genai = None
    genai_types = None


DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"

KNOWLEDGE_LEVELS = ["Beginner", "Intermediate", "Advanced"]
TARGET_TYPES = ["IP", "Domain", "URL"]

VERDICT_STYLES = {
    "SAFE": {"color": "#1DB954", "icon": "✅"},
    "SUSPICIOUS": {"color": "#F5A623", "icon": "⚠️"},
    "MALICIOUS": {"color": "#E5484D", "icon": "⛔"},
    "UNKNOWN": {"color": "#8A8F98", "icon": "❔"},
}

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_input(target: str, target_type: str) -> tuple[bool, Optional[str]]:
    """Validate a target string against the selected target type."""
    target = (target or "").strip()
    if not target:
        return False, "Please enter a target to analyze."

    if target_type == "IP":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return False, "That doesn't look like a valid IP address."

    elif target_type == "Domain":
        if not DOMAIN_REGEX.match(target):
            return False, "That doesn't look like a valid domain name."

    elif target_type == "URL":
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False, "Please enter a full URL, e.g. https://example.com/path"

    else:
        return False, f"Unknown target type: {target_type}"

    return True, None


# ---------------------------------------------------------------------------
# Source orchestration — knows nothing about how any individual source works
# ---------------------------------------------------------------------------

@st.cache_data(ttl=600, show_spinner=False)
def collect_file_intelligence(file_bytes: bytes, filename: str) -> dict[str, dict]:
    """
    Run every registered file-scanning source concurrently, same pattern as
    collect_intelligence but for the file_bytes/filename contract.
    """
    results: dict[str, dict] = {}

    def _run(name: str, func) -> tuple[str, dict]:
        try:
            return name, func(file_bytes, filename)
        except Exception as exc:
            return name, {
                "source": name,
                "success": False,
                "data": {},
                "error": f"Unexpected error: {exc}",
            }

    with ThreadPoolExecutor(max_workers=max(len(FILE_SOURCES), 1)) as executor:
        futures = [executor.submit(_run, name, func) for name, func in FILE_SOURCES.items()]
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result

    return {name: results[name] for name in FILE_SOURCES if name in results}


@st.cache_data(ttl=600, show_spinner=False)
def collect_intelligence(target: str, target_type: str) -> dict[str, dict]:
    """
    Run every registered source concurrently and collect its normalized
    result. Running sources in parallel (rather than one after another)
    cuts total wait time down to roughly the slowest single source
    instead of the sum of all of them.
    """
    target_type_key = target_type.lower()
    results: dict[str, dict] = {}

    def _run(name: str, func) -> tuple[str, dict]:
        try:
            return name, func(target, target_type_key)
        except Exception as exc:  # a misbehaving source must never crash the app
            return name, {
                "source": name,
                "success": False,
                "data": {},
                "error": f"Unexpected error: {exc}",
            }

    with ThreadPoolExecutor(max_workers=max(len(SOURCES), 1)) as executor:
        futures = [executor.submit(_run, name, func) for name, func in SOURCES.items()]
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result

    # Preserve the registry's declared order in the returned dict,
    # regardless of which source finished first.
    return {name: results[name] for name in SOURCES if name in results}


# ---------------------------------------------------------------------------
# Verdict logic — derived from structured evidence, not from Gemini
# ---------------------------------------------------------------------------

def derive_verdict(results: dict[str, dict]) -> tuple[str, str]:
    """
    Compute a verdict + confidence level from structured source data.
    Currently keys off VirusTotal detection stats when available.
    Falls back to UNKNOWN if there isn't enough evidence.
    """
    vt = results.get("VirusTotal") or results.get("VirusTotal (File)")
    if not vt or not vt.get("success"):
        return "UNKNOWN", "LOW"

    data = vt.get("data", {})
    malicious = data.get("malicious")
    suspicious = data.get("suspicious")
    total = data.get("total_engines")
    reputation = data.get("reputation")

    if malicious is None and suspicious is None:
        return "UNKNOWN", "LOW"

    malicious = malicious or 0
    suspicious = suspicious or 0

    # A single lone-engine "malicious" flag is a very common false positive
    # on VirusTotal (one scanner glitching or using an overly broad
    # heuristic) — it shouldn't alone outweigh dozens of clean verdicts and
    # a strong reputation score. Require at least 2 engines in agreement
    # before calling something outright MALICIOUS.
    if malicious >= 10:
        return "MALICIOUS", "HIGH"
    if malicious >= 2:
        return "MALICIOUS", "MEDIUM"
    if malicious == 1:
        # Treat as suspicious rather than malicious, unless reputation
        # data also points the same direction.
        if reputation is not None and reputation < 0:
            return "MALICIOUS", "LOW"
        return "SUSPICIOUS", "LOW"
    if suspicious >= 3:
        return "SUSPICIOUS", "MEDIUM"
    if suspicious >= 1:
        return "SUSPICIOUS", "LOW"

    if total:
        return "SAFE", "HIGH" if total >= 30 else "MEDIUM"
    return "SAFE", "LOW"


# ---------------------------------------------------------------------------
# Gemini prompt construction
# ---------------------------------------------------------------------------

def _format_source_results(results: dict[str, dict]) -> str:
    lines = []
    for source_name, result in results.items():
        lines.append(f"### {source_name}")
        if result.get("success"):
            data = result.get("data", {})
            if data:
                for key, value in data.items():
                    lines.append(f"- {key}: {value}")
            else:
                lines.append("- (no data fields returned)")
        else:
            lines.append(f"- UNAVAILABLE: {result.get('error', 'unknown error')}")
        lines.append("")
    return "\n".join(lines)


def build_gemini_prompt(
    target: str,
    target_type: str,
    knowledge_level: str,
    results: dict[str, dict],
    computed_verdict: str,
    computed_confidence: str,
) -> str:
    """Build a knowledge-level-aware prompt describing exactly what Gemini may use."""

    level_instructions = {
        "Beginner": (
            "Explain things in simple, plain language for someone new to "
            "cybersecurity. Briefly explain what the target is, whether it "
            "appears safe/suspicious/malicious, and why, in non-technical terms. "
            "Explain any technical term you use. Keep it short and give one "
            "clear recommended action."
        ),
        "Intermediate": (
            "Assume the reader understands basic cybersecurity concepts. You may "
            "discuss detection counts, reputation, registration information, "
            "domain age, and possible indicators of compromise using moderate "
            "technical terminology."
        ),
        "Advanced": (
            "Assume the reader has cybersecurity/networking expertise. You may "
            "discuss detection ratios, vendor consensus, reputation signals, "
            "registration anomalies, registrar and infrastructure indicators "
            "present in the data, potential attack-surface implications, and "
            "the confidence/limitations of this assessment."
        ),
    }

    prompt = f"""You are a cybersecurity analysis assistant embedded in a tool called ThreatLens.

TASK: Analyze the intelligence collected below about a single target and produce
a structured security assessment.

TARGET: {target}
TARGET TYPE: {target_type}
KNOWLEDGE LEVEL FOR THIS EXPLANATION: {knowledge_level}

A verdict has already been computed programmatically from the structured evidence:
COMPUTED VERDICT: {computed_verdict}
COMPUTED CONFIDENCE: {computed_confidence}
Treat this computed verdict as authoritative — do not override it, but explain
the reasoning behind it using the evidence below.

COLLECTED SOURCE RESULTS:
{_format_source_results(results)}

STRICT RULES:
- This is a cybersecurity analysis. Analyze ONLY the source data supplied above.
- Do not fabricate threat intelligence or assume missing information.
- Do not treat an absence of detections as proof that a target is safe.
- Clearly distinguish observed facts from your interpretation.
- If a source is marked UNAVAILABLE, explicitly mention that it was unavailable
  rather than guessing what it might have shown.
- Keep the response concise.

AUDIENCE INSTRUCTIONS: {level_instructions[knowledge_level]}

Respond using EXACTLY this structure:

VERDICT:
{computed_verdict}

CONFIDENCE:
{computed_confidence}

SUMMARY:
<2-4 sentences>

KEY FINDINGS:
- <finding 1>
- <finding 2>
- <finding 3 (optional)>

RECOMMENDED ACTION:
<1-2 sentences>
"""
    return prompt


# ---------------------------------------------------------------------------
# Gemini call + response parsing
# ---------------------------------------------------------------------------

@st.cache_data(ttl=600, show_spinner=False)
def _call_gemini_cached(prompt: str, max_retries: int) -> str:
    """
    Actually calls Gemini and returns the text on success.
    Raises RuntimeError on any failure — Streamlit's cache never stores a
    result from a call that raised, so failed attempts (e.g. a transient
    503) are never cached and the next click genuinely retries the API
    instead of replaying a stale error.
    """
    if genai is None:
        raise RuntimeError("google-genai package is not installed")

    api_key = get_secret("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("API key not configured (GEMINI_API_KEY missing in secrets)")

    model_name = get_secret("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL

    # Cap how long any single HTTP request to Gemini is allowed to hang
    # before we give up on it and move to the next retry — without this,
    # one slow/overloaded attempt can silently eat 60s+ before even
    # returning an error, which then stacks with our own backoff delays.
    client_kwargs = {"api_key": api_key}
    if genai_types is not None:
        try:
            client_kwargs["http_options"] = genai_types.HttpOptions(timeout=20_000)  # ms
        except Exception:
            pass
    client = genai.Client(**client_kwargs)

    # For newer Gemini models (3.x), "thinking" mode is on by default and
    # can add tens of seconds of latency even for a simple formatted reply.
    # We don't need deep reasoning here, so turn it off and cap the reply
    # length to keep generation fast.
    generation_config = None
    if genai_types is not None:
        try:
            generation_config = genai_types.GenerateContentConfig(
                thinking_config=genai_types.ThinkingConfig(thinking_level="minimal"),
                max_output_tokens=500,
            )
        except Exception:
            generation_config = None

    last_error = "Unknown error"
    config_disabled = False
    for attempt in range(1, max_retries + 1):
        try:
            use_config = generation_config if (generation_config is not None and not config_disabled) else None
            if use_config is not None:
                response = client.models.generate_content(
                    model=model_name, contents=prompt, config=use_config
                )
            else:
                response = client.models.generate_content(model=model_name, contents=prompt)
            text = getattr(response, "text", None)
            if not text:
                raise RuntimeError("Gemini returned an empty response")
            return text
        except Exception as exc:
            last_error = str(exc)
            is_transient = "503" in last_error or "429" in last_error or "UNAVAILABLE" in last_error
            is_bad_config = ("400" in last_error or "INVALID_ARGUMENT" in last_error) and not config_disabled
            if is_bad_config:
                # This model may not support thinking_config — drop it and retry immediately.
                config_disabled = True
                continue
            if is_transient and attempt < max_retries:
                time.sleep(attempt * 3)  # 3s, then 6s
                continue
            raise RuntimeError(f"Gemini request failed: {last_error}") from exc

    raise RuntimeError(f"Gemini request failed after {max_retries} attempts: {last_error}")


def call_gemini(prompt: str, max_retries: int = 2) -> tuple[Optional[str], Optional[str]]:
    """Call Gemini and return (text, error). See _call_gemini_cached for retry/caching behavior."""
    try:
        text = _call_gemini_cached(prompt, max_retries)
        return text, None
    except Exception as exc:
        return None, str(exc)


def parse_gemini_sections(text: str) -> dict[str, str]:
    """Split Gemini's structured reply into labeled sections."""
    sections = {"SUMMARY": "", "KEY FINDINGS": "", "RECOMMENDED ACTION": ""}
    labels = ["VERDICT", "CONFIDENCE", "SUMMARY", "KEY FINDINGS", "RECOMMENDED ACTION"]

    for i, label in enumerate(labels):
        pattern = rf"{label}:\s*(.*?)(?=(?:{'|'.join(labels[i+1:])}:)|\Z)"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match and label in sections:
            sections[label] = match.group(1).strip()

    return sections


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def inject_css() -> None:
    st.markdown(
        """
        <style>
        html, body, [class*="css"] {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        }

        /* ---- Header ---- */
        .tl-title {
            text-align: center;
            font-size: 2.6rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #7C9CFF 0%, #B47CFF 50%, #FF7CB4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.1rem;
        }
        .tl-subtitle {
            text-align: center;
            opacity: 0.65;
            font-size: 1rem;
            font-weight: 500;
            letter-spacing: 0.02em;
            margin-bottom: 1.6rem;
        }
        .tl-tagline {
            text-align: center;
            opacity: 0.85;
            margin-bottom: 1.6rem;
        }

        /* ---- Form container ---- */
        div[data-testid="stForm"] {
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 18px;
            padding: 1.75rem 1.75rem 1.25rem 1.75rem;
            background: linear-gradient(160deg, rgba(124,156,255,0.06), rgba(180,124,255,0.03));
            box-shadow: 0 8px 30px rgba(0,0,0,0.25);
        }

        /* ---- Inputs ---- */
        div[data-testid="stTextInput"] input {
            border-radius: 10px !important;
        }
        div[data-baseweb="select"] > div {
            border-radius: 10px !important;
        }
        div[role="radiogroup"] label {
            font-weight: 500;
        }

        /* ---- Analyze button ---- */
        div[data-testid="stFormSubmitButton"] button {
            border-radius: 10px;
            font-weight: 700;
            letter-spacing: 0.01em;
            background: linear-gradient(90deg, #7C9CFF, #B47CFF);
            border: none;
            color: white;
            padding: 0.6rem 0;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        div[data-testid="stFormSubmitButton"] button:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(124,156,255,0.35);
            color: white;
        }

        /* ---- Timing caption ---- */
        .tl-timing {
            font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Consolas, monospace;
            font-size: 0.78rem;
            opacity: 0.55;
            text-align: center;
            margin-top: 0.5rem;
        }

        /* ---- Verdict card ---- */
        .verdict-card {
            border-radius: 18px;
            padding: 2rem 1.5rem;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.08);
            box-shadow: 0 8px 30px rgba(0,0,0,0.25);
        }
        .verdict-title {
            font-size: 0.8rem;
            letter-spacing: 0.14em;
            opacity: 0.65;
            text-transform: uppercase;
            font-weight: 600;
        }
        .verdict-value {
            font-size: 2.4rem;
            font-weight: 800;
            letter-spacing: -0.01em;
            margin: 0.4rem 0 0.6rem 0;
        }
        .verdict-confidence {
            font-size: 0.9rem;
            opacity: 0.8;
            font-weight: 500;
        }

        /* ---- AI insight card ---- */
        .insight-card {
            border-radius: 18px;
            padding: 1.5rem 1.75rem;
            border: 1px solid rgba(180,124,255,0.28);
            background: linear-gradient(160deg, rgba(124,156,255,0.08), rgba(180,124,255,0.04));
            box-shadow: 0 8px 30px rgba(0,0,0,0.2);
        }
        .insight-header {
            font-weight: 700;
            font-size: 1.1rem;
            margin-bottom: 0.75rem;
            background: linear-gradient(90deg, #7C9CFF, #B47CFF);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            display: inline-block;
        }

        /* ---- Section headers ---- */
        h3 {
            font-weight: 700 !important;
            letter-spacing: -0.01em;
        }

        /* ---- Expander (source results) ---- */
        div[data-testid="stExpander"] {
            border-radius: 12px !important;
            border: 1px solid rgba(255,255,255,0.08) !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_verdict_card(verdict: str, confidence: str) -> None:
    style = VERDICT_STYLES.get(verdict, VERDICT_STYLES["UNKNOWN"])
    st.markdown(
        f"""
        <div class="verdict-card" style="background-color:{style['color']}18; border-color:{style['color']}55;">
            <div class="verdict-title">Security Verdict</div>
            <div class="verdict-value" style="color:{style['color']};">
                {style['icon']} {verdict}
            </div>
            <div class="verdict-confidence">Confidence: {confidence.title()}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_ai_insight(knowledge_level: str, sections: dict[str, str], raw_text: str) -> None:
    summary = sections.get("SUMMARY") or raw_text
    findings = sections.get("KEY FINDINGS")
    action = sections.get("RECOMMENDED ACTION")

    st.markdown('<div class="insight-card">', unsafe_allow_html=True)
    st.markdown(f'<div class="insight-header">🤖 AI Security Insight ({knowledge_level})</div>', unsafe_allow_html=True)
    st.write(summary)
    if findings:
        st.markdown("**Key Findings**")
        st.markdown(findings)
    if action:
        st.markdown(f"**Recommended Action:** {action}")
    st.markdown("</div>", unsafe_allow_html=True)


def render_source_results(results: dict[str, dict]) -> None:
    st.subheader("Source Results")
    for source_name, result in results.items():
        with st.expander(source_name, expanded=False):
            if result.get("success"):
                data = result.get("data", {})
                if not data:
                    st.info("No data returned.")
                for key, value in data.items():
                    label = key.replace("_", " ").title()
                    st.markdown(f"**{label}:** {value}")
            else:
                st.warning(f"{source_name} unavailable — {result.get('error', 'unknown error')}")


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def render_results(target: str, target_type: str, knowledge_level: str, results: dict[str, dict],
                    t0: float, t1: float) -> None:
    """Shared rendering path for both the target-analysis and file-scan tabs."""
    failed_sources = [name for name, r in results.items() if not r.get("success")]
    if failed_sources:
        st.warning(
            f"⚠ {', '.join(failed_sources)} unavailable. "
            f"Continuing with the remaining source(s) where possible."
        )

    verdict, confidence = derive_verdict(results)

    prompt = build_gemini_prompt(target, target_type, knowledge_level, results, verdict, confidence)

    with st.spinner("🤖 Generating AI insight..."):
        gemini_text, gemini_error = call_gemini(prompt)
    t2 = time.perf_counter()

    st.markdown(
        f'<div class="tl-timing">⏱ Sources: {t1 - t0:.1f}s · Gemini: {t2 - t1:.1f}s · Total: {t2 - t0:.1f}s</div>',
        unsafe_allow_html=True,
    )

    st.divider()
    render_verdict_card(verdict, confidence)
    st.write("")

    if gemini_error:
        st.error(f"AI insight unavailable — {gemini_error}")
    else:
        sections = parse_gemini_sections(gemini_text)
        render_ai_insight(knowledge_level, sections, gemini_text)

    st.write("")
    render_source_results(results)


def render_target_tab() -> None:
    with st.form("analyze_form"):
        target_type = st.radio("Target Type", TARGET_TYPES, horizontal=True)
        target = st.text_input("Target", placeholder="e.g. 8.8.8.8, example.com, https://example.com/login")
        knowledge_level = st.selectbox("Knowledge Level", KNOWLEDGE_LEVELS, index=0, key="target_level")
        submitted = st.form_submit_button("🔍 Analyze Target", use_container_width=True)

    if not submitted:
        return

    is_valid, error_message = validate_input(target, target_type)
    if not is_valid:
        st.error(error_message)
        return

    target = target.strip()

    t0 = time.perf_counter()
    with st.spinner("🔎 Gathering threat intelligence..."):
        results = collect_intelligence(target, target_type)
    t1 = time.perf_counter()

    render_results(target, target_type, knowledge_level, results, t0, t1)


def render_file_tab() -> None:
    st.caption(
        "Upload a file to check it against VirusTotal's file-scanning engines. "
        "Max 32MB. Files VirusTotal hasn't seen before may take a minute to finish scanning."
    )
    with st.form("file_scan_form"):
        uploaded_file = st.file_uploader("File to scan", type=None)
        knowledge_level = st.selectbox("Knowledge Level", KNOWLEDGE_LEVELS, index=0, key="file_level")
        submitted = st.form_submit_button("🔍 Scan File", use_container_width=True)

    if not submitted:
        return

    if uploaded_file is None:
        st.error("Please choose a file to scan.")
        return

    file_bytes = uploaded_file.getvalue()
    if len(file_bytes) > 32 * 1024 * 1024:
        st.error("That file is larger than 32MB, which VirusTotal's standard upload endpoint doesn't accept.")
        return

    t0 = time.perf_counter()
    with st.spinner("🔎 Scanning file..."):
        results = collect_file_intelligence(file_bytes, uploaded_file.name)
    t1 = time.perf_counter()

    render_results(uploaded_file.name, "File", knowledge_level, results, t0, t1)


def main() -> None:
    st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")
    inject_css()

    st.markdown('<div class="tl-title">🛡️ ThreatLens</div>', unsafe_allow_html=True)
    st.markdown('<div class="tl-subtitle">AI-POWERED THREAT INTELLIGENCE</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="tl-tagline">Analyze an IP, domain, URL, or file using multiple threat intelligence sources, explained by AI.</div>',
        unsafe_allow_html=True,
    )

    missing_keys = [
        name for name in ("VT_API_KEY", "GEMINI_API_KEY") if not get_secret(name)
    ]
    if missing_keys:
        st.warning(
            f"⚠ Missing secret(s): {', '.join(missing_keys)}. "
            "Add them in your Streamlit Cloud app's Settings → Secrets "
            "(or a local .streamlit/secrets.toml) before analyzing."
        )

    tab_target, tab_file = st.tabs(["🌐 Analyze Target", "📄 Scan File"])
    with tab_target:
        render_target_tab()
    with tab_file:
        render_file_tab()


if __name__ == "__main__":
    main()
