"""
app.py
------
ThreatLens — AI-powered threat intelligence dashboard (Streamlit).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

import streamlit as st

from sources import SOURCES, get_secret

try:
    from google import genai
except ImportError:
    genai = None


DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"

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


def render_api_key_sidebar() -> None:
    with st.sidebar:
        st.subheader("🔑 Your API Keys")

        st.caption(
            "Enter your API keys below. They are used only during "
            "your current Streamlit session."
        )

        st.text_input(
            "VirusTotal API Key",
            type="password",
            key="VT_API_KEY",
            placeholder="Enter VirusTotal API key",
        )

        st.text_input(
            "Gemini API Key",
            type="password",
            key="GEMINI_API_KEY",
            placeholder="Enter Gemini API key",
        )

        st.divider()

        st.caption(
            "VirusTotal API key: VirusTotal → Profile → API Key"
        )

        st.caption(
            "Gemini API key: Google AI Studio → API Keys"
        )


def validate_input(
    target: str,
    target_type: str
) -> tuple[bool, Optional[str]]:

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
            return (
                False,
                "Please enter a full URL, e.g. https://example.com/path"
            )

    else:
        return False, f"Unknown target type: {target_type}"

    return True, None


def collect_intelligence(
    target: str,
    target_type: str
) -> dict[str, dict]:

    target_type_key = target_type.lower()
    results: dict[str, dict] = {}

    for source_name, source_function in SOURCES.items():

        try:
            results[source_name] = source_function(
                target,
                target_type_key
            )

        except Exception as exc:
            results[source_name] = {
                "source": source_name,
                "success": False,
                "data": {},
                "error": f"Unexpected error: {exc}",
            }

    return results


def derive_verdict(
    results: dict[str, dict]
) -> tuple[str, str]:

    vt = results.get("VirusTotal")

    if not vt or not vt.get("success"):
        return "UNKNOWN", "LOW"

    data = vt.get("data", {})

    malicious = data.get("malicious")
    suspicious = data.get("suspicious")
    total = data.get("total_engines")

    if malicious is None and suspicious is None:
        return "UNKNOWN", "LOW"

    malicious = malicious or 0
    suspicious = suspicious or 0

    if malicious >= 5:
        return "MALICIOUS", "HIGH"

    if malicious >= 1:
        return "MALICIOUS", "MEDIUM"

    if suspicious >= 3:
        return "SUSPICIOUS", "MEDIUM"

    if suspicious >= 1:
        return "SUSPICIOUS", "LOW"

    if total:
        return "SAFE", "HIGH" if total >= 30 else "MEDIUM"

    return "SAFE", "LOW"


def _format_source_results(
    results: dict[str, dict]
) -> str:

    lines = []

    for source_name, result in results.items():

        lines.append(f"### {source_name}")

        if result.get("success"):

            data = result.get("data", {})

            if data:
                for key, value in data.items():
                    lines.append(f"- {key}: {value}")
            else:
                lines.append("- No data fields returned.")

        else:
            lines.append(
                f"- UNAVAILABLE: "
                f"{result.get('error', 'unknown error')}"
            )

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

    level_instructions = {
        "Beginner": (
            "Explain things in simple plain language for someone "
            "new to cybersecurity. Explain technical terms briefly. "
            "Keep the assessment concise."
        ),

        "Intermediate": (
            "Assume the reader understands basic cybersecurity. "
            "Discuss detection counts, reputation, registration "
            "information, and indicators using moderate technical "
            "terminology."
        ),

        "Advanced": (
            "Assume the reader has cybersecurity expertise. "
            "Discuss detection ratios, vendor consensus, reputation "
            "signals, registration anomalies, infrastructure indicators, "
            "and confidence limitations."
        ),
    }

    return f"""
You are a cybersecurity analysis assistant embedded in ThreatLens.

TASK:
Analyze the intelligence collected below about one target.

TARGET:
{target}

TARGET TYPE:
{target_type}

KNOWLEDGE LEVEL:
{knowledge_level}

PROGRAMMATIC VERDICT:
{computed_verdict}

PROGRAMMATIC CONFIDENCE:
{computed_confidence}

IMPORTANT:
The programmatic verdict is authoritative.
Do not override it.

Use ONLY the intelligence supplied below.

COLLECTED SOURCE RESULTS:
{_format_source_results(results)}

STRICT RULES:

- Do not fabricate threat intelligence.
- Do not assume missing information.
- Do not treat absence of detections as absolute proof of safety.
- Clearly distinguish observed facts from interpretation.
- If a source is unavailable, explicitly mention that.
- Do not invent information from unavailable sources.
- Keep the response concise.

AUDIENCE:
{level_instructions[knowledge_level]}

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
- <finding 3 if useful>

RECOMMENDED ACTION:
<1-2 sentences>
""".strip()


def get_gemini_model() -> str:

    try:
        configured_model = st.secrets.get(
            "GEMINI_MODEL",
            DEFAULT_GEMINI_MODEL
        )

        if configured_model:
            return str(configured_model).strip()

    except Exception:
        pass

    return DEFAULT_GEMINI_MODEL


def call_gemini(
    prompt: str,
    api_key: str
) -> tuple[Optional[str], Optional[str]]:

    if genai is None:
        return None, "google-genai package is not installed."

    if not api_key:
        return None, "No Gemini API key provided."

    model_name = get_gemini_model()

    try:

        client = genai.Client(
            api_key=api_key
        )

        response = client.models.generate_content(
            model=model_name,
            contents=prompt
        )

        text = getattr(
            response,
            "text",
            None
        )

        if not text:
            return None, "Gemini returned an empty response."

        return text.strip(), None

    except Exception as exc:
        return None, f"Gemini request failed: {exc}"


def parse_gemini_sections(
    text: str
) -> dict[str, str]:

    sections = {
        "SUMMARY": "",
        "KEY FINDINGS": "",
        "RECOMMENDED ACTION": "",
    }

    labels = [
        "VERDICT",
        "CONFIDENCE",
        "SUMMARY",
        "KEY FINDINGS",
        "RECOMMENDED ACTION",
    ]

    for index, label in enumerate(labels):

        remaining_labels = labels[index + 1:]

        if remaining_labels:

            lookahead = "|".join(
                re.escape(item)
                for item in remaining_labels
            )

            pattern = (
                rf"{re.escape(label)}:\s*"
                rf"(.*?)(?=(?:{lookahead}):|\Z)"
            )

        else:
            pattern = rf"{re.escape(label)}:\s*(.*)"

        match = re.search(
            pattern,
            text,
            re.DOTALL | re.IGNORECASE
        )

        if match and label in sections:
            sections[label] = match.group(1).strip()

    return sections


def inject_css() -> None:

    st.markdown(
        """
        <style>

        .verdict-card {
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.12);
            margin: 1rem 0;
        }

        .verdict-title {
            font-size: 0.85rem;
            letter-spacing: 0.08em;
            opacity: 0.75;
            text-transform: uppercase;
        }

        .verdict-value {
            font-size: 2rem;
            font-weight: 700;
            margin: 0.25rem 0;
        }

        .insight-card {
            border-radius: 16px;
            padding: 1.25rem 1.5rem;
            border: 1px solid rgba(120,120,255,0.25);
            background: rgba(120,120,255,0.06);
            margin-top: 1rem;
        }

        .insight-header {
            font-weight: 700;
            font-size: 1.05rem;
            margin-bottom: 0.5rem;
        }

        </style>
        """,
        unsafe_allow_html=True
    )


def render_verdict_card(
    verdict: str,
    confidence: str
) -> None:

    style = VERDICT_STYLES.get(
        verdict,
        VERDICT_STYLES["UNKNOWN"]
    )

    color = style["color"]
    icon = style["icon"]

    st.markdown(
        f"""
        <div class="verdict-card"
             style="
                 background-color: {color}22;
                 border-color: {color}77;
             ">

            <div class="verdict-title">
                Security Verdict
            </div>

            <div class="verdict-value"
                 style="color: {color};">
                {icon} {verdict}
            </div>

            <div>
                Confidence: {confidence.title()}
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )


def render_ai_insight(
    knowledge_level: str,
    sections: dict[str, str],
    raw_text: str
) -> None:

    summary = sections.get("SUMMARY") or raw_text
    findings = sections.get("KEY FINDINGS")
    action = sections.get("RECOMMENDED ACTION")

    st.markdown(
        '<div class="insight-card">',
        unsafe_allow_html=True
    )

    st.markdown(
        f"""
        <div class="insight-header">
            🤖 AI Security Insight ({knowledge_level})
        </div>
        """,
        unsafe_allow_html=True
    )

    st.write(summary)

    if findings:
        st.markdown("**Key Findings**")
        st.markdown(findings)

    if action:
        st.markdown(
            f"**Recommended Action:** {action}"
        )

    st.markdown(
        "</div>",
        unsafe_allow_html=True
    )


def render_source_results(
    results: dict[str, dict]
) -> None:

    st.subheader("Source Results")

    for source_name, result in results.items():

        with st.expander(
            source_name,
            expanded=False
        ):

            if result.get("success"):

                data = result.get(
                    "data",
                    {}
                )

                if not data:
                    st.info("No data returned.")

                else:

                    for key, value in data.items():

                        label = key.replace(
                            "_",
                            " "
                        ).title()

                        st.markdown(
                            f"**{label}:** {value}"
                        )

            else:

                st.warning(
                    f"{source_name} unavailable — "
                    f"{result.get('error', 'unknown error')}"
                )


def main() -> None:

    st.set_page_config(
        page_title="ThreatLens",
        page_icon="🛡️",
        layout="centered"
    )

    inject_css()
    render_api_key_sidebar()

    st.markdown(
        "<h1 style='text-align:center;'>🛡️ ThreatLens</h1>",
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <p style='text-align:center; opacity:0.75;'>
            AI-Powered Threat Intelligence
        </p>
        """,
        unsafe_allow_html=True
    )

    st.write(
        "Analyze an IP address, domain, or URL using "
        "VirusTotal and WHOIS, explained by AI."
    )

    with st.form("analyze_form"):

        target_type = st.radio(
            "Target Type",
            TARGET_TYPES,
            horizontal=True
        )

        target = st.text_input(
            "Target",
            placeholder=(
                "e.g. 8.8.8.8, example.com, "
                "https://example.com/login"
            )
        )

        knowledge_level = st.selectbox(
            "Knowledge Level",
            KNOWLEDGE_LEVELS,
            index=0
        )

        submitted = st.form_submit_button(
            "🔍 Analyze Target",
            use_container_width=True
        )

    if not submitted:
        return

    vt_api_key = st.session_state.get(
        "VT_API_KEY",
        ""
    ).strip()

    gemini_api_key = st.session_state.get(
        "GEMINI_API_KEY",
        ""
    ).strip()

    if not vt_api_key:
        st.error(
            "Please enter your VirusTotal API key in the sidebar."
        )
        return

    if not gemini_api_key:
        st.error(
            "Please enter your Gemini API key in the sidebar."
        )
        return

    is_valid, error_message = validate_input(
        target,
        target_type
    )

    if not is_valid:
        st.error(error_message)
        return

    target = target.strip()

    with st.spinner(
        "🔎 Gathering threat intelligence..."
    ):

        results = collect_intelligence(
            target,
            target_type
        )

    failed_sources = [
        name
        for name, result in results.items()
        if not result.get("success")
    ]

    if failed_sources:
        st.warning(
            f"⚠ {', '.join(failed_sources)} unavailable. "
            "Continuing with available sources."
        )

    verdict, confidence = derive_verdict(
        results
    )

    prompt = build_gemini_prompt(
        target=target,
        target_type=target_type,
        knowledge_level=knowledge_level,
        results=results,
        computed_verdict=verdict,
        computed_confidence=confidence
    )

    with st.spinner(
        "🤖 Generating AI insight..."
    ):

        gemini_text, gemini_error = call_gemini(
            prompt,
            gemini_api_key
        )

    st.divider()

    render_verdict_card(
        verdict,
        confidence
    )

    if gemini_error:

        st.error(
            f"AI insight unavailable — {gemini_error}"
        )

    elif gemini_text:

        sections = parse_gemini_sections(
            gemini_text
        )

        render_ai_insight(
            knowledge_level,
            sections,
            gemini_text
        )

    st.write("")

    render_source_results(results)


if __name__ == "__main__":
    main()
