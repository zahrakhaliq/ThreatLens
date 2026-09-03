# 🛡️ ThreatLens

AI-powered threat intelligence dashboard (Streamlit). Analyzes an IP / Domain / URL using **VirusTotal** + **WHOIS**, shows a color-coded verdict, and explains it via **Gemini** at your chosen knowledge level (Beginner/Intermediate/Advanced).


## Structure
```
threatlens/
├── app.py           # UI, validation, orchestration, Gemini logic
├── sources.py        # VirusTotal + WHOIS functions, SOURCES registry
└── requirements.txt
```
`app.py` → imports `sources.py`. `sources.py` kabhi `app.py` import nahi karta.

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

Browser mein `localhost:8501` khulega. Sidebar mein apni VT + Gemini API key daal kar target analyze karein.

## Add a new source (e.g. AbuseIPDB)

`sources.py` mein ek function likho + registry mein register karo — baqi kuch nahi badalna:

```python
def get_abuseipdb(target, target_type):
    return {"source": "AbuseIPDB", "success": True, "data": {...}, "error": None}

SOURCES["AbuseIPDB"] = get_abuseipdb
```

## Notes
- Gemini model name deprecate ho sakta hai — 404 error aaye to `app.py` mein `DEFAULT_GEMINI_MODEL` update karo.
- WHOIS IP addresses pe kaam nahi karta (sirf domain/URL).
- Source ya Gemini fail ho jaye to bhi app crash nahi hota.
