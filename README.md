# CyberRadar

**Real-time vulnerability intelligence and risk prioritization.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red.svg)](https://streamlit.io/)

CyberRadar combines vulnerability records from the **NVD**, **CISA Known Exploited Vulnerabilities (KEV)** catalog, and **FIRST EPSS** to help prioritize newly published security issues. It enriches CVEs with severity, vendor, exploitation, and exploit-probability signals in an interactive dashboard.

## Features

- **Multi-source threat data** — retrieves CVEs from NVD and enrichment signals from CISA KEV and FIRST EPSS.
- **Composite risk score** — combines CVSS and EPSS; a KEV-listed CVE receives a score of 100.
- **Threat filtering** — filter by publication window, severity, and KEV status.
- **SOC-style dashboard** — severity radar, summary metrics, and vendor views.
- **Refresh and caching** — caches dashboard data for one hour and supports a manual refresh.
- **Export-ready analysis** — inspect enriched vulnerability records in a single dashboard view.

## Tech Stack

Python · Streamlit · Pandas · Plotly · Requests · Pydantic

## Quick Start

```bash
git clone https://github.com/Gitcoder12/CyberRadar.git
cd CyberRadar

python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS / Linux: source .venv/bin/activate

pip install -r requirements.txt
streamlit run dashboard.py
```

Open the local URL printed by Streamlit (usually `http://localhost:8501`).

## Configuration

Set an NVD API key to increase the available request rate:

```bash
# macOS / Linux
export NVD_API_KEY="your-key"

# Windows PowerShell
$env:NVD_API_KEY="your-key"
```

The dashboard also uses public CISA KEV and FIRST EPSS endpoints. External API availability, rate limits, and the amount of returned data can affect scan results.

## Project Structure

```text
CyberRadar/
├── app.py          # Application entry point
├── dashboard.py    # Streamlit dashboard
├── fetcher.py      # NVD, KEV, EPSS retrieval and enrichment
├── config.py       # API endpoints and request headers
├── models.py       # Vulnerability data model
├── requirements.txt
└── README.md
```

## Scope and Limitations

CyberRadar is a prioritization aid, not a vulnerability scanner or proof of exploitability. Its composite score is a project-defined ranking heuristic; it should not replace asset context, vendor advisories, patch validation, or a security team's risk assessment.

NVD, CISA, and EPSS data may be delayed, rate-limited, incomplete, or temporarily unavailable. Treat missing enrichment values as unknown rather than as evidence that a vulnerability is safe.

## License

MIT. See [LICENSE](LICENSE).
