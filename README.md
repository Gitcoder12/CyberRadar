The NVD API enforces a 120-day window per request, so the code pulls the maximum 3 months the public API allows. This is an API limitation, not a bug.
***

# 🛡️ CyberRadar

**Real-time vulnerability intelligence and risk prioritization.**

[![Live Demo](https://static.streamlit.io/badges/streamlit_badge_black_red.svg)](YOUR_STREAMLIT_LINK_HERE)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

CyberRadar aggregates CVE data from NVD, CISA KEV, and FIRST EPSS to identify actively exploited vulnerabilities. It calculates a dynamic **Composite Risk Score** (CVSS + EPSS + KEV) to prioritize threats that are actually being weaponized.

## Features
- **Live Threat Intel:** Aggregates NVD, CISA KEV, and FIRST EPSS feeds.
- **Composite Risk Engine:** Weights CVSS (40%) and EPSS (60%). KEV-listed CVEs are forced to a score of `100`.
- **Solidifier Protocol:** Simulated WAF quarantine logic for exploited CVEs.
- **Interactive SOC Dashboard:** Polar Threat Radar, System Weakness Gauge, and Vendor Analysis.
- **Exportable:** Filter by severity/time and download CSV reports.
- **Resilient:** Built-in API rate limiting, pagination, and caching.

## Tech Stack
Python · Streamlit · Plotly · Pandas · Pydantic

## Quick Start
```bash
git clone https://github.com/Gitcoder12/CyberRadar.git
cd CyberRadar
pip install -r requirements.txt
streamlit run dashboard.py
```
*Note: Set `NVD_API_KEY` in your environment to bypass NVD rate limits.*

## License
MIT License


---

## AI-maintained project notes (secondary — 2026-11-13)

This section supplements the maintainer-authored README above. The original text has been restored verbatim from Git-history baseline `5cac0633648d3f716f9f0e44c6a4bf8cb2e1ee41`; this addendum does not replace or certify the original claims.

- The source tree, runtime data and tests are the implementation source of truth. Roadmap items, draft PRs and AI-generated descriptions are not shipped features by themselves.
- Preserve existing maintainer-provided data. Never replace real data with synthetic or placeholder records. Clearly label and isolate test fixtures.
- Mark unverified sources, IDs, records, metrics and external claims as unknown/unverified instead of guessing.
- Verify setup, execution, test commands and public claims against the exact current commit before using this project in a job, research or academic application.
- See [MODEL_AUDIT_ROUTER.md](MODEL_AUDIT_ROUTER.md) for the independent model review and merge gate.
