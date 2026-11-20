The NVD API enforces a 120-day window per request, so the code pulls the maximum 3 months the public API allows. This is an API limitation, not a bug.
***

# 🛡️ CyberRadar

**Real-time vulnerability intelligence and risk prioritization.**

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

## Open CyberRadar locally (VS Code)

1. Clone the repository and open the folder in VS Code:

```bash
git clone https://github.com/Gitcoder12/CyberRadar.git
cd CyberRadar
```

2. Create and activate a virtual environment:

```bash
# Windows PowerShell
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies and start the dashboard:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run dashboard.py
```

4. Open **http://localhost:8501** in your browser if Streamlit does not open it automatically. Keep the terminal running while using CyberRadar; press **Ctrl+C** to stop it.

*Optional:* set `NVD_API_KEY` in your environment to reduce NVD rate-limit restrictions. The dashboard still depends on external threat-intelligence APIs.

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

---

## Engineering Audit & Handover — 2026-11-17

**Reviewed commit:** `4505dd9bf3a91c14ce6c00639e5b8538c3d621a2` (`main`). Static inspection covered `app.py` and `fetcher.py`; runtime tests were not executed.

### Confirmed findings
- The dashboard retrieves data from external threat-intelligence sources (including CISA KEV, URLhaus, and Ransomware.live) and applies cache windows. Displayed data is therefore dependent on upstream availability, source schemas, and cache freshness.
- The fetcher stops NVD pagination after an exception and returns whatever has already been collected; consumers need to distinguish partial results from a complete query.
- The dashboard's error paths return DataFrames containing an `Error` column. Downstream display/analysis code must handle these error-shaped results rather than assuming normal vulnerability columns.
- The reviewed code does not establish that every listed event is independently validated or that the dashboard is a complete threat-intelligence feed.

### Next actions
1. Surface source, retrieval timestamp, cache age, partial-result status, and upstream errors in the UI.
2. Add schema-drift and partial-pagination tests for each external feed.
3. Keep threat data as defensive intelligence; avoid implying that absence from these feeds means a system is safe.

**Verification status:** static source inspection only; live APIs, dashboard behavior, and tests remain unverified.

---

## Examples Used
- Prioritizing a CVE listed in CISA KEV
- Comparing CVSS severity with EPSS exploitation likelihood
- Reviewing vulnerability exposure across vendors and time windows
