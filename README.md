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


---

## Comparison with Existing Open-Source Projects

CyberRadar is documented as a vulnerability-intelligence dashboard that aggregates CVE and exploitation signals and ranks issues for defensive prioritization. The following projects provide adjacent vulnerability-management and intelligence references.

| Project | Established focus | Relationship to CyberRadar |
|---|---|---|
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Vulnerability management, findings aggregation and remediation workflows | A broader vulnerability-management platform; CyberRadar's stated focus is prioritizing public vulnerability intelligence from CVSS, EPSS and KEV signals. |
| [OWASP Dependency-Track](https://github.com/DependencyTrack/dependency-track) | Component inventory and software-supply-chain risk analysis | Focuses on known components and their vulnerabilities; CyberRadar is framed around an external threat-intelligence view rather than an application's SBOM alone. |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | Threat-intelligence collection and enrichment orchestration | A broader enrichment platform; CyberRadar aims for a focused dashboard and composite prioritization view. |

### Where CyberRadar is different
- **Exploit-aware prioritization:** the documented score combines CVSS severity, EPSS likelihood and CISA KEV presence to distinguish urgency from severity alone.
- **Multiple public intelligence feeds:** the project brings several external vulnerability/exploitation sources into one dashboard.
- **Analyst-oriented overview:** the UI is designed to help users filter, inspect and export prioritized vulnerability records.

### Where established projects are stronger
DefectDojo, Dependency-Track and IntelOwl have more extensive workflows, integrations and deployment maturity. CyberRadar should not claim to be a complete vulnerability-management or asset-risk platform; its score is a prioritization heuristic, not a substitute for environment-specific exposure analysis.

### Evidence and limitations
Display source, retrieval time, cache age, partial-result status and upstream errors for every feed. Publish the scoring formula and test boundary cases. A missing CVE in an upstream feed does not imply that a system is safe. This is a documented-scope comparison, not a threat-detection or remediation-effectiveness benchmark.
