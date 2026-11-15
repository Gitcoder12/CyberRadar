# Project Status — CyberRadar

**Snapshot date:** 2026-11-16  
**Status type:** Initial documentation and repository-tree assessment  
**Default branch:** main  
**Review completeness:** Partial — not a code audit or release certification

## Project purpose
Streamlit vulnerability-intelligence dashboard intended to aggregate NVD, CISA KEV and FIRST EPSS data and prioritize CVEs.

## Current maturity (README-declared or visible scaffolding; not independently verified)
Root includes app.py, config.py, fetcher.py, models.py, dashboard.py and requirements.txt. README describes composite scoring and rate-limited API ingestion; no test folder or CI was visible in root.

## Observed repository structure
app.py, config.py, fetcher.py, models.py, dashboard.py, requirements.txt, .streamlit/, README.md and project guidance.

## Known issues and risks to investigate
README contains a placeholder demo URL (`YOUR_STREAMLIT_LINK_HERE`) and a license mismatch: badge says Apache 2.0 while the text says MIT; verify the actual LICENSE file. Composite score (CVSS 40%, EPSS 60%, KEV=100) needs normalized inputs, rationale, calibration and sensitivity analysis; not a universal risk truth. Validate NVD API time-window note, timestamps, missing EPSS values and stale cache behavior. No tests run.

## Recommended next actions
Resolve license statement from LICENSE file; replace demo placeholder only if a verified deployment exists; document exact score formula/normalization and KEV override; test API pagination, rate limits, missing/stale data and CVE ID joins; add snapshot fixtures and tests; expose source/timestamp for every CVE row.

## Verification record
| Check | Result |
|---|---|
| Default-branch top-level tree | Inspected |
| README | Inspected |
| Deep source review | Not performed |
| Tests / build / runtime | Not run |
| Data provenance / scoring validation | Not run |
| Security / dependency audit | Not run |
| Independent review | Not performed |

## Change log
- 2026-11-16: Added this initial status snapshot on a review branch. No application code or existing data changed.

> Update this file only after the corresponding inspection or verification has actually been performed. Distinguish observed facts, README claims, hypotheses and unrun checks.