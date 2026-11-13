# CyberRadar — README Explanation Draft

> Check against the actual source before merging into the main README.

## Plain-language explanation

A dashboard that collects public vulnerability records and helps defenders decide which known security issues deserve attention first.

## Current implementation

Streamlit application combining NVD CVE records, CISA KEV known-exploited status and FIRST EPSS probability signals into a prioritisation view. Any combined risk score is a project heuristic; it should expose component values, source timestamps, missing data and scoring rules.

## Technical/research explanation

Document the data flow, API contracts, source adapters, scoring/calibration logic, dependencies and error handling. Show a concrete example from input to output.

## Reproducibility

State exact setup/test commands, versions, dataset or API source, retrieval timestamp, configuration and expected output. Link benchmark results only when independently reproducible.

## Limitations

Explain missing sources, stale data, heuristic scores, uncertainty and unsupported use cases. For security and safety work, state that outputs are triage aids, not autonomous incident decisions.

## Contribution path

See FEATURE_UPGRADE_PLAN.md, CONTRIBUTING.md and ACTIVITY_LOG.md.
