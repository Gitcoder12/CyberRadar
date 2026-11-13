# CyberRadar — Feature Upgrade Plan

**Snapshot:** 2026-11-13

## Objective

A dashboard that collects public vulnerability records and helps defenders decide which known security issues deserve attention first.

## P0 — data integrity and correctness

- [ ] Record source timestamps, API status, pagination completeness and data freshness for every feed.
- [ ] Test scoring boundaries, missing EPSS/CVSS values, KEV precedence and stale-cache behavior.

## P1 — core workflow

- [ ] Make score components and rationale inspectable instead of hiding them in one number.
- [ ] Add robust retry, timeout, rate-limit and schema-change handling for upstream feeds.

## P2 — research and scale

- [ ] Benchmark prioritisation against a documented historical CVE set and analyst-reviewed labels.
- [ ] Add exportable, source-linked triage reports and a reproducible evaluation notebook.

## Collaboration work packages

1. Source/data validation and reproducible fixtures.
2. One isolated feature with deterministic regression tests.
3. Evaluation against a baseline or independently labelled sample.
4. Documentation of assumptions, provenance, uncertainty and limitations.

## Completion criteria

- [ ] Clean setup and one end-to-end workflow work.
- [ ] Tests cover valid, invalid, missing and adversarial inputs.
- [ ] External-data freshness and failures are visible.
- [ ] Claims are no stronger than the evidence.
