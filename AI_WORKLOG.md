# AI Engineering Worklog

## Audit record

- Date: 2026-11-13
- Audited base: `main` at `4505dd9bf3a91c14ce6c00639e5b8538c3d621a2`
- Review branch: `docs/portfolio-operating-kit-2026-11-13`
- Related pull request: [#3](https://github.com/Gitcoder12/CyberRadar/pull/3)
- Classification: threat-intelligence dashboard prototype
- Scope inspected: complete recursive tree, README, Streamlit app, dashboard, fetcher, configuration, requirements, audit router, open issue #1 and open PRs #2-#3.

## Confirmed findings

### P1 - External feed failures can be mistaken for complete intelligence

In `fetcher.py`, NVD errors are printed and then the function returns whatever partial results were accumulated. `fetch_kev_list()` catches all exceptions and returns an empty set. `enrich_with_epss()` silently ignores failed requests. Missing EPSS values are then treated as zero by `calculate_composite_risk()`. The dashboard does not expose a complete/partial/stale data status. This can silently understate risk or present incomplete feed coverage as current intelligence.

### P1 - No automated quality gate

The main tree contains no tests and no GitHub Actions workflow. No regression tests currently protect parsing, pagination, API failures, missing scores, or ranking behavior.

### P2 - Streamlit configuration path is malformed

The repository contains a root file named `.streamlit` with TOML theme content. Streamlit expects a `.streamlit/config.toml` file inside a `.streamlit/` directory. The current file is not at the expected configuration path.

### P2 - README links and license claims are inconsistent

The README's Live Demo badge links to the literal placeholder `YOUR_STREAMLIT_LINK_HERE`. Its badge says Apache 2.0 while the README body says MIT. Verify the actual LICENSE file and choose one accurate presentation before publishing.

### P2 - Feed and scoring semantics need clearer boundaries

The dashboard aggregates NVD, CISA KEV, EPSS, URLhaus and ransomware victim feeds. These sources have different update schedules and failure modes. The score is a project-defined prioritization heuristic, not a calibrated probability or proof of exploitability. Expose component availability, source timestamps, and score breakdowns.

## Verification

- Complete recursive tree and selected source/configuration files inspected.
- No local tests were run; no test suite exists on main.
- CI: NOT CONFIGURED on main.
- Independent review: NOT PERFORMED; PR #3 is documentation-focused.
- Live external API behavior: NOT TESTED during this audit.

## Next actions

1. Add typed adapters with explicit success, partial, stale, and failed states for each feed.
2. Never convert an unavailable KEV feed into an authoritative empty set; expose unknown status.
3. Preserve missing EPSS as unknown and exclude or clearly qualify the score rather than silently treating it as zero.
4. Add unit tests using clearly labeled fixtures for pagination, malformed responses, timeouts, and partial data.
5. Add CI, correct the Streamlit configuration path, fix the demo link placeholder, and reconcile the license badge/text.
6. Document source timestamps and heuristic score semantics.
