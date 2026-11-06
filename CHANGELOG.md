# Changelog

## 1.0.2 — Enterprise console visual refresh

- Replaced the warm orange palette with a restrained steel-blue, slate, and neutral-grey operations-console palette.
- Reduced decorative styling, corner rounding, and visual effects for a conventional enterprise security-tool appearance.
- Kept detection logic, API routes, and data handling unchanged.
- Updated the package version to `1.0.2`.


## 1.0.0 — NEXUS IDS rebrand and documentation refresh

- Rebranded the web dashboard and API identity as NEXUS IDS.
- Updated the installable distribution name and project metadata to `nexus-ids` version `1.0.0`.
- Refreshed the README and web-console guide with setup, architecture, technology, API, data-handling, limitations, and attribution details.
- Moved the default alert database location to `~/.nexus-ids/alerts.sqlite3` while retaining `SENTINEL_DB` as a compatibility override.
- Kept the established `sentinel` Python module and CLI invocation to preserve existing imports and workflows.
- Added assertions for the renamed web service identity and version.


## 0.2.0 — Web console integration

- Retained the upstream command-line packet analyzer, flow inspector, IDS engine, detectors, configurable TOML rules, live-capture code, and existing test suite.
- Added a FastAPI-based local web console for PCAP/PCAPNG upload and offline IDS analysis.
- Added SQLite persistence for alert metadata, severity filtering, summary statistics, and CSV export.
- Added API and web-console tests using synthetic captures.
- Updated README, Windows/Linux setup instructions, web API documentation, screenshot guidance, and attribution details.
- Corrected the package metadata to reference the retained `LICENSE.md` file and include the dashboard HTML in packaged distributions.

The upstream MIT copyright notice is retained. See `LICENSE.md` and the attribution section in `README.md`.
