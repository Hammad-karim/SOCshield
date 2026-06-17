# Changelog

All notable changes to SOCshield are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial public release of the documentation set:
  - Top-level [README.md](README.md)
  - [docs/architecture.md](docs/architecture.md)
  - 5 Mermaid diagrams in [docs/diagrams/](docs/diagrams/)
  - [docs/walkthrough.md](docs/walkthrough.md)
  - [docs/mitre_coverage.md](docs/mitre_coverage.md)
  - [docs/threat_model.md](docs/threat_model.md)
  - [docs/project_summary.md](docs/project_summary.md)
  - [docs/resume_bullets.md](docs/resume_bullets.md)
  - [docs/demo_script.md](docs/demo_script.md)
- 4 replayable demo scenarios in [demo/](demo/)
- [CHANGELOG.md](CHANGELOG.md), [ROADMAP.md](ROADMAP.md),
  [CONTRIBUTING.md](CONTRIBUTING.md)

## [1.0.0] — 2026-06-17

### Added — Detection & correlation
- Brute force detector with sliding 60-second window, severity
  scaling at 3 / 5 / 8 attempts (MEDIUM / HIGH / CRITICAL).
- Port scan detector with three classifiers: horizontal,
  vertical, SYN flood.
- Privilege escalation detector (suid, sudoers, capabilities,
  root shell).
- Shared `Alert` dataclass with MITRE ATT&CK technique + tactic
  fields.
- Three-rule correlator (rule A: recon + cred → HIGH; rule B:
  full chain → CRITICAL; rule C: insider threat → CRITICAL).
- Streaming correlator (event-bus driven) and batch correlator
  (run-once for the CLI mode).
- Event bus: synchronous pub/sub, per-subscriber dispatcher
  threads, bounded queue, drop-on-overflow.

### Added — Threat intelligence
- AbuseIPDB provider (with mock-mode fallback).
- VirusTotal provider (with mock-mode fallback).
- 24-hour SQLite-backed cache.
- Auto-enable mock mode when no API keys are configured.
- `enrich_campaigns` step in the orchestrator.
- `compute_metrics` for top countries, average abuse score, highest
  risk attacker.

### Added — Storage
- SQLite schema for alerts (`database/alerts.db`).
- SQLite schema for the threat-intel cache
  (`threat_intel/cache.db`).
- On-disk JSON incident reports
  (`reports/incidents/incident_<ip>_rule<X>_<ts>.json`).
- MITRE coverage report (JSON + Markdown).

### Added — Service mode
- `app.service` runs the long-running pipeline: tail watchers,
  event bus, correlator, DB persister, metrics printer.
- Graceful SIGTERM / SIGINT shutdown.
- Rolling file + console logging.

### Added — Dashboard
- Flask app with blueprints (`app/web/`).
- 6 pages: Overview, Alerts, Incidents, Incident Detail, Threat
  Intel, MITRE.
- 9 JSON API endpoints (used by the auto-refresh JS).
- Bootstrap 5 dark SOC theme, slate + amber palette, left sidebar,
  dense monospace tables.
- Chart.js for 6 dashboard charts.
- 30 s auto-refresh of the KPI block and recent alerts.

### Added — Deployment
- `Dockerfile` (python:3.12-slim, non-root, tini PID 1,
  healthcheck).
- `docker-compose.yml` (single service, named volume, capability
  drops, isolated network).
- `.env.example` (all env vars documented).
- `.dockerignore`.
- `app.supervisor` (one-process supervisor: service thread +
  Flask dashboard).
- `docker/entrypoint.sh` (pre-flight, env load, dir creation,
  optional log seed, `exec` the supervisor).
- `scripts/backup_database.py` (online SQLite backup).
- `scripts/backup_reports.py` (tar.gz archive).
- `scripts/backup_all.sh` (cron-friendly wrapper).
- `scripts/validate_deployment.sh` (post-deploy smoke test).
- `DEPLOYMENT.md` (full deployment guide).

### Added — Security
- `/api/health` (liveness) and `/api/health/deep` (readiness).
- Parameterised SQL everywhere; whitelist regex on every free-form
  URL parameter.
- Container: `cap_drop: ALL`, `security_opt: no-new-privileges`,
  resource limits, JSON log rotation.
- Secrets read from `.env` only; never baked into the image.
- Strict environment handling: paths, log files, and config all
  relocate via env.

[Unreleased]: https://github.com/Hammad-karim/socshield/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Hammad-karim/socshield/releases/tag/v1.0.0
