# SOCshield — Project Summary

*One page. Recruiter-ready.*

---

## Problem

Modern SOCs sit on top of a firehose of authentication, firewall, and
host logs. The hard work is no longer *collecting* events — it's
turning those events into something an analyst can act on: which
alerts are real, which are part of the same campaign, whether the
actor is known-bad, and what the next step is.

Building that pipeline end-to-end — detection, correlation, threat
intel, MITRE mapping, dashboard — is the day job of a SOC engineer.
Most portfolios show one or two pieces. SOCshield shows the whole
loop.

## Solution

A self-contained, MITRE-mapped, threat-intel-enriched SOC platform
in a single Docker container:

```
Logs  →  Detectors  →  Alerts  →  Correlator  →  Threat Intel
                                                         │
                                                         ▼
                                                    SQLite + JSON
                                                         │
                                                         ▼
                                                    Dashboard
```

* Three independent detectors (brute force, port scan, privilege
  escalation) producing a shared `Alert` model.
* A correlation engine with three rules that turn isolated alerts
  into multi-stage campaigns (rule A: recon + cred; rule B: full
  intrusion; rule C: insider threat).
* Threat-intel enrichment via AbuseIPDB + VirusTotal, with a 24h
  cache and a mock-mode fallback so the pipeline runs without API
  keys.
* MITRE ATT&CK mapping baked in. Every alert, every campaign, and
  the dashboard's `/mitre` page are driven by the same catalog.
* A production-style analyst dashboard: dark SOC theme, left
  sidebar, dense tables, monospace where it matters, 30s auto-refresh.

## Key features

| Capability                  | Implementation                                                    |
| --------------------------- | ----------------------------------------------------------------- |
| Detection                   | 3 detectors, shared `Alert` dataclass, sliding-window + rule-based |
| Correlation                 | 3 rules, streaming + batch, MITRE-aware                           |
| Threat intel                | AbuseIPDB + VirusTotal, 24h SQLite cache, mock mode              |
| MITRE ATT&CK                | Central catalog, automatic technique/tactic tagging                |
| Dashboard                   | Flask + Bootstrap 5 + Chart.js, 6 routes + 9 API endpoints         |
| Real-time monitoring        | Event-bus-driven, threaded watchers, graceful shutdown             |
| Containerization            | python:3.12-slim, non-root, tini PID 1, healthcheck               |
| Persistent storage          | Named volume, online SQLite backup, tar.gz reports                |
| Production hardening        | `cap_drop: ALL`, `no-new-privileges`, JSON log driver             |
| Health checks               | `/api/health` (liveness) + `/api/health/deep` (readiness)         |

## Technologies used

**Languages & frameworks:** Python 3.12, Flask 3, Bootstrap 5,
Chart.js 4
**Storage:** SQLite (alerts + threat-intel cache)
**Concurrency:** `threading`, custom event bus, signal handling
**Networking:** outbound HTTPS for threat intel, Flask development
server (production: gunicorn)
**Containers:** Docker, Docker Compose
**External APIs:** AbuseIPDB, VirusTotal (both optional, mock-mode
fallback)
**Mapping:** MITRE ATT&CK (T1046, T1110, T1068 in v1)

## Cybersecurity concepts demonstrated

* **Detection engineering** — sliding-window brute force detection,
  port-scan classification (horizontal / vertical / SYN flood),
  privilege-escalation signal detection.
* **Correlation** — multi-rule correlation by source IP, three
  distinct rules producing different campaign narratives, MITRE
  kill-chain assembly.
* **Threat intelligence** — third-party reputation feeds, caching
  with TTL, mock-mode for offline operation, graceful degradation
  on provider failure.
* **MITRE ATT&CK** — technique / tactic mapping, coverage matrix,
  kill-chain extraction.
* **SOC operations** — incident detail page with timeline,
  narrative, threat intel, and correlated alerts; auto-refresh
  dashboard; severity-based prioritization.
* **Production engineering** — Docker, health checks, persistent
  volumes, online backups, structured logging, secure defaults.

## Potential real-world use cases

1. **Small-business SOC** — drop-in alerting for a single host or a
   small network where a full SIEM is overkill.
2. **CTF / training environment** — the showcase scenario in
   `demo/scenario_4_full_chain/` is a multi-stage attack chain
   suitable for SOC analyst training.
3. **Detection-content development** — extend `app/mitre.py` and
   `detectors/` to author new detections and immediately see them
   in the dashboard's coverage matrix.
4. **Compliance demo** — the audit trail (incident JSONs, MITRE
   coverage report) is suitable as evidence for SOC 2 / ISO 27001
   detection-coverage controls.
5. **Portfolio piece** — every layer of the SOC engineering loop,
   end-to-end, in code.

## Repo highlights

* `app/models.py` — shared `Alert` dataclass
* `app/correlator.py` — three correlation rules, streaming + batch
* `app/mitre.py` — central ATT&CK catalog + detector mapping
* `app/supervisor.py` — one-process supervisor (service + dashboard)
* `app/web/` — Flask dashboard, 6 routes + 9 API endpoints
* `detectors/` — three independent detectors
* `threat_intel/` — AbuseIPDB + VirusTotal + 24h cache
* `docs/` — architecture, walkthrough, threat model, MITRE coverage
* `demo/` — 4 ready-to-replay attack scenarios
* `Dockerfile` + `docker-compose.yml` — one-command production deploy
