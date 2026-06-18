# SOCshield

[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000.svg?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![SQLite](https://img.shields.io/badge/SQLite-3-003B57.svg?style=flat-square&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg?style=flat-square)](https://attack.mitre.org/)
[![Security Monitoring](https://img.shields.io/badge/SOC-monitoring-00d4ff.svg?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Status: Active](https://img.shields.io/badge/status-active-success.svg?style=flat-square)](#)

**An end-to-end, MITRE-mapped, threat-intel-enriched Security Operations Center
platform — built as a real product, not a demo.**

SOCshield ingests authentication, firewall, and privilege-escalation logs,
detects attacks with three independent rule families, correlates the
resulting alerts into multi-stage incident campaigns, enriches the source
IPs with AbuseIPDB + VirusTotal reputation, maps everything to
[MITRE ATT&CK](https://attack.mitre.org/), and serves the result on a
production-style analyst dashboard. One container, one process, one
`docker compose up`.

---

## Why this project

A SOC analyst's day is a sequence of hard questions:

1. *Did anything actually happen?* — filtering millions of log lines down to the alerts that matter.
2. *Is this related to anything else?* — turning isolated alerts into a single incident.
3. *Should I care?* — adding external context (IP reputation, MITRE mapping, country).
4. *What do I do?* — surfacing an investigation-ready timeline.

SOCshield is the minimum viable version of that workflow, in code, with a
dashboard you'd be willing to use on a Monday morning. The detection,
correlation, and threat-intel layers are real and unit-testable; the
dashboard is real and live; the Docker image is real and ships health
checks, persistent storage, and a one-command deploy.

---

## Features

- **Three independent detectors** — brute force (sliding window over
  failed logins), port scan (horizontal / vertical / SYN flood), and
  privilege escalation (suid / sudo / capability anomalies).
- **Three-rule correlation engine** that turns isolated alerts into
  multi-stage campaigns: rule A (scan → brute force), rule B (scan →
  brute force → priv-esc, "full intrusion"), and rule C (multiple
  critical priv-esc events, "insider threat candidate").
- **Threat intelligence enrichment** for every campaign source IP
  via AbuseIPDB + VirusTotal, with a 24-hour SQLite-backed cache and
  mock-mode fallback so the pipeline runs end-to-end without API keys.
- **MITRE ATT&CK mapping** baked in. Every alert and every campaign
  carries its technique id and parent tactic; the dashboard renders
  the full ATT&CK matrix and a coverage report.
- **Production analyst dashboard** — Flask + Bootstrap 5 + Chart.js,
  dark SOC theme, left sidebar, dense tables, monospace where it
  matters, real-time polling (30 s), paginated alerts, filterable
  threat-intel view, ATT&CK matrix view.
- **Docker-ready** — one process (`app.supervisor`) runs the
  monitoring service in a background thread and the dashboard in the
  foreground. Non-root user, tini as PID 1, health checks, named
  volumes for persistence, capability drops, log rotation.
- **Backup / restore** — online SQLite backup (safe while the DB is
  in use) and a tar.gz of every incident JSON, both with retention.
- **Strictly backward-compatible** — the legacy batch pipeline
  (`python main.py`) and the legacy service mode
  (`python main.py --service`) still work, unchanged.

---

## Architecture

```
   Logs ──► Parsers ──► Detectors ──► Alert Engine
                                       │
                                       ▼
                              ┌─────────────────┐
                              │   Correlator    │
                              │   (rules A/B/C) │
                              └────────┬────────┘
                                       │
                              ┌────────▼────────┐
                              │ Threat Intel    │
                              │ AbuseIPDB / VT  │
                              └────────┬────────┘
                                       │
                              ┌────────▼────────┐
                              │  SQLite (state) │
                              │  reports/*.json │
                              └────────┬────────┘
                                       │
                              ┌────────▼────────┐
                              │ SOC Dashboard   │
                              │ Flask + Chart.js│
                              └─────────────────┘
```

A more detailed diagram is in [docs/architecture.md](docs/architecture.md).
Mermaid source for every diagram lives in [docs/diagrams/](docs/diagrams/).

---

## Detection capabilities

| Detector              | Input                | Detection rule                                                                                       | MITRE   |
| --------------------- | -------------------- | ---------------------------------------------------------------------------------------------------- | ------- |
| Brute Force           | `logs/auth.log`      | ≥ 3 failed logins from one IP inside a rolling 60-second window; severity scales with attempt count  | T1110   |
| Port Scan — Horizontal| `logs/firewall.log`  | One source IP → many destination ports on one host                                                  | T1046   |
| Port Scan — Vertical  | `logs/firewall.log`  | One source IP → many destination hosts on one port                                                  | T1046   |
| Port Scan — SYN Flood | `logs/firewall.log`  | High-rate SYN packets from one source IP                                                            | T1046   |
| Privilege Escalation  | `logs/priv.log`      | suid set, unexpected sudoers, capability changes, root shell acquisition                             | T1068   |

All detectors return the same `Alert` dataclass — severity, source IP,
timestamp, MITRE technique + tactic, and a free-form description — so
the correlator and dashboard never need to special-case a detector.

---

## Threat intelligence

Every campaign source IP is enriched through:

- **AbuseIPDB** — abuse confidence score, total reports, country, ISP
- **VirusTotal** — reputation, malicious / suspicious counts
- **Local cache** (`threat_intel/cache.db`) — 24 h TTL, survives
  restarts, populated lazily on first lookup
- **Mock mode** — if no API keys are configured, the entrypoint
  auto-enables `SOCSHIELD_MOCK_TI=1` so the dashboard still shows
  realistic-looking data

The cache is keyed by IP, so the same attacker queried 100 times only
costs 1 external API call per 24 h.

---

## MITRE ATT&CK coverage

| Tactic                  | Technique  | Name                              | Detector               | Status   |
| ----------------------- | ---------- | --------------------------------- | ---------------------- | -------- |
| Reconnaissance          | T1046      | Network Service Discovery         | Port Scan (H/V/SYN)    | Covered  |
| Credential Access       | T1110      | Brute Force                       | Brute Force            | Covered  |
| Privilege Escalation    | T1068      | Exploitation for Privilege Escal.  | Privilege Escalation   | Covered  |

The current catalog covers the full external-to-internal kill chain.
Future techniques (persistence, lateral movement, exfiltration) are
tracked in [ROADMAP.md](ROADMAP.md).

---

## Dashboard screenshots

| | |
| --- | --- |
| **Overview** — KPI cards + six charts + recent alerts + latest incidents | ![dashboard](docs/screenshots/dashboard.png) |
| **Alerts** — paginated table with search, severity filter, sort | ![alerts](docs/screenshots/alerts.png) |
| **Incidents** — correlated campaigns as analyst-reviewable cards | ![incidents](docs/screenshots/incidents.png) |
| **Incident detail** — full attack chain, threat intel, correlated alerts | ![incident detail](docs/screenshots/incident_detail.png) |
| **Threat intel** — AbuseIPDB / VirusTotal reputation, filterable | ![threat intel](docs/screenshots/threat_intel.png) |
| **MITRE** — ATT&CK matrix + coverage charts + covered/gaps tables | ![mitre](docs/screenshots/mitre.png) |

The screenshot index is in [docs/screenshots/](docs/screenshots/).

---

## Installation

### Local (development)

Requires Python 3.12+.

```bash
git clone https://github.com/Hammad-karim/socshield.git
cd socshield

python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional: configure threat-intel API keys (otherwise mock mode kicks in)
cp .env.example .env
$EDITOR .env

# Generate a fresh alert + incident + coverage dataset
python main.py

# Start the dashboard
python run_dashboard.py
# → http://127.0.0.1:5000/
```

### Docker (production)

```bash
cp .env.example .env
$EDITOR .env                        # add your AbuseIPDB / VirusTotal keys

docker compose up -d --build

docker compose ps                   # STATUS should be "(healthy)"
curl http://127.0.0.1:5000/api/health
# → {"status":"ok", ...}

# Dashboard: http://127.0.0.1:5000/
```

Validate the deployment:

```bash
./scripts/validate_deployment.sh
```

Full deployment guide: [DEPLOYMENT.md](DEPLOYMENT.md).

### Vercel (serverless, dashboard-only)

A read-only dashboard is also deployable to [Vercel](https://vercel.com).
The deployment uses the same Flask app as Docker but with managed
Postgres (via Neon) for the alert store and threat-intel cache, since
Vercel's serverless filesystem is read-only except `/tmp`.

The dual-backend in `database/db.py` and `threat_intel/cache.py`
auto-selects Postgres when `DATABASE_URL` is set; otherwise it falls
back to the local SQLite file.

**One-time setup:**

1. Push the repo to GitHub (already done if you forked the original).
2. In Vercel → **Add New Project**, import the repo, leave all
   framework / build settings at their defaults — `vercel.json` and
   `api/index.py` configure everything.
3. In Vercel → **Storage** → **Marketplace** → install
   [**Neon Postgres**](https://vercel.com/marketplace/neon). The
   integration auto-creates a database, wires it to the project, and
   injects `DATABASE_URL` (and the rest of the `PG*` variables) into
   the deployment environment. No copy-paste needed.
4. (Optional) Add `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` under
   **Settings → Environment Variables** if you want live threat-intel
   lookups on Vercel. Without them, the dashboard renders but the
   threat-intel panel stays empty.
5. **Deploy**. The dashboard should be live at
   `https://<project>.vercel.app` within ~60 seconds.

**What runs on Vercel vs what doesn't:**

| Component | Vercel | Local / Docker |
| --- | --- | --- |
| Flask dashboard (`/`, `/alerts`, `/api/health`, …) | ✅ | ✅ |
| SQLite alerts DB | ❌ (read-only FS) | ✅ |
| Postgres alerts DB (via Neon) | ✅ | optional |
| Background monitoring service (`app/supervisor.py`) | ❌ (no long-lived threads in serverless) | ✅ |
| Detector pipeline (`python main.py`) | ❌ | ✅ |

The Vercel deployment is the **read-only dashboard** only. To run
detection, run `python main.py` (batch) or `python -m app.supervisor`
(real-time) on a Docker host, a VM, or any always-on environment, and
let the same Neon DB feed the deployed dashboard.

---

## Usage

### One-shot batch pipeline

```bash
python main.py
```

Runs every detector against the in-repo sample logs, prints the
alerts-by-detector + campaigns-by-rule summary, writes incident JSON
reports, and writes the MITRE coverage report. Exits non-zero if any
CRITICAL campaign was found.

### Real-time monitoring (long-running)

```bash
python main.py --service
```

Tails `logs/auth.log`, `logs/firewall.log`, `logs/priv.log`. Every
new line is parsed, every new alert is published on the bus, the
correlator updates its campaigns in real time, and a 5-second metrics
snapshot is printed to stdout. Stop with `Ctrl-C` (SIGINT) or
`SIGTERM` — the watchers, bus, and correlator all shut down cleanly.

Inside Docker, this is the default mode — the supervisor runs the
service in a background thread while the dashboard is the foreground
process.

### Dashboard

```bash
python run_dashboard.py --port 5000
# → http://127.0.0.1:5000/
```

| URL                | What it shows                                             |
| ------------------ | --------------------------------------------------------- |
| `/`                | Overview — KPIs, charts, recent alerts, recent incidents |
| `/alerts`          | All alerts (search, filter, sort, paginate)              |
| `/incidents`       | Correlated campaigns                                     |
| `/incident/<id>`   | One campaign — full timeline, threat intel, MITRE         |
| `/threat-intel`    | Cached AbuseIPDB + VirusTotal records                     |
| `/mitre`           | ATT&CK matrix + frequency charts + coverage tables        |
| `/api/health`      | Liveness probe (for Docker health checks)                 |
| `/api/health/deep` | Readiness probe (DB, TI cache, watcher logs, service)    |

---

## Example attack scenario

A complete end-to-end demonstration lives in [demo/](demo/). The short
version: an attacker IP `185.220.101.45` performs a horizontal port
scan against a host, then brute-forces authentication, then acquires
root. The pipeline produces:

```
[detector] BRUTE_FORCE: 6 alerts from 185.220.101.45 (peak severity HIGH)
[detector] PORT_SCAN:HORIZONTAL: 1 alert (severity MEDIUM)
[detector] PRIV_ESC: 4 alerts (severity CRITICAL)

[correlator] rule A (Port Scan + Brute Force)  -> HIGH
[correlator] rule B (Full Intrusion Chain)     -> CRITICAL

[threat intel] abuse_score=29, reports=120, country=FR, malicious=true
[mitre]       kill chain: Reconnaissance -> Credential Access -> Privilege Escalation
[dashboard]   /incident/185.220.101.45-ruleA-…
              /incident/185.220.101.45-ruleB-…
```

A full play-by-play is in [docs/walkthrough.md](docs/walkthrough.md)
and the demo data is in [demo/scenario_4_full_chain/](demo/scenario_4_full_chain/).

---

## Project layout

```
socshield/
├── app/                    # detection + service + dashboard
│   ├── models.py           # shared Alert dataclass
│   ├── orchestrator.py     # batch pipeline
│   ├── correlator.py       # rules A/B/C + streaming correlator
│   ├── mitre.py            # ATT&CK catalog + mapping
│   ├── metrics_engine.py   # thread-safe runtime counters
│   ├── event_bus.py        # sync pub/sub with per-subscriber threads
│   ├── service.py          # long-running monitoring service
│   ├── supervisor.py       # one-process service+dashboard supervisor
│   ├── watchers/           # auth / firewall / priv tail watchers
│   └── web/                # Flask dashboard (blueprints, templates, static)
├── database/db.py          # SQLite alerts store
├── detectors/              # three independent detectors
├── threat_intel/           # AbuseIPDB + VirusTotal + cache + enrichment
├── reports/                # incident JSONs + MITRE coverage
├── docs/                   # architecture, walkthrough, threat model, MITRE…
├── demo/                   # sample attack datasets (4 scenarios)
├── scripts/                # backup + validation scripts
├── logs/                   # tailed input logs
├── main.py                 # batch pipeline CLI
├── run_dashboard.py        # dashboard CLI
├── Dockerfile              # production image
├── docker-compose.yml      # one-command deploy
├── .env.example            # documented env vars
└── DEPLOYMENT.md           # deployment guide
```

---

## Security

- Non-root container user (uid 1000)
- `cap_drop: [ALL]` + `no-new-privileges` in compose
- Parameterised SQL everywhere (the dashboard's filter inputs go
  through a whitelist regex on top of `?`-style placeholders)
- TLS is terminated outside the container (the dashboard itself is
  HTTP only — put it behind nginx, Caddy, or a cloud LB in front)
- Secrets live in `.env` only; `.env` is git-ignored; the image has
  no baked-in credentials
- Online SQLite backup uses the `conn.backup()` API so the running
  service is never blocked during a backup

Full details in [DEPLOYMENT.md §8](DEPLOYMENT.md#8-security-hardening).

---

## Roadmap

- [ ] Persistence / Lateral Movement detectors
- [ ] Sigma-rule import (so users can extend detection without writing Python)
- [ ] EDR-style process tree ingestion
- [ ] Real-time WebSocket push (replacing the 30 s polling)
- [ ] SSO / OIDC on the dashboard
- [ ] Helm chart
- [ ] Multi-tenant role separation

See [ROADMAP.md](ROADMAP.md).

---

## Contributing

Issues and PRs are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).
Please don't open a PR that touches `detectors/*`, `app/correlator.py`,
`app/mitre.py`, or `app/web/templates/*` without an issue first — those
are the "detection contract" and the UI's information architecture, and
changes there need a discussion.

---

## License

[MIT](LICENSE).

---

## Author

Built as a portfolio project to demonstrate the full SOC engineering
loop: ingest, detect, correlate, enrich, map, surface, operate.

For resume bullets and a one-page summary, see
[docs/resume_bullets.md](docs/resume_bullets.md) and
[docs/project_summary.md](docs/project_summary.md).
