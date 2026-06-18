# SOCshield — Resume Bullets & Project Descriptions

Multiple variations of the same project, tuned for different surfaces.

---

## Resume bullets (technical)

Pick the ones that match the role you're applying for.

### For a SOC analyst / detection engineer role

* **Built an end-to-end MITRE-mapped SOC platform** (SOCshield) that
  ingests authentication, firewall, and host logs, runs three
  independent detectors, correlates the resulting alerts into
  multi-stage attack campaigns, enriches source IPs with AbuseIPDB
  and VirusTotal reputation data, and surfaces everything on a
  production-style analyst dashboard — all in a single Docker
  container with health checks, persistent storage, and online
  backup.
* **Implemented a three-rule correlation engine** that turns
  isolated alerts into named campaigns (Rule A: recon + credential
  access; Rule B: full intrusion chain; Rule C: insider threat
  candidate), with a streaming correlator that re-runs on every
  new alert and a batch correlator that runs the same logic over
  historical data.
* **Authored three independent detection rules** — sliding-window
  brute force, three-way port-scan classification (horizontal /
  vertical / SYN flood), and privilege-escalation signal detection
  — all emitting a shared `Alert` dataclass with MITRE ATT&CK
  technique + tactic tagging, persisted to a parameterised SQLite
  schema.
* **Designed and shipped a production-grade analyst dashboard**
  (Flask + Bootstrap 5 + Chart.js) with six KPI cards, six
  Chart.js charts, paginated / searchable alert tables, an
  ATT&CK coverage matrix, a threat-intel filter view, and a
  per-incident detail page with timeline + threat intel + correlated
  alerts.

### For a platform / SRE / DevSecOps role

* **Containerised and productionised a Python 3.12 SOC platform** —
  python:3.12-slim base, non-root user (uid 1000), tini as PID 1,
  layered dependency cache, .dockerignore context trimming,
  healthcheck on `/api/health` every 30s, and a one-process
  supervisor (`app.supervisor.py`) that runs the long-running
  monitoring service in a background thread and the Flask
  dashboard in the foreground — so a single `docker stop` shuts
  down both halves cleanly.
* **Hardened the Docker image with `cap_drop: ALL`,
  `security_opt: no-new-privileges`, named volumes for persistence,
  JSON log rotation (3 × 10 MB), resource limits (1 CPU / 512 MB),
  and an isolated bridge network** — every control verified by a
  one-shot post-deploy validation script
  (`scripts/validate_deployment.sh`).
* **Built a runtime health registry** (`/api/health` and
  `/api/health/deep`) that checks database connectivity, threat-intel
  cache reachability, watcher log file presence, and the
  monitoring-service thread heartbeat — used by Docker
  `HEALTHCHECK`, Kubernetes liveness / readiness probes, and the
  deployment validator.
* **Wrote online backup tooling** (`scripts/backup_database.py`,
  `scripts/backup_reports.py`) that uses SQLite's `conn.backup()`
  API so the database can be snapshotted while the dashboard is
  serving reads, with N-way retention, atomic temp-file rename,
  and a cron-friendly wrapper.

### For a security software engineer role

* **Designed the SOCshield detection pipeline as a clean-architecture
  stack** — detectors are pure functions returning shared `Alert`
  objects, the event bus is a thin synchronous pub/sub with
  per-subscriber dispatcher threads, the correlator is a separate
  pure module that the streaming and batch paths both consume, and
  the dashboard is a read-only consumer that never writes back to
  the alert store.
* **Implemented an MITRE ATT&CK catalog** (`app/mitre.py`) that is
  the single source of truth for technique / tactic mapping —
  detectors import it, the correlator enriches campaigns with it,
  the dashboard's coverage matrix renders from it, and adding a
  new detection is a one-line catalog change plus a new detector
  module.
* **Built a thread-safe runtime metrics engine**
  (`app/metrics_engine.py`) that tracks alert and incident rates
  over rolling windows (1 min / 1 h), counts active attacker IPs
  over a 5-min sliding window, and serialises to a JSON-snapshot
  format the dashboard's auto-refresh consumes every 30 s.

---

## LinkedIn project description (long form)

> **SOCshield — MITRE-mapped SOC platform**
>
> A self-contained, production-ready Security Operations Center
> platform built in Python 3.12. Ingests authentication, firewall,
> and host logs; runs three independent detectors (brute force,
> port scan, privilege escalation); correlates alerts into
> multi-stage attack campaigns via a three-rule engine; enriches
> every campaign source IP with AbuseIPDB + VirusTotal reputation;
> tags every alert with MITRE ATT&CK technique + tactic; serves
> the result on a Flask + Chart.js dashboard with auto-refresh.
>
> Highlights: clean-architecture detection pipeline (detectors →
> event bus → correlator → storage → dashboard), Docker-ready
> with one-process supervisor, persistent volumes, online SQLite
> backup, health checks, non-root container, capability drops.
>
> Stack: Python 3.12 · Flask 3 · Bootstrap 5 · Chart.js · SQLite ·
> Docker · AbuseIPDB · VirusTotal · MITRE ATT&CK
>
> See [the GitHub repo](https://github.com/Hammad-karim/socshield) for
> the full architecture, four replayable demo scenarios, the
> threat model, the MITRE coverage report, and the deployment
> guide.

## LinkedIn project description (short form)

> Built SOCshield — a production-style SOC platform that detects,
> correlates, enriches, and visualises multi-stage attacks end-to-end.
> Python 3.12, Flask, Docker, MITRE ATT&CK.

---

## GitHub repository description

The "About" box at the top of the GitHub repo (max 350 chars):

> MITRE-mapped SOC platform — log ingest, three-rule correlation,
> AbuseIPDB + VirusTotal enrichment, analyst dashboard. Dockerized,
> production-ready, no API keys required (mock mode). One
> `docker compose up`.

The website URL field can point to the rendered documentation site
or a short demo video.

---

## GitHub "Topics" (the tag pills on the right)

```
security
soc
siem
detection-engine
threat-intelligence
mitre-attack
flask
dashboard
docker
sqlite
```

---

## Cover-letter paragraph

> "I built SOCshield (linked from my GitHub) — a Docker-ready
> Security Operations Center platform that detects brute force,
> port scan, and privilege-escalation attacks, correlates them
> into multi-stage campaigns, enriches the source IPs with
> AbuseIPDB / VirusTotal, maps everything to MITRE ATT&CK, and
> renders the result on a production-style analyst dashboard. The
> whole stack — detectors, event bus, correlator, threat-intel
> layer, dashboard, supervisor, Docker image, health checks, online
> backup, and full documentation — is in one repo. The showcase
> scenario demonstrates a single attacker IP performing
> reconnaissance → credential access → privilege escalation,
> producing both a HIGH and a CRITICAL campaign, with full
> threat-intel enrichment and a single URL the analyst can hand
> off as the incident artifact."

---

## Interview talking points

When an interviewer asks "tell me about this project," here are the
narrative beats that show end-to-end ownership:

1. **The problem.** "Every SOC has the same problem: logs are
   cheap, but *decisions* are expensive. I wanted to build the
   minimum viable version of a SOC pipeline end-to-end."

2. **The detection contract.** "The hard design call was making all
   three detectors return the *same* `Alert` dataclass — same
   fields, same MITRE tagging. That let the correlator and the
   dashboard be detector-agnostic."

3. **Correlation, not aggregation.** "I could have just counted
   alerts. Instead I implemented three rules with different
   narratives: recon + cred = HIGH, full chain = CRITICAL,
   multiple critical priv-esc = insider threat. Same data, three
   stories."

4. **Threat intel as a cache.** "I wrapped AbuseIPDB + VirusTotal
   behind a 24-hour SQLite cache, with a mock-mode fallback. The
   pipeline runs end-to-end with zero API keys, and a real
   deployment only does 1 API call per IP per day."

5. **The dashboard.** "I designed it the way real SOC tooling looks:
   left sidebar, hairline borders, monospace for IPs / IDs /
   timestamps, severity as a 3px left border, not a fat colored
   badge. I deliberately stripped out all decorative "glow" and
   rainbow-stripe elements for a cleaner, professional look."
6. **Production engineering.** "One Docker container, one process,
   one supervisor that runs the monitoring service in a background
   thread and the dashboard in the foreground. Non-root,
   cap-drop, health checks, named volumes, online backup, full
   threat model, full deployment guide."

7. **Documentation as a feature.** "Architecture diagram, threat
   model, MITRE coverage report, analyst walkthrough, four
   replayable demo scenarios, resume bullets. The repo is meant
   to be read."
