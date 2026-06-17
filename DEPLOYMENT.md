# SOCshield — Deployment Guide

This document covers the supported ways to run SOCshield in production:
the recommended Docker Compose path, plus a local-development path
without containers.

The dashboard, the detection pipeline, and the threat-intel layer are
unchanged. This release only adds containerization, persistent
storage, health checks, and operational tooling.

---

## 1. Architecture at a glance

```
   ┌─────────────────────────────────────────────────┐
   │  Docker container (socshield)                    │
   │  ┌──────────────────────┐  ┌──────────────────┐ │
   │  │ Flask dashboard      │  │ Monitoring       │ │
   │  │ (gunicorn / flask)   │  │ service thread   │ │
   │  │ :5000                │  │ (watchers +      │ │
   │  │                      │  │ correlator)      │ │
   │  └──────────┬───────────┘  └────────┬─────────┘ │
   │             │ shared event bus / DB                │
   │  ┌──────────▼─────────────────────▼─────────────┐ │
   │  │ SQLite (alerts.db)  +  threat-intel cache     │ │
   │  └──────────┬────────────────────────────────────┘ │
   └─────────────┼──────────────────────────────────────┘
                 │ mounted volumes
   ┌─────────────▼──────────┐  ┌──────────────────────┐
   │ socshield_data         │  │ (host log sources,   │
   │  ├── alerts.db         │  │  bind-mounted, opt)  │
   │  ├── threat_intel_…    │  └──────────────────────┘
   │  ├── logs/             │
   │  └── reports/          │
   └────────────────────────┘
```

The whole stack runs as **one container** (one PID). Inside, the
[`app.supervisor`](app/supervisor.py) starts the monitoring service in
a background thread and the Flask dashboard in the foreground. A
single `docker stop` therefore cleanly tears down both halves.

---

## 2. One-command deployment (recommended)

```bash
# 1. Clone / copy the project
cd /opt
git clone <your-fork> socshield
cd socshield

# 2. Create the env file from the template and fill in your keys
cp .env.example .env
$EDITOR .env           # add ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY if you have them

# 3. Build + start
docker compose up -d --build

# 4. Watch the logs
docker compose logs -f socshield
```

Within ~20 seconds the dashboard should be reachable at
<http://127.0.0.1:5000/> and the health endpoint at
<http://127.0.0.1:5000/api/health>.

If you want the dashboard reachable from the network, edit
`docker-compose.yml` and change `"127.0.0.1:5000:5000"` to
`"5000:5000"`. **Do not expose the dashboard directly to the
internet** — put it behind a reverse proxy that terminates TLS and
adds authentication.

### Stop / restart

```bash
docker compose stop     # SIGTERM, graceful
docker compose start    # resume
docker compose down     # stop + remove container (volumes are kept)
docker compose down -v  # ⚠ also removes the socshield_data volume
```

---

## 3. Environment variables

All variables (and their defaults) live in [`.env.example`](.env.example).
The image's entrypoint loads them at startup. Critical ones:

| Variable                    | Default                                   | Notes |
| --------------------------- | ----------------------------------------- | ----- |
| `SOCSHIELD_DB_PATH`         | `/var/lib/socshield/alerts.db`            | Where the SQLite alerts store lives. Volume-mounted. |
| `SOCSHIELD_TI_CACHE_PATH`   | `/var/lib/socshield/threat_intel_cache.db`| Threat-intel cache. |
| `SOCSHIELD_LOGS_DIR`        | `/var/lib/socshield/logs`                 | Service + supervisor + startup logs. |
| `SOCSHIELD_REPORTS_DIR`     | `/var/lib/socshield/reports`              | Incident JSON + MITRE coverage. |
| `SOCSHIELD_AUTH_LOG`        | `${SOCSHIELD_LOGS_DIR}/auth.log`          | Tailed by the brute-force detector. |
| `SOCSHIELD_FIREWALL_LOG`    | `${SOCSHIELD_LOGS_DIR}/firewall.log`      | Tailed by the port-scan detector. |
| `SOCSHIELD_PRIV_LOG`        | `${SOCSHIELD_LOGS_DIR}/priv.log`          | Tailed by the priv-esc detector. |
| `FLASK_HOST` / `FLASK_PORT` | `0.0.0.0` / `5000`                        | Bind address. |
| `SOCSHIELD_SERVER`          | `flask`                                   | `flask` (dev) or `gunicorn` (prod). |
| `ABUSEIPDB_API_KEY`         | _empty_                                   | If both TI keys are empty, mock mode is auto-enabled. |
| `VIRUSTOTAL_API_KEY`        | _empty_                                   | |
| `SOCSHIELD_MOCK_TI`         | _auto_                                    | `1` to force mock threat-intel. |
| `SOCSHIELD_SEED_LOGS`       | `0`                                       | `1` to seed the persistent volume with the in-repo sample logs (first run only). |
| `SOCSHIELD_BACKUP_DIR`      | `/var/backups/socshield`                  | Where `scripts/backup_*` write to. |
| `SOCSHIELD_BACKUP_RETAIN`   | `14`                                      | Retention count for rotated backups. |

Secrets (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`) are **only** read
from the environment. They are not baked into the image and are
never logged.

---

## 4. Persistent storage

Three kinds of state survive a container restart:

| Volume mount            | What's in it                              | What you lose if you delete it |
| ----------------------- | ----------------------------------------- | ------------------------------ |
| `/var/lib/socshield`    | SQLite alerts DB, threat-intel cache,     | All alerts + all TI data + all |
| (named `socshield_data`)| service logs, report JSON files           | generated incident reports     |

Inspect the volume:

```bash
docker volume inspect socshield_data
docker run --rm -v socshield_data:/data alpine ls -la /data
```

To back up the volume, use the helper scripts (see §6).

---

## 5. Health checks

The container exposes two health endpoints:

| URL                     | Purpose                                         | Use this for |
| ----------------------- | ----------------------------------------------- | ------------ |
| `/api/health`           | Liveness — process is up                       | Docker `HEALTHCHECK`, load-balancer liveness probe |
| `/api/health/deep`      | Readiness — DB reachable, TI cache readable, watcher log files exist, monitoring service thread alive | Kubernetes readiness probe, alerting |

`/api/health` always returns `200` unless the process is wedged.
`/api/health/deep` returns `200` only when every component reports
healthy; otherwise it returns `503` and the body lists which
component failed.

The Dockerfile and `docker-compose.yml` both declare a healthcheck
that hits `/api/health` every 30 seconds. Inspect status:

```bash
docker compose ps                # STATUS column shows "(healthy)"
curl -s http://127.0.0.1:5000/api/health      | jq
curl -s http://127.0.0.1:5000/api/health/deep | jq
```

---

## 6. Backup and restore

Two purpose-built scripts live under [`scripts/`](scripts/):

| Script                    | Backs up                          | Method |
| ------------------------- | --------------------------------- | ------ |
| `backup_database.py`      | `alerts.db`                       | SQLite online backup API (`conn.backup()`) — safe while the DB is in use |
| `backup_reports.py`       | `reports/incidents/*.json` + `mitre_coverage.json` | tar.gz archive |
| `backup_all.sh`           | Both, in sequence                 | Cron-friendly wrapper |

Run from inside the running container (recommended — uses the same
filesystem layout):

```bash
docker exec -it socshield python /app/scripts/backup_database.py \
    --dest /var/lib/socshield/backups --retain 30

docker exec -it socshield python /app/scripts/backup_reports.py \
    --dest /var/lib/socshield/backups --retain 30
```

…or on the host, with the volume mounted:

```bash
docker run --rm -v socshield_data:/data:ro \
    -v /srv/backups:/backups \
    python:3.12-slim \
    bash -c "pip install ... && python /app/scripts/backup_database.py --source /data/alerts.db --dest /backups"
```

The simpler form is to schedule a cron job on the host that runs the
scripts against the volume mount:

```cron
# /etc/cron.d/socshield — daily 02:30
30 2 * * *  root  docker exec socshield python /app/scripts/backup_all.sh
```

### Restore

The DB backup is a normal SQLite file. To restore:

```bash
# 1. Stop the running container
docker compose stop socshield

# 2. Copy the desired backup over the live DB
docker run --rm -v socshield_data:/data \
    -v /srv/backups:/backups:ro \
    alpine cp /backups/socshield_alerts_20260617T081510Z.sqlite3 /data/alerts.db

# 3. Start the container
docker compose start socshield
```

Reports are stored under `/var/lib/socshield/reports/`; restore is a
straightforward `cp` from the archive's `reports/incidents/` and
`reports/mitre_coverage.json` paths.

---

## 7. Local development (no Docker)

You can still run SOCshield directly on the host without containers.
This is useful for development, testing, and CI:

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start the monitoring service in one terminal
python -m app.service

# Start the dashboard in another
python run_dashboard.py
```

The dashboard reads from the same on-disk SQLite file the service
writes to. State lives in the repo by default; set
`SOCSHIELD_DB_PATH`, etc. to relocate it.

---

## 8. Security hardening

The image is built with the following controls. None of these change
detection or correlation behavior; they only restrict what the
container can do.

| Control                          | Where it lives               | Why |
| -------------------------------- | ---------------------------- | --- |
| Non-root user (uid 1000)         | `Dockerfile` (`USER socshield`) | The app can read its DB but cannot tamper with the host |
| `cap_drop: [ALL]`                | `docker-compose.yml`         | Drop Linux capabilities; we only need outbound HTTPS |
| `security_opt: no-new-privileges`| `docker-compose.yml`         | Prevent setuid / file-cap escalation inside the container |
| Resource limits (1 CPU / 512 MB) | `docker-compose.yml`         | Stop a runaway loop in the dashboard from consuming the host |
| JSON log driver with rotation    | `docker-compose.yml`         | Cap on-disk log size; 3 × 10 MB files |
| Secrets in env, not in image     | `.env.example` + `docker-compose.yml` `env_file` | Real keys never enter `docker build` context |
| Parameterised SQL everywhere     | `app/web/queries.py`, `database/db.py` | Prevents SQLi in the dashboard's filter endpoints |
| Whitelisted input validation     | `app/web/routes.py` (regex on `q`, `incident_id`, `page`, `sort`) | Defence-in-depth on top of parametrised SQL |
| No outbound network beyond TI API| Default compose network + env keys | `internal: false` only because we need AbuseIPDB / VirusTotal; drop if running fully offline |
| Tini as PID 1                    | `Dockerfile` (`ENTRYPOINT ["/usr/bin/tini", ...]`) | Forwards SIGTERM to the supervisor so `docker stop` shuts down both the dashboard and the monitoring thread |

### Operating without internet

Set `SOCSHIELD_MOCK_TI=1` (or leave both API keys empty — the
entrypoint auto-enables mock mode) and the threat-intel layer returns
synthetic data so the rest of the pipeline is still exercised.

---

## 9. Troubleshooting

| Symptom                                      | Likely cause                                  | Fix |
| -------------------------------------------- | --------------------------------------------- | --- |
| Container exits with code 1 immediately     | DB init failed (path not writable)            | Check the `socshield_data` volume's permissions, or change `SOCSHIELD_DB_PATH` |
| `docker compose ps` shows `(unhealthy)`      | `/api/health` returning non-2xx               | `docker compose logs socshield`; look for tracebacks in the supervisor log |
| Dashboard shows "no alerts" after restart    | `SOCSHIELD_AUTH_LOG` etc. don't exist          | Either set `SOCSHIELD_SEED_LOGS=1` on first run, or bind-mount real log files (see the commented lines in `docker-compose.yml`) |
| Threat-intel rows are all empty              | No API keys AND no mock mode                  | Set `SOCSHIELD_MOCK_TI=1`, or supply at least one real key |
| `docker stop` takes > 10 s                   | Watchers haven't observed the stop event      | Acceptable; the supervisor has a 5-second grace period. Tune `GUNICORN_TIMEOUT` if using gunicorn. |
| `unable to open database file`               | Volume mounted read-only, or wrong user       | `chown -R 1000:1000 /var/lib/socshield` on the host |

### Useful commands

```bash
docker compose ps                   # container status + health
docker compose logs -f socshield    # live stdout
docker exec -it socshield bash      # shell into the container
docker exec socshield ls /var/lib/socshield  # inspect persistent state
docker stats socshield              # CPU + memory
```

---

## 10. Validation checklist

Before declaring a deployment successful, work through this list.
A small script that runs these checks is in §11.

- [ ] `docker compose up -d --build` exits 0
- [ ] `docker compose ps` shows `socshield` with status `(healthy)`
- [ ] `curl -fsS http://127.0.0.1:5000/api/health` returns `{"status":"ok",...}`
- [ ] `curl -fsS http://127.0.0.1:5000/api/health/deep` returns `200` and every component in `components` is `true`
- [ ] Browser opens <http://127.0.0.1:5000/> and renders the dashboard
- [ ] Browser opens <http://127.0.0.1:5000/alerts> and shows at least one row after `SOCSHIELD_SEED_LOGS=1` first run
- [ ] Browser opens <http://127.0.0.1:5000/incidents> and shows at least one correlated campaign
- [ ] Browser opens <http://127.0.0.1:5000/threat-intel> and shows at least one IP (real or mock)
- [ ] Browser opens <http://127.0.0.1:5000/mitre> and shows the ATT&CK matrix
- [ ] New alerts appear in the dashboard within ~30 s of writing to `SOCSHIELD_AUTH_LOG` / `SOCSHIELD_FIREWALL_LOG` / `SOCSHIELD_PRIV_LOG`
- [ ] `docker compose down` followed by `docker compose up -d` preserves all alerts and reports
- [ ] `docker exec socshield python /app/scripts/backup_database.py` writes a `.sqlite3` to the backup dir
- [ ] `docker exec socshield python /app/scripts/backup_reports.py` writes a `.tar.gz` to the backup dir
- [ ] No process inside the container runs as root (`docker exec socshield id` returns `uid=1000(socshield)`)

---

## 11. One-shot validation script

Save this as `scripts/validate_deployment.sh` (or run it inline) to
automate the checklist above:

```bash
#!/bin/sh
set -eu
HOST="${SOCSHIELD_HOST:-127.0.0.1:5000}"

echo "[1/8] container status"
docker compose ps socshield | tee /tmp/_ps.log
grep -q '(healthy)' /tmp/_ps.log || { echo "  ✗ not healthy"; exit 1; }

echo "[2/8] liveness"
curl -fsS "http://${HOST}/api/health" | tee /tmp/_h.json
grep -q '"status":"ok"' /tmp/_h.json || { echo "  ✗ liveness failed"; exit 1; }

echo "[3/8] readiness (deep)"
curl -fsS "http://${HOST}/api/health/deep" | tee /tmp/_d.json
grep -q '"status":"ok"' /tmp/_d.json || { echo "  ✗ deep check failed"; exit 1; }

echo "[4/8] dashboard renders"
curl -fsS "http://${HOST}/" -o /tmp/_dash.html
grep -q 'Security Operations Dashboard\|Overview' /tmp/_dash.html \
    || { echo "  ✗ dashboard render failed"; exit 1; }

echo "[5/8] alerts page renders"
curl -fsS "http://${HOST}/alerts" -o /tmp/_a.html
grep -q 'soc-table\|data-table' /tmp/_a.html \
    || { echo "  ✗ alerts page render failed"; exit 1; }

echo "[6/8] incidents page renders"
curl -fsS "http://${HOST}/incidents" -o /tmp/_i.html
grep -q 'incident-list\|incident-card' /tmp/_i.html \
    || { echo "  ✗ incidents page render failed"; exit 1; }

echo "[7/8] non-root user"
docker exec socshield id -u | grep -q '^1000$' \
    || { echo "  ✗ container runs as root"; exit 1; }

echo "[8/8] database is on the volume"
docker exec socshield ls -la /var/lib/socshield/alerts.db \
    || { echo "  ✗ alerts.db not on the persistent volume"; exit 1; }

echo
echo "All checks passed."
```

Run it from the project root:

```bash
chmod +x scripts/validate_deployment.sh
./scripts/validate_deployment.sh
```

---

## 12. Updating / redeploying

```bash
git pull                  # or copy the new files in
docker compose build      # rebuild the image
docker compose up -d      # restart with the new image (volumes are preserved)
```

The persistent volume `socshield_data` is **not** recreated, so all
alerts, reports, and threat-intel cache survive an upgrade.

---

## 13. File / directory map

| Path                            | Purpose |
| ------------------------------- | ------- |
| `Dockerfile`                    | Production image (python:3.12-slim, non-root) |
| `docker-compose.yml`            | Service definition, named volume, internal network |
| `.env.example`                  | Documented env variables (no secrets) |
| `.dockerignore`                 | Build context exclusions |
| `docker/entrypoint.sh`          | Pre-flight, dir creation, `exec python -m app.supervisor` |
| `app/supervisor.py`             | One-process supervisor: service thread + Flask dashboard |
| `app/web/health.py`             | Runtime health registry (read by `/api/health/deep`) |
| `app/web/routes.py`             | `/api/health` + `/api/health/deep` endpoints |
| `scripts/backup_database.py`    | Online SQLite backup |
| `scripts/backup_reports.py`     | tar.gz archive of incident JSON + MITRE coverage |
| `scripts/backup_all.sh`         | Cron-friendly wrapper |
| `scripts/validate_deployment.sh`| One-shot post-deploy validation |

---

## 14. Out of scope

This release does not change:

* Detection logic (`detectors/*`)
* Correlation logic (`app/correlator.py`)
* MITRE mapping (`app/mitre.py`)
* The dashboard's UI (`app/web/templates/*`, `app/web/static/*`)
* The orchestrator's CLI mode (`main.py`)

The detection / correlation / dashboard layers remain pure and can
still be used standalone (e.g. for unit tests, `main.py --service`,
or `python run_dashboard.py`).
