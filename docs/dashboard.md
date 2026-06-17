# SOCshield — SOC Analyst Dashboard

The dashboard is a Flask web application that consumes the existing
detection, correlation, threat-intel, and coverage pipeline and renders
the data for analyst review. It does **not** modify any detection or
correlation logic.

## Quick start

```bash
pip install -r requirements.txt
python run_dashboard.py --host 0.0.0.0 --port 5000
```

Open <http://127.0.0.1:5000/> in a browser.

## Routes

| Route                 | Purpose                                                       |
| --------------------- | ------------------------------------------------------------- |
| `/`                   | Dashboard homepage — KPIs + charts + recent alerts            |
| `/alerts`             | Paginated alert table with search, severity filter, sort      |
| `/incidents`          | Card list of all correlated campaigns (from JSON reports)     |
| `/incident/<id>`      | Analyst detail view: timeline, threat-intel, correlated alerts|
| `/threat-intel`       | Cached AbuseIPDB + VirusTotal reputation data                 |
| `/mitre`              | ATT&CK coverage matrix, tactic / technique frequency charts   |

## JSON API (used by the auto-refresh JS)

| Endpoint                  | Returns                                              |
| ------------------------- | ---------------------------------------------------- |
| `/api/summary`            | Dashboard KPI block                                  |
| `/api/alerts/recent`      | 10 most recent alerts                                |
| `/api/alerts/timeline`    | Hourly alert-count buckets                           |
| `/api/alerts/severity`    | Severity distribution                                |
| `/api/alerts/top-ips`     | Top attacker IPs                                     |
| `/api/alerts/tactics`     | Tactic distribution                                  |
| `/api/alerts/techniques`  | Technique distribution                               |
| `/api/alerts/countries`   | Attacks by country                                   |
| `/api/health`             | Liveness probe                                       |

## Project layout

```
app/web/
├── __init__.py          # create_app() factory
├── routes.py            # web + api blueprints
├── queries.py           # read-only data access (SQLite + reports)
├── helpers.py           # severity colors, formatting, validation
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── alerts.html
│   ├── incidents.html
│   ├── incident_detail.html
│   ├── threat_intel.html
│   ├── mitre.html
│   └── error.html
└── static/
    ├── css/socshield.css
    ├── js/socshield.js
    └── img/architecture.svg
```

## Security

* All SQL is parameterised (`?`-style placeholders); no string
  interpolation of user input.
* All free-form URL parameters (search, incident id, etc.) are
  whitelisted against a strict character class before being used.
* The `SECRET_KEY` is for cookie / session hygiene only; the dashboard
  itself is read-only and does not set cookies.
* Error handlers render a friendly error page; full stack traces are
  only logged server-side.

## Auto-refresh

The dashboard polls `/api/summary` and `/api/alerts/recent` every 30
seconds via `static/js/socshield.js`. The status pill in the navbar
flips to "Offline" if the requests fail.

## Architecture

```
Logs → Detectors → Alerts → Correlator → Threat Intel → Database → Dashboard
   └─ auth.log  └─ BRUTE_FORCE     ┐        ┌─ Campaigns         ┌─ /alerts
   └─ firewall  └─ PORT_SCAN       ├─ rules ├─ reports/*.json    ├─ /incidents
   └─ priv.log  └─ PRIV_ESC        ┘   A/B/C ┘                   └─ /mitre
                                                                  └─ /threat-intel
```

See `docs/architecture.svg` for the rendered diagram.
