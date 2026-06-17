# SOCshield — Analyst Walkthrough

A minute-by-minute account of how a SOC analyst uses SOCshield to
triage an incident. Built around the [showcase scenario](../demo/scenario_4_full_chain/README.md)
— a single external IP performing a port scan, brute force, and
privilege escalation against a host.

---

## Setup

```bash
# Run the showcase scenario end-to-end
cp -r demo/scenario_4_full_chain/logs/* logs/
python main.py
python run_dashboard.py --port 5000
```

Open <http://127.0.0.1:5000/>.

---

## T+0:00 — Open the dashboard

The SOC analyst's day starts at the overview. Six KPI cards across
the top, six charts underneath, and a recent-alerts table on the
right.

* **Total Alerts** — count of everything in the DB.
* **Critical** — alerts at `CRITICAL` severity. *If this is non-zero, start here.*
* **Active Attacker IPs** — source IPs that produced an alert in the
  last 60 minutes.
* **Incidents** — correlated campaigns on disk.
* **MITRE Techniques** — covered techniques / total catalog.
* **Avg Abuse Score** — average AbuseIPDB score across enriched IPs.

Below: alert volume (line chart), severity mix (donut), top attacker
IPs (bar), source geography (bar), tactic distribution, technique
distribution. After a fresh `python main.py` against the showcase
dataset:

* The donut shows a healthy mix of CRITICAL / HIGH / MEDIUM
  (CRITICAL is amber-underlined to draw the eye).
* The top-IPs bar has one long bar for `185.220.101.45`.
* The tactic distribution has three bars: Reconnaissance, Credential
  Access, Privilege Escalation.
* The technique distribution has three bars: T1046, T1110, T1068.

The analyst's first instinct is correct: the dashboard says
"something external hit one of our hosts, did recon, did a brute
force, and we have priv-esc alerts too."

## T+0:30 — Open the Incidents page

Navigate to **Incidents** in the sidebar. The showcase dataset
produces two cards for the same source IP:

* **Rule A — Reconnaissance + Credential Attack** (HIGH, 5–7 alerts)
  — the "scan + brute force" view.
* **Rule B — Full Intrusion Chain** (CRITICAL, all alerts) — the full
  kill chain including the priv-esc.

Both cards show:

* A risk badge (`HIGH` amber, `CRITICAL` red).
* The source IP in monospace.
* A kill-chain strip of colored dots (one per timeline step, tinted
  by severity).
* MITRE tactic and technique chips.

The two cards give the analyst two views of the same attack: the
narrower A view is the "did they get in?" question, the broader B
view is the "what did they do once they were in?" question.

## T+1:00 — Open the CRITICAL incident detail

Click the **Rule B** card (CRITICAL). The detail page renders:

### Header

* Source IP, risk badge, rule name, generation timestamp.
* A small KPI strip: "N alerts in chain", "M tactics observed",
  "K techniques observed" — at-a-glance scope.

### Narrative

A one-paragraph plain-English description of the campaign:

> "Full intrusion chain from 185.220.101.45: port scan -> brute
> force -> privilege escalation (N alert(s) across [...], peak
> severity CRITICAL). Window: ... -> .... ATT&CK kill chain:
> Reconnaissance -> Credential Access -> Privilege Escalation."

### Attack chain (left panel)

A vertical timeline of every alert in the campaign, in chronological
order. Each step shows the timestamp, detector, severity, and a
short title. The dots are tinted by severity — red for CRITICAL,
orange for HIGH, amber for MEDIUM.

### Threat intelligence (right panel)

For `185.220.101.45`, SOCshield has called AbuseIPDB and VirusTotal:

* Abuse score: 29 (Medium)
* Reports: 120
* Country: FR
* ISP: MockISP-Datacenter (in mock mode) or whatever AbuseIPDB
  returns
* VT reputation / malicious / suspicious counts
* Sources: `abuseipdb`, `virustotal`
* A fetched-at timestamp so the analyst knows how fresh the data is

This is the moment the analyst decides whether to escalate. A HIGH
abuse score and a VT malicious count of 7 — combined with the
"intrusion chain" narrative — is enough to page the on-call.

### Correlated alerts (full-width table)

Every alert that contributed to the campaign, in the same dense
format as `/alerts`. The analyst can read descriptions, click
through to filter, or export this view.

## T+2:00 — Open the MITRE coverage page

Switch to **MITRE** in the sidebar. The matrix is fully populated
because the showcase covers all three techniques. Each technique
card is bordered in amber (covered) with the observation count
underneath. The "Detection gaps" panel is empty.

This is the page the analyst uses to argue for new detections:
"we have 0 observations of T1059 (Command and Interpreter) — we
should add an EDR feed."

## T+3:00 — Open the Threat Intel page

Switch to **Threat Intel**. The single record for `185.220.101.45`
shows the abuse-score bar, the status badge (`MALICIOUS` because
the abuse score is ≥ 50 or VT malicious ≥ 3), the country, the ISP,
and the source list.

The filter row at the top lets the analyst slice the cached data:
search for a specific IP, filter by country, set a minimum abuse
score, or show only malicious entries.

## T+4:00 — Open the Alerts page

Switch to **Alerts**. The full table is paginated (25 per page by
default), with a search box, severity filter, sort, and direction
selectors. The analyst can:

* Filter to `CRITICAL` only — the priv-esc events surface
* Search `185.220` — all alerts from the offending IP
* Sort by `source_ip ASC` — group by attacker

The table is dense, monospace where it matters, and the severity
column is a 3px left border plus a small monospace label, not a fat
colored badge. This is the page the analyst uses as their
spreadsheet for an incident response.

## T+5:00 — The auto-refresh keeps it current

The dashboard polls `/api/summary` and `/api/alerts/recent` every
30 seconds. If a new alert arrives while the analyst is reading, it
appears in the recent-alerts table without a page reload. The status
pill in the sidebar stays "Live" as long as the polls succeed;
flips to "Offline" if the service is unreachable.

## T+10:00 — Wrap up and write the ticket

The analyst copies the attack-chain URL (`/incident/<id>`) and pastes
it into the IR ticket. The narrative + timeline + threat-intel
panel + correlated alerts is the single-page artifact for the
hand-off. The MITRE mapping is already in place, so the ticket
maps cleanly to the threat-intel team's taxonomy.

---

## Recap

The five steps the dashboard is designed to optimise:

1. **Notice** — KPI cards + auto-refresh make sure something loud
   is impossible to miss.
2. **Triage** — Incidents page sorts campaigns by risk, the
   kill-chain strip shows at a glance how serious the chain is.
3. **Investigate** — Incident detail has the narrative, the
   timeline, the threat intel, and the correlated alerts on one
   page.
4. **Contextualize** — MITRE + Threat Intel pages answer the
   "is this normal for us?" and "is this actor known?" questions.
5. **Hand off** — the URL is a single, complete artifact; the
   ticket is just a link.
