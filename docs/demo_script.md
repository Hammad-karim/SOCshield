# SOCshield — Demo Video Script

A 4-minute walkthrough, optimised for screen-recording. The script
is shot against the [showcase scenario](../demo/scenario_4_full_chain/),
which is the only scenario that exercises every layer of the
pipeline at once.

**Format:** 4 minutes total. 8 sections. Two camera angles: terminal
+ browser. No voiceover script — just the on-screen action and
a one-line caption for each section.

---

## Pre-recording checklist

* [ ] Container is running: `docker compose ps` shows `(healthy)`.
* [ ] Dashboard is open: <http://127.0.0.1:5000/>.
* [ ] Database is wiped: `docker exec socshield rm -f /var/lib/socshield/alerts.db` (optional, for a clean first run).
* [ ] Screen recorder is set to 1920×1080, 30 fps.
* [ ] Microphone is muted (or tested and clean).
* [ ] Notifications are off.

## Section 1 — Problem (0:00–0:25)

**Caption:** *The hard part of a SOC is not collecting logs — it's turning them into decisions.*

**On screen:** A terminal showing three `tail -f` panes
(`auth.log`, `firewall.log`, `priv.log`) scrolling with hundreds
of lines per second.

**Action:** Hold for 10 s, then cut.

## Section 2 — Architecture (0:25–0:55)

**Caption:** *SOCshield is a self-contained SOC platform in a single Docker container.*

**On screen:** the rendered Mermaid diagram from
[`docs/diagrams/01_system_architecture.md`](diagrams/01_system_architecture.md).
Highlight the data flow with the cursor (Logs → Detectors →
Correlator → Threat Intel → Database → Dashboard).

**Action:** 30 s, with the cursor tracing the data path.

## Section 3 — Detection (0:55–1:30)

**Caption:** *Three independent detectors, one shared alert model.*

**On screen:** terminal at the repo root.

**Action:**

```bash
cp -r demo/scenario_4_full_chain/logs/* logs/
python main.py
```

Pause on each line of the output:

* "brute-force: scanned N failed-login events"
* "port-scan: produced 1 alert(s)"
* "priv-esc: produced 4 alert(s)"
* "pipeline produced N alert(s)"

Then the correlator output:

* "Correlated campaigns: 2"
* "  - Rule A   : 1"   (Port Scan + Brute Force)
* "  - Rule B   : 1"   (Full Intrusion Chain)

Then the threat-intel block:

* "Average abuse score: 29.0"
* "Highest-risk attacker: 185.220.101.45 (risk=HIGH, abuse_score=29)"

Then the MITRE block:

* "Techniques covered: 3 / 3 (100%)"
* "Observed kill chain: Reconnaissance → Credential Access → Privilege Escalation"

## Section 4 — Correlation (1:30–2:00)

**Caption:** *Three rules turn isolated alerts into named campaigns.*

**On screen:** the incidents list. Or, if you're in the terminal,
the campaign JSON files:

```bash
ls reports/incidents/
cat reports/incidents/incident_185.220.101.45_ruleB_*.json | python -m json.tool
```

**Action:** Highlight the campaign dict, point out `rule_id`, `risk`,
`mitre_techniques`, `mitre_tactics`, `attack_path`, and the nested
`threat_intel` block.

## Section 5 — Threat intelligence (2:00–2:25)

**Caption:** *One external IP, two providers, one normalised record.*

**On screen:** the threat-intel page in the browser.

**Action:** Show the `185.220.101.45` row — the abuse-score bar in
amber, the `MALICIOUS` badge (because the abuse score is ≥ 50 in
the mock), the country / ISP / VT-reputation fields. Toggle the
"malicious only" filter on to show the filter works.

## Section 6 — Dashboard (2:25–3:30)

**Caption:** *What the analyst sees, all in one place.*

**On screen:** the dashboard at <http://127.0.0.1:5000/>.

**Action:**

1. **Overview tab.** 10 s. Point at the six KPI cards (Total
   Alerts, Critical, Active Attacker IPs, Incidents, MITRE
   Techniques, Avg Abuse Score). Then the six charts. Then the
   recent-alerts table on the right.

2. **Alerts tab.** 10 s. Filter to `CRITICAL`. Show the dense
   table. Sort by source IP. Show the search box filtering to
   `185.220`.

3. **Incidents tab.** 15 s. Show the two cards. Click the CRITICAL
   one (Rule B). Land on the incident detail page. Show the
   attack-chain timeline on the left, the threat-intelligence
   panel on the right, the correlated alerts table at the
   bottom.

4. **MITRE tab.** 10 s. Show the three technique cards in the
   matrix, each in amber (covered). Show the frequency charts
   underneath. Show the "Detection gaps" panel — empty.

5. **Threat Intel tab.** 5 s. Already covered; quick re-show.

## Section 7 — Live ingestion (3:30–4:00)

**Caption:** *The same pipeline, running live, against a tail of real logs.*

**On screen:** terminal.

**Action:**

```bash
# In one terminal
python main.py --service

# In another, append a new line to the brute-force log
echo "2026-06-18 13:00:00 WARN sshd Failed login user=admin ip=192.0.2.99 method=password" \
    >> logs/auth.log
```

Switch to the dashboard. The new alert should appear in the
recent-alerts table within 30 s (the auto-refresh interval).
Highlight this.

**Cut.**

## Section 8 — Wrap (4:00–4:15)

**Caption:** *One container. One process. `docker compose up`.*

**On screen:** terminal.

**Action:**

```bash
docker compose ps
```

Show the `(healthy)` status. Show the `docker compose logs` tail.
Cut to the GitHub repo's README header. End card.

---

## Recording notes

* **Resolution:** 1920 × 1080 minimum. The dashboard looks best at
  1440 wide.
* **Frame rate:** 30 fps is plenty. No need for 60.
* **Tooling:** OBS Studio (free), or QuickTime on macOS, or
  `ffmpeg -f gdigrab -i desktop` for scripted capture.
* **Audio:** optional. The captions cover the same ground.
* **Length tolerance:** ± 30 s on each section. The hard total
  budget is 5 minutes.
* **Pacing:** when in doubt, slow down. A 4-minute demo that
  breathes is better than a 3-minute demo that races.
