# Scenario 2 — Brute Force

A single source IP issues a burst of failed SSH logins, escalating past
the 3-attempt threshold within a 60-second window. The detector
produces a series of escalating `BRUTE_FORCE` alerts as the window
grows. No correlation rule fires (no scan, no priv-esc), but the
threat-intel lookup still runs.

## Source IP

`198.51.100.22` (TEST-NET-2; per RFC 5737, safe for documentation).

## Logs

The `logs/` directory contains a populated `auth.log` with 6 failed
logins within ~30 seconds, plus empty `firewall.log` and `priv.log`.

To replay:

```bash
cp -r logs/* /path/to/socshield/logs/
python main.py
```

## Expected output

| Metric                      | Value                                   |
| --------------------------- | --------------------------------------- |
| Alerts raised               | 4 (3, 4, 5, 6 — window-grow alerts)     |
| Detector                    | `BRUTE_FORCE`                           |
| Severity                    | MEDIUM (3/4), HIGH (5/6)                |
| Source IP                   | `198.51.100.22`                         |
| MITRE technique             | `T1110`                                 |
| MITRE tactic                | `Credential Access`                     |
| Campaigns created           | 0 (no scan, no priv-esc)                |
| Threat-intel records        | up to 1                                 |

### Console snippet

```
[info] brute-force: scanned N failed-login events from auth.log
[info] brute-force: produced 4 alert(s)
[info] pipeline produced 4 alert(s)
[correlator] 0 campaign(s)
```

### Dashboard view

* `/alerts` — 4 rows for `198.51.100.22`, severities `MEDIUM MEDIUM HIGH HIGH`,
  MITRE `T1110` (Credential Access).
* `/incidents` — empty.
* `/mitre` — one covered technique (`T1110`), 4 observations.

## Variants

- Lower the threshold to 3 failed logins and add a 7th → severity
  scales to `CRITICAL` (≥ 8).
- Drop the time gap below 60 s but spread across multiple users →
  the same IP still trips the rule.
- Add a scan or priv-esc alert from the same IP within minutes →
  promotes to rule A (HIGH) or rule B (CRITICAL).
