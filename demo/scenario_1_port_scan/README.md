# Scenario 1 — Port Scan (Horizontal)

A single source IP sweeps multiple destination ports on one host.
Produces a `PORT_SCAN:HORIZONTAL` alert, no correlation rule fires
(there are no other alerts from this IP), and a threat-intel lookup
attempts a reputation check.

## Source IP

`203.0.113.50` (TEST-NET-3; per RFC 5737, safe for documentation).

## Logs

The `logs/` directory contains a populated `firewall.log` and empty
`auth.log` + `priv.log`. To replay:

```bash
cp -r logs/* /path/to/socshield/logs/
python main.py
```

## Expected output

| Metric                      | Value                                   |
| --------------------------- | --------------------------------------- |
| Alerts raised               | 1                                       |
| Detector                    | `PORT_SCAN:HORIZONTAL`                  |
| Severity                    | MEDIUM                                  |
| Source IP                   | `203.0.113.50`                          |
| MITRE technique             | `T1046`                                 |
| MITRE tactic                | `Reconnaissance`                        |
| Campaigns created           | 0 (rule A needs a brute-force alert)    |
| Threat-intel records        | up to 1 (AbuseIPDB + VirusTotal lookup) |

### Console snippet

```
[info] port-scan: scanned N firewall events from firewall.log
[info] port-scan: produced 1 alert(s)
[info] pipeline produced 1 alert(s)
[correlator] 0 campaign(s) (need PORT_SCAN + BRUTE_FORCE for rule A)
[threat intel] 203.0.113.50 abuse=N malicious=?
```

### Dashboard view

* `/alerts` — one row, source IP `203.0.113.50`, severity MEDIUM,
  detector `Port Scan — Horizontal`, MITRE `T1046` (Reconnaissance).
* `/incidents` — empty.
* `/mitre` — one covered technique (`T1046`), 1 observation.
* `/threat-intel` — one record (if the TI cache had room).

## Variants

- Increase `dport` count to 20 → severity stays MEDIUM but the alert
  title still says "Horizontal Port Scan from …" with 20 ports listed.
- Add a second destination IP for the same source IP (different
  `dst=`) within 60 s → still horizontal (same destination host), no
  second alert.
- Use distinct `dst=` values to pivot to a *vertical* scan — see
  scenario 4's firewall log for an example.
