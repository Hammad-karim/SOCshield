# Scenario 3 — Privilege Escalation

A single source IP (a compromised host) acquires root through three
distinct mechanisms: a setuid bit on a binary, a modification of
`/etc/sudoers`, and a direct root shell acquisition. The detector
raises one `PRIV_ESC` alert per signal, all at `CRITICAL`. Two
critical priv-esc events from the same host trigger **rule C**
(insider threat candidate).

## Source IP

`10.0.0.99` — an internal host. Per RFC 1918 this is documentation-only
and never routed on the public internet; we use it here to make the
"internal" nature of the threat obvious.

## Logs

The `logs/` directory contains a populated `priv.log` with three
distinct priv-esc signals from `10.0.0.99`. To replay:

```bash
cp -r logs/* /path/to/socshield/logs/
python main.py
```

## Expected output

| Metric                      | Value                                   |
| --------------------------- | --------------------------------------- |
| Alerts raised               | 3                                       |
| Detector                    | `PRIV_ESC` (all three)                  |
| Severity                    | CRITICAL                                |
| Source IP                   | `10.0.0.99`                             |
| MITRE technique             | `T1068`                                 |
| MITRE tactic                | `Privilege Escalation`                  |
| Campaigns created           | 1 (rule C — insider threat candidate)   |
| Risk                        | CRITICAL                                |
| MITRE techniques in campaign| `T1068`                                 |
| MITRE tactics in campaign   | `Privilege Escalation`                  |
| Threat-intel records        | up to 1                                 |

### Console snippet

```
[info] priv-esc: produced 3 alert(s)
[info] pipeline produced 3 alert(s)
[correlator] rule C fires (≥ 2 CRITICAL PRIV_ESC) -> 10.0.0.99
```

### Dashboard view

* `/alerts` — 3 rows, all `CRITICAL`, MITRE `T1068` (Privilege Escalation).
* `/incidents` — 1 card, `CRITICAL`, source `10.0.0.99`, rule C,
  summary "Insider threat candidate at 10.0.0.99 (3 CRITICAL privesc)".
* `/incident/<id>` — three timeline entries (suid → sudoers → root shell),
  threat-intel enrichment for the host IP, narrative explaining the
  multi-stage escalation.

## Variants

- Remove one of the three priv-esc signals → only 2 alerts fire,
  but rule C still triggers (threshold is 2). Remove another → rule
  C no longer fires.
- Add an external scan from this IP first → rule C still fires, but
  if the external scan was from a *different* IP, then the existing
  alerts do not promote to rule A or B (rules A/B require same IP
  for all three families).
