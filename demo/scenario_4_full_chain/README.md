# Scenario 4 — Full Attack Chain

The SOCshield showcase. One source IP performs the canonical external-to-internal
kill chain:

```
Port Scan  →  Brute Force  →  Privilege Escalation
(T1046)       (T1110)          (T1068)
```

The correlator matches **rule A** (port scan + brute force → HIGH) and
**rule B** (full chain → CRITICAL) on the same `source_ip`. Two separate
incident cards are produced so the analyst can see both views.

## Source IP

`185.220.101.45` — a well-known TOR exit relay IP, used in many
threat-intel feeds. In mock mode the threat-intel enrichment returns
a representative record (`abuse_score=29, reports=120, country=FR`).
With real API keys it will return whatever AbuseIPDB / VirusTotal
currently report for this IP.

## Logs

To replay against your live SOCshield:

```bash
cp -r logs/* /path/to/socshield/logs/
python main.py
python run_dashboard.py --port 5000
# open http://127.0.0.1:5000/incidents
```

## Expected output

| Metric                            | Value                                                |
| --------------------------------- | ---------------------------------------------------- |
| Alerts raised                     | ~10 (1 port-scan, 4-6 brute-force window-grows, 4 priv-esc) |
| Detectors in play                 | `PORT_SCAN:HORIZONTAL`, `BRUTE_FORCE`, `PRIV_ESC`    |
| Source IP                         | `185.220.101.45`                                     |
| MITRE techniques                  | `T1046`, `T1110`, `T1068`                            |
| MITRE tactics                     | `Reconnaissance`, `Credential Access`, `Privilege Escalation` |
| Campaigns created                 | 2                                                    |
| Campaign 1 (rule A)               | risk = HIGH, 5–7 alerts, kill chain `Recon → Cred`    |
| Campaign 2 (rule B)               | risk = CRITICAL, all alerts, kill chain `Recon → Cred → PrivEsc` |
| Threat-intel records              | 1 (AbuseIPDB + VirusTotal)                           |
| Most common tactic                | `Credential Access` or `Privilege Escalation`        |
| Most common technique             | `T1068` or `T1110` (depends on alert counts)         |

### Console snippet

```
[info] pipeline produced N alert(s)
[info] correlator produced 2 campaign(s)
[correlator] rule A: 185.220.101.45 risk=HIGH
[correlator] rule B: 185.220.101.45 risk=CRITICAL
[threat intel] 185.220.101.45 abuse=29 reports=120 country=FR malicious=true
[mitre]       kill chain: Reconnaissance -> Credential Access -> Privilege Escalation
```

### Dashboard view

* `/alerts` — full table filtered to the source IP.
* `/incidents` — two cards side by side: rule A (HIGH) and rule B
  (CRITICAL). The risk badge in the rule B card is the only red one.
* `/incident/<ruleA-id>` — focused view on the scan + brute-force
  subset; rule name "Reconnaissance + Credential Attack", attack
  path "Reconnaissance → Credential Access".
* `/incident/<ruleB-id>` — full chain; rule name "Full Intrusion
  Chain", attack path "Reconnaissance → Credential Access →
  Privilege Escalation", threat-intel panel filled in.
* `/mitre` — all three techniques covered; matrix fully populated.
* `/threat-intel` — one record for `185.220.101.45` with the
  AbuseIPDB bar chart and country.

## Why this scenario is the demo

It's the only one that triggers every layer of the pipeline at once
and produces both correlation rules. Record the demo against this
scenario. The README's main walkthrough also uses it as the canonical
example.
