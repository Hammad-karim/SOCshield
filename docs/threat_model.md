# SOCshield — Threat Model

This document describes what SOCshield protects, who it protects
against, what it can and cannot detect, and the residual risks an
operator should be aware of.

It is intentionally scoped to SOCshield *as a product*: the SOC
operator's environment (the things being detected) is the asset, the
attackers using public network / leaked credentials / host
vulnerabilities are the threat actors.

---

## 1. Assets

SOCshield protects the visibility of an environment, not the
environment itself. The assets are:

| Asset                                | Sensitivity | Where it lives                       |
| ------------------------------------ | ----------- | ------------------------------------ |
| **Log files** (auth / firewall / priv)| Medium      | `logs/` (or Docker volume)           |
| **SQLite alert store** (`alerts.db`) | High        | `database/alerts.db` (Docker volume) |
| **Threat-intel cache**               | Medium      | `threat_intel/cache.db`              |
| **Incident JSON reports**             | High        | `reports/incidents/*.json`           |
| **MITRE coverage report**            | Low         | `reports/mitre_coverage.json`        |
| **Service configuration / .env**      | High        | `.env` (never in image)              |
| **Threat-intel API keys**            | Critical    | `.env` / Docker secrets              |
| **Dashboard session**                 | Low         | No state; read-only cookie optional  |

The dashboard is read-only; loss of confidentiality of an incident
JSON is more damaging than loss of integrity (an attacker who can
rewrite an incident JSON can suppress the audit trail of their
actions).

## 2. Threat actors

| Actor                 | Capability     | Motivation                | Likely actions                                                |
| --------------------- | -------------- | ------------------------- | ------------------------------------------------------------- |
| **External attacker** | Low–High       | Initial access, exfil     | Recon, brute force, exploit                                  |
| **Malicious insider** | Medium         | Privilege abuse, theft    | Privilege escalation from a compromised account              |
| **Compromised host**  | Low–Medium     | Lateral movement         | Scan, brute force, escalate, beacon                          |
| **Automated scanner** | Low            | Discovery, future target  | Port scans, low-and-slow credential stuffing                  |
| **Compromised operator account** | High | Cover tracks, data theft | Delete / truncate logs, modify reports, change alert configs |

## 3. Attack paths (the kill chain)

The MITRE-mapped path that SOCshield is built to surface:

```
[1] Reconnaissance     T1046  PORT_SCAN:*
        │  source IP discovered
        ▼
[2] Credential Access  T1110  BRUTE_FORCE
        │  credentials obtained
        ▼
[3] Privilege Escal.   T1068  PRIV_ESC
        │  host compromised
        ▼
    (lateral movement, exfil, etc. — out of scope in v1)
```

SOCshield's correlator encodes this chain as **rule B** ("Full
Intrusion Chain", CRITICAL). The earlier sub-chain (scan + brute
force) is **rule A** (HIGH) and triggers if the priv-esc step is
missing. Multiple critical priv-esc events from a single source IP
trigger **rule C** (insider threat candidate).

## 4. Security assumptions

SOCshield assumes:

1. **Log integrity is preserved up to the watcher.** The watcher
   tails the file at EOF, never reads the file out of order, and
   detects rotation. An attacker with write access to the log file
   can suppress detections — this is *out of scope* for SOCshield
   and is a host-level concern (append-only forwarding, separate
   log server, etc.).
2. **The host running SOCshield is not the same host being
   monitored.** A compromised host that runs SOCshield can tamper
   with alerts before they hit the bus.
3. **The dashboard network is trusted.** The dashboard binds to
   `0.0.0.0:5000` and serves HTTP only. In production, an operator
   puts it behind a reverse proxy that terminates TLS and adds
   authentication. SOCshield itself does not authenticate dashboard
   users.
4. **The SQLite database is the single source of truth for
   alerts.** Backups are taken on the operator's schedule. If
   `alerts.db` is lost between backups, the corresponding alert
   history is lost; the in-memory bus state is already gone on
   restart.
5. **API keys are kept out of the image and out of source
   control.** They live in `.env` or in the host's secret store.

## 5. Detection coverage (what we detect)

| Vector                        | Detector            | Where                                | MITRE   |
| ----------------------------- | ------------------- | ------------------------------------ | ------- |
| External port scan (H/V/SYN)  | port_scan_detector  | `logs/firewall.log`                  | T1046   |
| SSH / login brute force       | brute_force_detector| `logs/auth.log`                      | T1110   |
| suid / sudoers / cap / root   | priv_esc_detector   | `logs/priv.log`                      | T1068   |
| Multi-stage campaign          | correlator          | derived from above                   | (chain) |
| Known-malicious IP            | threat_intel        | AbuseIPDB + VirusTotal lookups       | n/a     |

For each of these, the pipeline emits:

* a structured `Alert` with severity, source IP, MITRE fields, and
  an evidence description;
* a SQLite row in `alerts` (timestamp, ip, detector, severity, title,
  description);
* for matched correlation rules, a `Campaign` written to
  `reports/incidents/incident_<ip>_rule<X>_<ts>.json`.

## 6. Detection gaps (what we do NOT detect)

SOCshield is *intentionally narrow*. It is not a SIEM; it does not
ingest EDR, email gateway, or cloud audit logs. The following are
deliberately out of scope in v1:

* **Insider misuse that does not trigger a priv-esc signal** — e.g.
  data exfiltration by a privileged user who already has the access.
* **Web-application attacks** (SQLi, XSS, SSRF) — no HTTP-layer
  ingest.
* **Phishing / credential capture from email** — no email ingest.
* **Lateral movement** (T1021, T1570) — no host-isolation ingest.
* **Persistence** (T1543, T1547) — no autostart-execution ingest.
* **Defense evasion** (T1070 log tampering, T1027 obfuscation) —
  no host-integrity ingest.
* **C2 / exfil** (T1071, T1041) — no network-beaconing detection
  beyond what AbuseIPDB / VirusTotal reputation provides.
* **Cloud control-plane attacks** (AWS, Azure, GCP) — no cloud
  audit ingest.

These are tracked in [ROADMAP.md](../ROADMAP.md).

## 7. Residual risks

Even with SOCshield in place, the following risks remain:

| Risk                                                      | Likelihood | Impact    | Mitigation (out of scope for SOCshield) |
| --------------------------------------------------------- | ---------- | --------- | -------------------------------------- |
| **Log tampering by an attacker on the monitored host**    | Medium     | High      | Forward logs over the network to a separate collector; sign logs at source. |
| **Tampering with `alerts.db` on the SOC host**            | Low        | High      | Run SOCshield on a hardened, dedicated host; offline backups (already implemented). |
| **Compromise of the SOC operator's session**              | Low–Medium | High      | SSO / MFA on the dashboard (see [ROADMAP.md](../ROADMAP.md) — SSO is a planned feature). |
| **Threat-intel provider compromise / poisoning**         | Low        | Medium    | Cross-check two providers; pin a specific API version; periodically re-validate cached entries. |
| **Detector evasion by a sophisticated attacker**          | Medium     | Medium    | Layered detections; Sigma rules; behavioral baselining (future work). |
| **Container escape from the SOC host**                    | Low        | High      | Hardened base image, no-new-privileges, cap_drop ALL, image scanning (Snyk / Trivy). |
| **API key leak via logs / error pages**                   | Low        | High      | Never log env vars; never echo `Authorization` headers; ensure error pages don't include the request body. |
| **Backup poisoning** (attacker modifies both DB and backups) | Very low | High   | Store backups on a separate, write-once or off-host store; periodically test restore from cold. |

## 8. Container-specific threat model

The Docker image adds a small additional surface:

* **Build-time secrets in image history.** Mitigation: the
  `.dockerignore` excludes `.env`; the Dockerfile never reads it.
* **Container escape via the `python:3.12-slim` base.** Mitigation:
  `cap_drop: ALL`, `no-new-privileges`, non-root user, no mount of
  the host filesystem except the persistent volume.
* **Bind-mounted host log files.** If you mount `/var/log/auth.log`
  from the host into the container, the container has read access
  to that file. If the container is compromised, the host log
  file is exposed. Mitigation: read-only mount (`:ro`) and
  SELinux / AppArmor profile.
* **Docker socket exposure.** SOCshield does not need the Docker
  socket and should never be run with `-v /var/run/docker.sock`.

## 9. Security testing recommendations

For an operator deploying SOCshield, the following are recommended
periodic checks:

1. **`/api/health/deep` is 200.** If it ever flips to 503, one
   component is failing.
2. **Alert tampering test.** After running the showcase scenario,
   `sqlite3 database/alerts.db "SELECT COUNT(*) FROM alerts;"` and
   confirm the count matches the showcase README. An attacker who
   has write access to the DB can drop rows.
3. **Threat-intel cache freshness.** `sqlite3 threat_intel/cache.db
   "SELECT ip, fetched_at FROM threat_intel_cache;"` — all rows
   should be ≤ 24 h old after a fresh run.
4. **Image scanning.** `trivy image socshield:latest` or
   `docker scout cves socshield:latest` — fix anything above
   Medium.
5. **Restore drill.** Pull a backup, restore it to a fresh
   container, confirm the dashboard shows the same alert count and
   incident set.
