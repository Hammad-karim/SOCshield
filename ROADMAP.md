# SOCshield — Roadmap

Public direction for the project. Items are ordered by what unlocks
the most user value, not by which is the easiest to implement.

---

## Near-term (next minor release)

### Detection
- **T1021 Remote Services** — lateral movement via SSH / RDP,
  ingested from the existing auth + firewall logs.
- **T1059 Command and Scripting Interpreter** — outbound shell
  spawning from a process-execution feed (syscall or audit).
- **T1071 Application Layer Protocol** — beaconing detection on
  outbound firewall logs (regularity + destination reputation).

### Correlation
- **Time-windowed rules** — currently rules fire whenever all
  detector families are present from the same source IP. Add
  optional time-window constraints (e.g. "all three within 10
  minutes").
- **Multi-source-IP campaigns** — correlate by destination
  host instead of source IP, to catch distributed attacks against
  one asset.

### Dashboard
- **Saved filter presets** — bookmark a search/filter combination
  and share it via URL.
- **Acknowledge / dismiss** on the incident detail page (writes
  to a `state` column; this is a v2 feature that requires schema
  migration).
- **Bulk export** of the alerts table to CSV / JSON.

### Operations
- **Helm chart** for Kubernetes deployment.
- **Prometheus metrics endpoint** — `/metrics` for scraping alert
  rate, incident rate, service uptime, etc.

---

## Medium-term

### Detection
- **T1543 / T1547 Persistence** — systemd / cron / autostart
  execution from a host-monitoring feed.
- **T1070 Indicator Removal** — log deletion / truncation events.
- **T1041 Exfiltration Over C2** — large outbound transfers to
  external IPs (combines firewall + threat-intel reputation).

### Ingest
- **EDR-style process tree ingest** — fork/exec chains, file
  events, network connections per host.
- **Cloud audit ingest** — AWS CloudTrail, Azure Activity Log,
  GCP Audit Logs (pluggable parsers).
- **Email gateway ingest** — phishing / credential-capture
  detection.

### Detection engineering
- **Sigma-rule import** — author detections in the standard
  Sigma YAML format; SOCshield loads them at startup.
- **Detection testing framework** — replay a labelled log set,
  assert the expected alerts fire, fail the build on regression.

### Authentication
- **SSO / OIDC** on the dashboard. Currently the dashboard is
  bound to localhost or behind a reverse proxy; SSO would add a
  real auth layer for internet-facing deployments.

---

## Long-term

* **Multi-tenant role separation** — multiple SOC teams on one
  deployment, with per-team dashboards and alert queues.
* **Real-time WebSocket push** — replace the 30 s polling with a
  persistent connection; immediate alert push.
* **ATT&CK Navigator layer export** — push coverage into the
  MITRE ATT&CK Navigator so the SOC's external tracker updates
  automatically.
* **Active response integration** — pluggable action hooks
  (block IP, disable account, snapshot host) triggered by
  rule-match.
* **Federation** — multiple SOCshield instances sharing threat
  intel and incident state.

---

## Explicitly out of scope

* **Replacing a real SIEM** (Splunk, Elastic, Sentinel). SOCshield
  is a portfolio / small-environment project, not an enterprise
  SIEM.
* **Replacing an EDR** (CrowdStrike, SentinelOne, Defender for
  Endpoint). SOCshield is a log-based detection platform, not a
  kernel-level agent.
* **Compliance automation** (PCI / SOC 2 evidence collection).
  SOCshield produces evidence; an external tool should drive
  evidence collection.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the process. Issues and
PRs against any of the items above are welcome; please open an
issue first to discuss the design before sending a PR for changes
to `detectors/*`, `app/correlator.py`, `app/mitre.py`, or
`app/web/templates/*`.
