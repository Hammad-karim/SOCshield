# SOCshield — MITRE ATT&CK Coverage

This document is the canonical reference for what SOCshield detects,
how it maps detections to ATT&CK, and where the coverage gaps are.
The dashboard's `/mitre` page renders this data live; the file
`reports/mitre_coverage.json` is the persisted, machine-readable form.

---

## Covered tactics

| Tactic                   | Techniques covered | Status     |
| ------------------------ | ------------------ | ---------- |
| Reconnaissance           | 1                  | Covered    |
| Credential Access        | 1                  | Covered    |
| Privilege Escalation     | 1                  | Covered    |

SOCshield covers the canonical *external-to-internal* kill chain in
its entirety: an attacker moves from outside the network
(Reconnaissance) to inside the network (Credential Access) to
host-level compromise (Privilege Escalation). Three tactics, one
technique each.

## Covered techniques

| ID    | Name                                  | Tactic                  | Detector                |
| ----- | ------------------------------------- | ----------------------- | ----------------------- |
| T1046 | Network Service Discovery             | Reconnaissance          | `PORT_SCAN:HORIZONTAL`, `PORT_SCAN:VERTICAL`, `PORT_SCAN:SYN_FLOOD` |
| T1110 | Brute Force                           | Credential Access       | `BRUTE_FORCE`           |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation    | `PRIV_ESC`              |

Each technique is mapped to a single detector identifier in
[`app/mitre.py`](../app/mitre.py). The mapping is the single source
of truth — every Alert and every Campaign carries the technique id
forward, and the dashboard renders the matrix directly from it.

## Coverage matrix (live data)

The matrix below is updated by `python main.py` and persisted at
`reports/mitre_coverage.json`. The version embedded here is a
representative snapshot from the showcase dataset.

| Status      | Technique | Name                              | Tactic                | Observations | Detectors |
| ----------- | --------- | --------------------------------- | --------------------- | ------------ | --------- |
| ✅ covered  | T1046     | Network Service Scanning         | Reconnaissance        | 4            | PORT_SCAN:HORIZONTAL, PORT_SCAN:SYN_FLOOD |
| ✅ covered  | T1068     | Exploitation for Privilege Esc.   | Privilege Escalation  | 10           | PRIV_ESC  |
| ✅ covered  | T1110     | Brute Force                       | Credential Access     | 10           | BRUTE_FORCE |

The `observations` count is the number of times that technique was
raised across the run. The `Detectors` column lists every detector
identifier that contributed.

## Current detection coverage

SOCshield currently maps to 3 of 3 catalogued techniques, or 100%
of the in-scope surface. The catalog is intentionally narrow — it
is the *minimum* needed to demonstrate a multi-stage attack chain
end-to-end. Adding techniques is a one-line change in `app/mitre.py`
plus a new detector in `detectors/`.

### What's covered well

* **Reconnaissance-to-credential-to-priv-esc** as a single chain.
  Rules A and B in the correlator require all three detector
  families to be present from the same source IP.
* **Severity scaling** inside each detector family — a brute-force
  window with 3 attempts is MEDIUM, with 8 is CRITICAL.
* **Long-window correlation** — the correlator re-runs on every
  alert, so a campaign that starts as a single scan and escalates to
  a full intrusion chain is correctly reported as both rule A and
  rule B (with different risk levels) over time.

### What's deliberately not in scope (yet)

* Lateral movement (T1021, T1570)
* Persistence (T1543, T1547)
* Defense evasion (T1070, T1027)
* Discovery (T1082, T1083)
* Execution (T1059)
* Exfiltration (T1041, T1567)
* Command and control (T1071, T1090)

These are tracked in [ROADMAP.md](../ROADMAP.md).

## Future coverage goals

Near-term (next minor version):

- **T1021 Remote Services** — lateral movement via SSH / RDP,
  ingested from auth + firewall logs.
- **T1059 Command and Scripting Interpreter** — outbound shell
  spawning, ingested from a process-execution feed.
- **T1071 Application Layer Protocol** — beaconing detection on
  outbound firewall logs (regularity analysis).

Medium-term:

- **T1543 Boot or Logon Autostart Execution** — systemd / cron
  persistence from a host-monitoring feed.
- **T1070 Indicator Removal** — log deletion / truncation events.
- **T1041 Exfiltration Over C2** — large outbound transfers to
  external IPs.

Long-term:

- Full EDR ingestion (process trees, file events, network
  connections).
- Sigma-rule import so users can author detections without
  Python.
- ATT&CK navigator layer export (so a SOC's navigator view updates
  as new detections fire).

## How to extend coverage

1. Add the technique id to `MITRE_CATALOG` and `DETECTOR_MITRE_MAP`
   in `app/mitre.py`.
2. Write a new detector in `detectors/<name>_detector.py` that
   returns shared `Alert` objects with the right `detector` and
   `mitre_technique` fields.
3. Add a new correlator rule in `app/correlator.py` if the
   technique should contribute to a multi-stage campaign.
4. Update this file's "Covered techniques" table.

The dashboard's `/mitre` page updates automatically — no template
changes required.
