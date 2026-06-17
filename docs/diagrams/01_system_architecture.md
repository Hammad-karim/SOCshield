# Diagram 01 — System Architecture

The full data flow, end-to-end, from log files to dashboard. Renders
on GitHub automatically (the `mermaid` fenced block below is parsed by
GitHub's Mermaid renderer).

```mermaid
flowchart LR
  subgraph L[Log sources]
    A1[auth.log]
    A2[firewall.log]
    A3[priv.log]
  end

  subgraph W[Tail watchers]
    W1[auth_watcher]
    W2[firewall_watcher]
    W3[priv_watcher]
  end

  subgraph D[Detectors]
    D1[Brute Force<br/>T1110]
    D2[Port Scan<br/>T1046]
    D3[Priv Esc<br/>T1068]
  end

  subgraph B[Event bus]
    BX[NEW_ALERT<br/>INCIDENT_*]
  end

  subgraph C[Correlation]
    C1[ContinuousCorrelator<br/>Rules A / B / C]
  end

  subgraph T[Threat intel]
    T1[AbuseIPDB]
    T2[VirusTotal]
    TX[Cache 24h]
  end

  subgraph S[Storage]
    S1[(alerts.db)]
    S2[reports/incidents/*.json]
    S3[reports/mitre_coverage.json]
  end

  subgraph U[UI]
    U1[Flask dashboard]
  end

  A1 --> W1 --> D1 --> BX
  A2 --> W2 --> D2 --> BX
  A3 --> W3 --> D3 --> BX
  BX --> C1
  C1 --> BX
  C1 --> T1
  C1 --> T2
  T1 --> TX
  T2 --> TX
  C1 --> S1
  C1 --> S2
  C1 --> S3
  S1 --> U1
  S2 --> U1
  S3 --> U1
```
