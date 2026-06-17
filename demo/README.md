# SOCshield — Demo Dataset

A self-contained set of attack scenarios you can replay end-to-end:

1. Drop the scenario's `logs/` files into the SOCshield log directory.
2. Run `python main.py` (batch) or `python main.py --service` (live).
3. Open the dashboard.

Each scenario ships with:

- `logs/` — the input log files (auth.log / firewall.log / priv.log)
- `expected/` — what the pipeline *should* produce (alert counts,
  campaign rules, MITRE techniques, threat-intel fields)

## Scenarios

| # | Scenario            | Source IP          | Detector chain                       | Expected rules |
| - | ------------------- | ------------------ | ------------------------------------ | -------------- |
| 1 | Port scan           | `203.0.113.50`     | PORT_SCAN:HORIZONTAL                 | none           |
| 2 | Brute force         | `198.51.100.22`    | BRUTE_FORCE                          | none           |
| 3 | Privilege escalation| `10.0.0.99`        | PRIV_ESC                             | none           |
| 4 | Full attack chain   | `185.220.101.45`   | PORT_SCAN → BRUTE_FORCE → PRIV_ESC   | A, B           |

Scenario 4 is the showcase — it's the same data the live DB already
has, and it produces both an A and a B campaign. It's the one to
record the demo video against.

## Quick start

```bash
# Backup anything you have, then point SOCshield at the demo dataset
cp -r logs /tmp/socshield-logs-backup
cp -r demo/scenario_4_full_chain/logs/* logs/

# Run the batch pipeline
python main.py

# (Optional) start the dashboard
python run_dashboard.py
# -> http://127.0.0.1:5000/
```

To restore your real data:

```bash
rm -rf logs
cp -r /tmp/socshield-logs-backup logs
```

## Why this format

The repo's `logs/` directory is meant to be empty or host your real
data. By keeping the demo logs in a sibling directory, you can
copy them in for a demo, run the pipeline, then restore your real
data — without ever polluting the demo files themselves.
