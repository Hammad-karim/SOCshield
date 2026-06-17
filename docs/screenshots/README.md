# SOCshield — Screenshots

The dashboard is the visible face of SOCshield. This folder collects
the screenshots referenced by the top-level [README](../../README.md)
and the [walkthrough](../walkthrough.md).

## Naming convention

| Filename                  | Route rendered                  | Used in |
| ------------------------- | ------------------------------- | ------- |
| `dashboard.png`           | `http://127.0.0.1:5000/`        | README, walkthrough |
| `alerts.png`              | `http://127.0.0.1:5000/alerts`  | README, walkthrough |
| `incidents.png`           | `http://127.0.0.1:5000/incidents` | README, walkthrough |
| `incident_detail.png`     | `http://127.0.0.1:5000/incident/<id>` | README, walkthrough |
| `threat_intel.png`        | `http://127.0.0.1:5000/threat-intel` | README, walkthrough |
| `mitre.png`               | `http://127.0.0.1:5000/mitre`   | README, walkthrough |

All PNGs are intended to render at 1280 × 800 (or wider) so the
analyst layout is visible at a glance. The dashboard's CSS is
designed to look correct at that width — narrower viewports collapse
to a single column.

## Capturing fresh screenshots

### 1. Start the dashboard with a non-empty dataset

```bash
# In one terminal — start the dashboard
python run_dashboard.py --host 127.0.0.1 --port 5000

# In another — generate a fresh alert + incident + coverage dataset
python main.py
```

If the in-repo sample logs aren't already populated, the live
detectors will start producing alerts once the service is running.
For instant screenshots with all 5 routes populated, use the demo
dataset in [`../../demo/`](../../demo/):

```bash
cp -r demo/scenario_4_full_chain/logs/* logs/
python main.py
python run_dashboard.py --port 5000
```

### 2. Capture each route

The repository ships a tiny capture helper at
[`scripts/capture_screenshots.sh`](../../scripts/capture_screenshots.sh)
that uses `playwright` (headless Chromium) to take screenshots
programmatically:

```bash
pip install playwright
playwright install chromium

bash scripts/capture_screenshots.sh
```

If you'd rather capture by hand, the workflow is:

1. Open each URL above in a 1280 × 800 browser window.
2. For `/incident/<id>`, copy the id from the `/incidents` page (e.g.
   `185.220.101.45-ruleA-2026-06-17T13:55:04+00:00`).
3. Save the file to this directory using the names in the table.

### 3. Re-render the README preview

After replacing the PNGs, `git diff` to confirm the README's image
references still match the new filenames, then push.

## What the screenshots are meant to demonstrate

| Screenshot             | What a recruiter / interviewer should notice                          |
| ---------------------- | --------------------------------------------------------------------- |
| `dashboard.png`        | 6 KPI cards in a single hairline-bordered row; 6 charts; recent alerts + incidents |
| `alerts.png`           | Dense table, monospace IPs / IDs / timestamps, severity as left-border + label |
| `incidents.png`        | Cards with risk badge, source IP, kill-chain strip, MITRE chips      |
| `incident_detail.png`  | Header strip + kill chain, two-column layout, full correlated alerts table |
| `threat_intel.png`     | Filterable table with abuse-score bar, status badge, country / ISP   |
| `mitre.png`            | ATT&CK matrix with covered techniques in amber; frequency charts      |

If any of those is missing or wrong in a captured screenshot, the
dashboard has regressed — re-run `python main.py` and re-capture.

## Placeholders

Until a fresh capture is done, the `*.png` placeholders in this folder
are intentionally left as 1×1 transparent files. The README references
are stable, so re-capturing and dropping the new files in is a
zero-edit change.
