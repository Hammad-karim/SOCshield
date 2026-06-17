"""
SOCshield - Incident Report Generator

Takes correlated campaigns from `app.correlator` and writes one JSON report
per campaign into `reports/incidents/`.

Output (per spec):
    reports/incidents/incident_<ip>_<rule>_<timestamp>.json

    {
      "source_ip": "...",
      "risk": "...",
      "timeline": [...],
      "alerts": [...],
      "narrative": "...",
      "generated_at": "...",
      "summary": "..."
    }

Pure I/O wrapper around the correlator output. No detection logic here.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

# Make sibling packages importable when run as a script
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.correlator import Campaign  # noqa: E402

logger = logging.getLogger("socshield.report_generator")

# Reports may be relocated via env (e.g. Docker volume). Default is in-repo.
_DEFAULT_REPORTS = _REPO_ROOT / "reports"
REPORTS_DIR = Path(os.environ.get("SOCSHIELD_REPORTS_DIR", str(_DEFAULT_REPORTS))).resolve()
INCIDENTS_DIR = REPORTS_DIR / "incidents"

_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename_part(s: str) -> str:
    return _SAFE_RE.sub("_", s).strip("_") or "unknown"


def _incident_filename(c: Campaign) -> str:
    first_ts = c.alerts[0].timestamp if c.alerts else datetime.now()
    stamp = first_ts.strftime("%Y%m%dT%H%M%S")
    return f"incident_{_safe_filename_part(c.source_ip)}_rule{c.rule_id}_{stamp}.json"


@dataclass
class ReportResult:
    """Outcome of one report-generation run."""
    written: list[Path] = field(default_factory=list)
    skipped: list[Campaign] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.written)


def generate_reports(
    campaigns: Iterable[Campaign],
    output_dir: Path = INCIDENTS_DIR,
) -> ReportResult:
    """Persist one JSON file per campaign under `output_dir`.

    Returns a ReportResult listing files actually written plus any campaigns
    that were skipped (e.g. because the output dir is not writable).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = ReportResult()

    for c in campaigns:
        path = output_dir / _incident_filename(c)
        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(c.to_dict(), f, indent=2, ensure_ascii=False)
        except OSError as exc:
            logger.error("failed to write %s: %s", path, exc)
            result.skipped.append(c)
            continue
        result.written.append(path)
        logger.info("wrote incident report: %s", path)

    return result
