"""
SOCshield - Orchestration Layer

Centralized alert management. Runs all detectors, collects their `Alert`
outputs, persists them via `database.db`, and returns the unified list.

Clean-architecture boundary:
    detectors  ->  return List[Alert]            (no I/O)
    orchestrator -> runs detectors, writes DB, returns merged list
    correlator -> reads List[Alert], produces campaigns
    report_generator -> reads campaigns, writes JSON

This module is the ONLY writer to the alerts table at runtime.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Make sibling packages importable when run as a script
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models import Alert  # noqa: E402
from database import db as alerts_db  # noqa: E402

logger = logging.getLogger("socshield.orchestrator")


@dataclass(frozen=True)
class DetectorSpec:
    """Static description of a detector the orchestrator can invoke."""
    name: str
    run_fn: Callable[[], list[Alert]]


@dataclass
class OrchestrationResult:
    """Container for the outcome of one orchestrator run."""
    alerts: list[Alert] = field(default_factory=list)
    by_detector: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.alerts)


def _default_detectors() -> list[DetectorSpec]:
    """Import detector `run()` functions lazily to keep the orchestrator
    import-light (e.g. for tests that only need the DB layer)."""
    from detectors import brute_force_detector, port_scan_detector, priv_esc_detector
    return [
        DetectorSpec(name="BRUTE_FORCE", run_fn=brute_force_detector.run),
        DetectorSpec(name="PORT_SCAN",  run_fn=port_scan_detector.run),
        DetectorSpec(name="PRIV_ESC",   run_fn=priv_esc_detector.run),
    ]


def run_pipeline(
    detectors: list[DetectorSpec] | None = None,
    *,
    init_database: bool = True,
    persist: bool = True,
) -> OrchestrationResult:
    """Run the full detection pipeline.

    Args:
        detectors:      Optional override list of DetectorSpec. Defaults to
                        the three built-in detectors.
        init_database:  If True, call `database.db.init_db()` once before
                        persistence. Safe to call repeatedly.
        persist:        If True, store each alert via `save_alert`. If
                        False, the orchestrator still collects and merges
                        but does not write — useful for dry runs.

    Returns:
        OrchestrationResult with the merged, time-sorted list of alerts
        and a per-detector count.
    """
    specs = detectors if detectors is not None else _default_detectors()

    if init_database:
        alerts_db.init_db()

    result = OrchestrationResult()
    for spec in specs:
        logger.info("running detector: %s", spec.name)
        try:
            produced = spec.run_fn() or []
        except Exception:  # noqa: BLE001
            logger.exception("detector %s raised — continuing", spec.name)
            produced = []

        result.by_detector[spec.name] = len(produced)
        logger.info("detector %s produced %d alert(s)", spec.name, len(produced))

        if persist:
            for alert in produced:
                alerts_db.save_alert(alert)

        result.alerts.extend(produced)

    # Unified chronological order — earliest first; correlator depends on this
    result.alerts.sort(key=lambda a: (a.timestamp, a.source_ip, a.detector))
    return result


def refresh_database() -> OrchestrationResult:
    """Wipe the alerts table, then run the pipeline. Intended for clean
    re-runs (e.g. demo / smoke test / scheduled reprocess)."""
    alerts_db.init_db()
    alerts_db.clear_alerts()
    return run_pipeline(init_database=False, persist=True)
