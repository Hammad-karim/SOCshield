"""
SOCshield - MITRE ATT&CK Coverage Report

Reads a list of `Alert` objects (typically the orchestrator's collected
output) and produces:

  1. A JSON coverage report at ``reports/mitre_coverage.json`` with:
        - covered techniques (with tactic, observations, contributing detectors)
        - uncovered techniques (from the catalog)
        - tactic + technique frequencies
        - most common tactic / technique
        - total coverage ratio

  2. A Markdown summary at ``docs/mitre_coverage.md`` with a human-readable
     coverage table and the kill-chain progression observed in this run.

This module is pure (no I/O until ``write_*`` is called) and does not depend
on the correlator or threat-intel layers. It can be used standalone.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Make sibling packages importable deep from anywhere
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models import Alert  # noqa: E402
from app import mitre as _mitre  # noqa: E402

logger = logging.getLogger("socshield.coverage")

_DEFAULT_REPORTS = _REPO_ROOT / "reports"
_REPORTS_DIR = Path(os.environ.get("SOCSHIELD_REPORTS_DIR", str(_DEFAULT_REPORTS))).resolve()
DOCS_DIR = _REPO_ROOT / "docs"
COVERAGE_JSON_PATH = _REPORTS_DIR / "mitre_coverage.json"
COVERAGE_MD_PATH = DOCS_DIR / "mitre_coverage.md"

# Public alias kept for backwards compatibility (used by the dashboard).
REPORTS_DIR = _REPORTS_DIR


@dataclass
class CoverageReport:
    """In-memory coverage report. Serializable to JSON / Markdown."""
    generated_at: str = ""
    total_alerts: int = 0
    total_techniques_covered: int = 0
    total_tactics_covered: int = 0
    total_techniques_in_catalog: int = 0
    coverage_ratio: float = 0.0
    covered_techniques: list[dict] = field(default_factory=list)
    uncovered_techniques: list[dict] = field(default_factory=list)
    tactic_frequency: dict[str, int] = field(default_factory=dict)
    technique_frequency: dict[str, int] = field(default_factory=dict)
    most_common_tactic: str | None = None
    most_common_technique: str | None = None
    observed_kill_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "total_alerts": self.total_alerts,
            "total_techniques_covered": self.total_techniques_covered,
            "total_tactics_covered": self.total_tactics_covered,
            "total_techniques_in_catalog": self.total_techniques_in_catalog,
            "coverage_ratio": round(self.coverage_ratio, 4),
            "covered_techniques": self.covered_techniques,
            "uncovered_techniques": self.uncovered_techniques,
            "tactic_frequency": self.tactic_frequency,
            "technique_frequency": self.technique_frequency,
            "most_common_tactic": self.most_common_tactic,
            "most_common_technique": self.most_common_technique,
            "observed_kill_chain": self.observed_kill_chain,
        }


# ---------- Builders ---------- #

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _detectors_per_technique(alerts: Iterable[Alert]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in alerts:
        tid = a.mitre_technique or _mitre.technique_for_detector(a.detector)
        if not tid:
            continue
        out.setdefault(tid, [])
        if a.detector not in out[tid]:
            out[tid].append(a.detector)
    return out


def build_coverage(alerts: Iterable[Alert]) -> CoverageReport:
    """Aggregate alerts into a `CoverageReport`.

    `alerts` is the orchestrator's flat list — every Alert carries the
    MITRE fields populated by its detector, so the report works without
    any external lookups.
    """
    alert_list = list(alerts)
    detectors = [a.detector for a in alert_list]
    technique_counts = Counter(_mitre.technique_for_detector(d) for d in detectors)
    technique_counts.pop(None, None)
    tactic_counts = Counter(_mitre.tactic_for_detector(d) for d in detectors)
    tactic_counts.pop(None, None)

    covered_set = set(technique_counts)
    covered_rows: list[dict] = []
    for tid in sorted(covered_set):
        ref = _mitre.get_ref(tid)
        if not ref:
            continue
        covered_rows.append({
            "technique_id": ref.technique_id,
            "technique_name": ref.technique_name,
            "tactic": ref.tactic,
            "observations": technique_counts[tid],
            "contributing_detectors": sorted(_detectors_per_technique(alert_list).get(tid, [])),
        })

    uncovered_rows: list[dict] = []
    for tid, ref in sorted(_mitre.MITRE_CATALOG.items()):
        if tid in covered_set:
            continue
        uncovered_rows.append({
            "technique_id": ref.technique_id,
            "technique_name": ref.technique_name,
            "tactic": ref.tactic,
            "observations": 0,
            "contributing_detectors": [],
        })

    top_tactic, top_technique = _mitre.most_common(detectors)

    # Ordered kill chain of distinct tactics observed in this run
    seen_tactics: list[str] = []
    for t in _mitre.unique_tactics(detectors):
        if t not in seen_tactics:
            seen_tactics.append(t)

    total_in_catalog = len(_mitre.MITRE_CATALOG)
    ratio = (len(covered_set) / total_in_catalog) if total_in_catalog else 0.0

    return CoverageReport(
        generated_at=_now_iso(),
        total_alerts=len(alert_list),
        total_techniques_covered=len(covered_set),
        total_tactics_covered=len(tactic_counts),
        total_techniques_in_catalog=total_in_catalog,
        coverage_ratio=ratio,
        covered_techniques=covered_rows,
        uncovered_techniques=uncovered_rows,
        tactic_frequency=dict(tactic_counts),
        technique_frequency=dict(technique_counts),
        most_common_tactic=top_tactic,
        most_common_technique=top_technique,
        observed_kill_chain=seen_tactics,
    )


# ---------- Writers ---------- #

def write_json(report: CoverageReport, path: Path = COVERAGE_JSON_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info("wrote MITRE coverage JSON: %s", path)
    return path


def write_markdown(report: CoverageReport, path: Path = COVERAGE_MD_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# SOCshield — MITRE ATT&CK Coverage")
    lines.append("")
    lines.append(f"_Generated at `{report.generated_at}` from "
                 f"{report.total_alerts} alert(s)._")
    lines.append("")

    # ---- Summary block ----
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Alerts analyzed:** {report.total_alerts}")
    lines.append(f"- **Techniques covered:** {report.total_techniques_covered} / "
                 f"{report.total_techniques_in_catalog} "
                 f"({report.coverage_ratio * 100:.0f}%)")
    lines.append(f"- **Tactics covered:** {report.total_tactics_covered}")
    lines.append(f"- **Most common tactic:** "
                 f"`{report.most_common_tactic or '-'}`")
    lines.append(f"- **Most common technique:** "
                 f"`{report.most_common_technique or '-'}`")
    if report.observed_kill_chain:
        lines.append("- **Observed kill chain:** "
                     + " → ".join(report.observed_kill_chain))
    lines.append("")

    # ---- Coverage matrix ----
    lines.append("## Coverage Matrix")
    lines.append("")
    lines.append("| Status | Technique | Name | Tactic | Observations | Detectors |")
    lines.append("|--------|-----------|------|--------|--------------|-----------|")
    for row in report.covered_techniques:
        detectors = ", ".join(row["contributing_detectors"]) or "-"
        lines.append(
            f"| ✅ covered | `{row['technique_id']}` | {row['technique_name']} | "
            f"{row['tactic']} | {row['observations']} | {detectors} |"
        )
    for row in report.uncovered_techniques:
        lines.append(
            f"| ⚪ uncovered | `{row['technique_id']}` | {row['technique_name']} | "
            f"{row['tactic']} | 0 | - |"
        )
    lines.append("")

    # ---- Frequencies ----
    lines.append("## Tactic Frequency")
    lines.append("")
    if report.tactic_frequency:
        lines.append("| Tactic | Count |")
        lines.append("|--------|-------|")
        for tac, n in sorted(report.tactic_frequency.items(),
                             key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| {tac} | {n} |")
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("## Technique Frequency")
    lines.append("")
    if report.technique_frequency:
        lines.append("| Technique | Name | Count |")
        lines.append("|-----------|------|-------|")
        for tid, n in sorted(report.technique_frequency.items(),
                             key=lambda kv: (-kv[1], kv[0])):
            ref = _mitre.get_ref(tid)
            name = ref.technique_name if ref else "?"
            lines.append(f"| `{tid}` | {name} | {n} |")
    else:
        lines.append("_None._")
    lines.append("")

    # ---- Gaps ----
    lines.append("## Detection Gaps")
    lines.append("")
    if report.uncovered_techniques:
        for row in report.uncovered_techniques:
            lines.append(f"- `{row['technique_id']}` — {row['technique_name']} "
                         f"({row['tactic']})")
    else:
        lines.append("_Full catalog coverage._")
    lines.append("")

    lines.append("---")
    lines.append("_Generated by SOCshield coverage report (`reports/coverage_report.py`)._")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("wrote MITRE coverage Markdown: %s", path)
    return path


def generate(alerts: Iterable[Alert]) -> CoverageReport:
    """Build and persist both the JSON and Markdown coverage reports."""
    report = build_coverage(alerts)
    write_json(report)
    write_markdown(report)
    return report
