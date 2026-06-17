"""
SOCshield - MITRE ATT&CK mapping.

Each detector maps to one ATT&CK technique (and its parent tactic). This
module is the single source of truth — detectors import DETECTOR_MITRE_MAP,
the correlator / report generators call the public functions below.

Mappings (per task spec):

    Brute Force        -> T1110  (Credential Access)
    Port Scan          -> T1046  (Reconnaissance)
    Privilege Escalation -> T1068  (Privilege Escalation)

The mapping covers the three techniques SOCshield currently detects.
Adding a new detector is a one-line change: extend DETECTOR_MITRE_MAP and
the rest of the pipeline (alert enrichment, correlator narratives,
coverage report, docs) updates automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


# --- Technique / tactic constants ---

# Brute Force
T1110 = "T1110"
T1110_NAME = "Brute Force"
TACTIC_CREDENTIAL_ACCESS = "Credential Access"

# Port Scan (Discovery tactic family; Network Scan is T1046)
T1046 = "T1046"
T1046_NAME = "Network Service Scanning"
TACTIC_RECONNAISSANCE = "Reconnaissance"

# Privilege Escalation (Exploitation for Privilege Escalation)
T1068 = "T1068"
T1068_NAME = "Exploitation for Privilege Escalation"
TACTIC_PRIVILEGE_ESCALATION = "Privilege Escalation"


@dataclass(frozen=True)
class MitreRef:
    """One MITRE ATT&CK reference: technique id + name + parent tactic name."""
    technique_id: str
    technique_name: str
    tactic: str


# Public catalog — full coverage matrix SOCshield *could* report against.
# Each entry maps an ATT&CK technique id to its human-readable name + tactic.
MITRE_CATALOG: dict[str, MitreRef] = {
    T1110: MitreRef(T1110, T1110_NAME, TACTIC_CREDENTIAL_ACCESS),
    T1046: MitreRef(T1046, T1046_NAME, TACTIC_RECONNAISSANCE),
    T1068: MitreRef(T1068, T1068_NAME, TACTIC_PRIVILEGE_ESCALATION),
}


# Detector -> MITRE technique. Imported by detectors when they build Alert
# objects so the mapping is consistent across the codebase.
# Keys here are the detector identifiers defined in app/models.py.
DETECTOR_MITRE_MAP: dict[str, str] = {
    "BRUTE_FORCE":              T1110,
    "PORT_SCAN:HORIZONTAL":     T1046,
    "PORT_SCAN:VERTICAL":       T1046,
    "PORT_SCAN:SYN_FLOOD":      T1046,   # SYN flood is pre-cursor to recon
    "PRIV_ESC":                 T1068,
}


# ---------- Public helpers ---------- #

def get_ref(technique_id: str) -> MitreRef | None:
    """Return the catalog entry for `technique_id`, or None if unknown."""
    return MITRE_CATALOG.get(technique_id)


def get_ref_for_detector(detector: str) -> MitreRef | None:
    """Resolve a detector identifier to its MITRE reference, or None."""
    tech_id = DETECTOR_MITRE_MAP.get(detector)
    if tech_id is None:
        return None
    return MITRE_CATALOG.get(tech_id)


def technique_for_detector(detector: str) -> str | None:
    """Convenience: just the technique id for a detector (or None)."""
    return DETECTOR_MITRE_MAP.get(detector)


def tactic_for_detector(detector: str) -> str | None:
    ref = get_ref_for_detector(detector)
    return ref.tactic if ref else None


def unique_techniques(detectors: Iterable[str]) -> list[str]:
    """Sorted unique list of technique ids encountered by the given detectors."""
    seen: set[str] = set()
    for d in detectors:
        tid = DETECTOR_MITRE_MAP.get(d)
        if tid:
            seen.add(tid)
    return sorted(seen)


def unique_tactics(detectors: Iterable[str]) -> list[str]:
    """Sorted unique list of tactic names encountered by the given detectors.

    Tactic ordering follows the standard ATT&CK kill-chain progression
    (Reconnaissance -> Credential Access -> ... -> Privilege Escalation)
    so that callers can render an ordered attack path.
    """
    seen: set[str] = set()
    for d in detectors:
        tac = tactic_for_detector(d)
        if tac:
            seen.add(tac)
    # Order by canonical kill-chain position when possible
    return sorted(seen, key=_tactic_rank)


def _tactic_rank(tactic: str) -> int:
    order = [
        TACTIC_RECONNAISSANCE,
        TACTIC_CREDENTIAL_ACCESS,
        TACTIC_PRIVILEGE_ESCALATION,
    ]
    try:
        return order.index(tactic)
    except ValueError:
        return len(order) + 1


def attack_path(detectors: Iterable[str]) -> list[str]:
    """Return the ordered kill-chain list of tactic names for a sequence
    of detectors (e.g. ['Reconnaissance', 'Credential Access', 'Privilege Escalation'])."""
    return unique_tactics(detectors)


def technique_frequency(detectors: Iterable[str]) -> dict[str, int]:
    """Histogram of technique ids across a detector list."""
    out: dict[str, int] = {}
    for d in detectors:
        tid = DETECTOR_MITRE_MAP.get(d)
        if not tid:
            continue
        out[tid] = out.get(tid, 0) + 1
    return dict(sorted(out.items()))


def tactic_frequency(detectors: Iterable[str]) -> dict[str, int]:
    """Histogram of tactic names across a detector list."""
    out: dict[str, int] = {}
    for d in detectors:
        tac = tactic_for_detector(d)
        if not tac:
            continue
        out[tac] = out.get(tac, 0) + 1
    # Sort by frequency desc, then by tactic rank asc (stable kill-chain order)
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], _tactic_rank(kv[0]))))


def most_common(detectors: Iterable[str]) -> tuple[str | None, str | None]:
    """Return (most_common_tactic, most_common_technique) by frequency.

    Tie-breaks:
      - tactic:    lower kill-chain rank wins (earlier in the attack)
      - technique: by technique id (lexicographic) for determinism
    """
    tf = tactic_frequency(detectors)
    tef = technique_frequency(detectors)

    top_tac = (
        min(tf, key=lambda t: (-tf[t], _tactic_rank(t))) if tf else None
    )
    top_tech = min(tef, key=lambda t: (-tef[t], t)) if tef else None
    return top_tac, top_tech


def coverage_matrix(detectors_seen: Iterable[str]) -> dict:
    """Build the coverage matrix for the coverage report.

    Returns a dict with two sections:
      - 'covered':     techniques SOCshield *did* observe, with tactic + count
      - 'uncovered':   techniques in the catalog SOCshield has not seen
    """
    seen_set = set(technique_for_detector(d) for d in detectors_seen)
    seen_set.discard(None)
    counts = technique_frequency(detectors_seen)

    covered: list[dict] = []
    uncovered: list[dict] = []
    for tech_id, ref in sorted(MITRE_CATALOG.items()):
        row = {
            "technique_id": ref.technique_id,
            "technique_name": ref.technique_name,
            "tactic": ref.tactic,
            "observations": counts.get(tech_id, 0),
        }
        if tech_id in seen_set:
            covered.append(row)
        else:
            uncovered.append({**row, "observations": 0})

    return {
        "covered": covered,
        "uncovered": uncovered,
        "total_techniques_in_catalog": len(MITRE_CATALOG),
        "total_covered": len(covered),
    }
