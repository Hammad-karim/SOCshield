"""
SOCshield - Dashboard data access.

Read-only helpers that the Flask blueprints use to pull data out of
SQLite and the on-disk incident / coverage reports. Every public
function is parameterized, pure-Python, and returns plain data
structures (dicts / lists) — never ORM rows.

This module *consumes* the existing backend components:

  * `database.db` for the alerts table
  * `app.correlator` + `app.mitre` for correlation + MITRE
  * `threat_intel.cache` for cached AbuseIPDB / VirusTotal lookups
  * `reports.report_generator` for the on-disk JSON incident files
  * `reports.coverage_report` for the MITRE coverage summary

The detection / correlation logic is **not** modified — we just
re-run the correlator over the alerts we have so the dashboard stays
in sync with whatever is in the DB.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# Make the repo root importable no matter how this module is loaded
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Backend modules — read-only consumers
from database import db as alerts_db  # noqa: E402
from threat_intel import cache as ti_cache  # noqa: E402
from app.correlator import correlate  # noqa: E402
from app import mitre as _mitre  # noqa: E402
from reports.report_generator import INCIDENTS_DIR  # noqa: E402
from reports.coverage_report import COVERAGE_JSON_PATH  # noqa: E402

logger = logging.getLogger("socshield.web.queries")

# ---------- Validation constants ----------

ALLOWED_SEVERITIES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ALLOWED_SORT_COLUMNS: dict[str, str] = {
    "timestamp": "timestamp",
    "source_ip": "source_ip",
    "detector": "detector",
    "severity": "severity",
    "mitre_technique": "mitre_technique",
    "mitre_tactic": "mitre_tactic",
}
SORT_DIRS: tuple[str, ...] = ("ASC", "DESC")
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 200

# Strict pattern — anything that isn't an IPv4 / IPv6 / hostname shape
# is rejected at the route layer. We don't actually need to *validate*
# every IP in the DB (the detectors / orchestrator wrote them), but we
# do need to defend against user-controlled search input.
_IP_PATTERN = re.compile(r"^[A-Za-z0-9_.\-:]{1,64}$")


# ---------- Internal helpers ----------

def _alerts_db_path() -> Path:
    return alerts_db.DB_PATH


def _ti_cache_path() -> Path:
    return ti_cache._CACHE_PATH


def _connect_alerts() -> sqlite3.Connection:
    """Open a fresh alerts-DB connection (separate from `db._connect`
    so we can do parameterised paginated queries without touching
    the production module's API)."""
    conn = sqlite3.connect(str(_alerts_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def _alerts_with_mitre(alerts: list[Any]) -> list[dict]:
    """Decorate a list of Alert objects with MITRE fields looked up
    from the detector -> technique map. Used everywhere MITRE is
    displayed."""
    rows: list[dict] = []
    for a in alerts:
        rows.append({
            "id": getattr(a, "id", None),
            "timestamp": a.timestamp,
            "source_ip": a.source_ip,
            "detector": a.detector,
            "severity": a.severity,
            "title": a.title,
            "description": getattr(a, "description", "") or "",
            "mitre_technique": (
                a.mitre_technique
                or _mitre.technique_for_detector(a.detector)
            ),
            "mitre_tactic": (
                a.mitre_tactic
                or _mitre.tactic_for_detector(a.detector)
            ),
        })
    return rows


def _row_to_alert(row: sqlite3.Row) -> Any:
    """Materialize a raw row from the alerts table as an Alert object,
    using the canonical `Alert.from_row` constructor."""
    from app.models import Alert
    return Alert.from_row(row)


# ---------- Alert queries ----------

def get_alerts(
    *,
    search: str | None = None,
    severity: str | None = None,
    sort_by: str = "timestamp",
    sort_dir: str = "DESC",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Return a paginated, filtered, sorted slice of the alerts table.

    Returns:
        {
            "rows":         [...decorated dicts...],
            "total":        int,            # total matching rows
            "page":         int,
            "page_size":    int,
            "pages":        int,
            "filters":      {echoed back to the template}
        }
    """
    # ---- Defensive input handling ----
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))

    sort_col = ALLOWED_SORT_COLUMNS.get(sort_by, "timestamp")
    sort_dir = "DESC" if sort_dir.upper() not in SORT_DIRS else sort_dir.upper()
    if sort_dir == "DESC" and sort_col not in ("timestamp",):
        # Default: most recent first
        pass

    sev: str | None = None
    if severity and severity.upper() in ALLOWED_SEVERITIES:
        sev = severity.upper()

    # MITRE technique / tactic aren't stored in the alerts table; we
    # use the detector -> technique map at decorate time and rely on
    # an in-memory sort for those columns (the row counts here are
    # small enough that it's well under a millisecond).
    in_memory_sort = sort_col in ("mitre_technique", "mitre_tactic")

    where_clauses: list[str] = []
    params: list[Any] = []

    if sev:
        where_clauses.append("severity = ?")
        params.append(sev)

    search_term: str | None = None
    if search and _IP_PATTERN.match(search.strip()):
        # Search hits source_ip + title + detector + description
        search_term = f"%{search.strip()}%"
        where_clauses.append(
            "(source_ip LIKE ? OR title LIKE ? OR detector LIKE ? OR description LIKE ?)"
        )
        params.extend([search_term, search_term, search_term, search_term])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Total count for pagination
    with _connect_alerts() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) AS n FROM alerts {where_sql}", params
            ).fetchone()["n"]
        )

        order_sql = (
            f"ORDER BY {sort_col} {sort_dir}, id DESC"
            if not in_memory_sort
            else "ORDER BY timestamp DESC, id DESC"
        )

        offset = (page - 1) * page_size
        cur = conn.execute(
            f"SELECT id, timestamp, source_ip, detector, severity, title, description "
            f"FROM alerts {where_sql} {order_sql} LIMIT ? OFFSET ?",
            params + [page_size, offset],
        )
        raw_rows = [_row_to_alert(r) for r in cur.fetchall()]

    rows = _alerts_with_mitre(raw_rows)

    if in_memory_sort:
        rows.sort(key=lambda r: (str(r.get(sort_col) or ""),), reverse=(sort_dir == "DESC"))

    pages = max(1, (total + page_size - 1) // page_size)

    return {
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "filters": {
            "search": search or "",
            "severity": sev or "",
            "sort_by": sort_by,
            "sort_dir": sort_dir,
        },
    }


# ---------- KPI / summary ----------

def get_dashboard_summary() -> dict:
    """Top-of-dashboard stats: totals, active attackers, MITRE coverage.

    All values come from the live SQLite database + the on-disk MITRE
    coverage JSON. No mocks, no hardcoded values.
    """
    with _connect_alerts() as conn:
        total_alerts = int(
            conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        )
        critical_alerts = int(
            conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'CRITICAL'")
            .fetchone()["n"]
        )
        high_alerts = int(
            conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'HIGH'")
            .fetchone()["n"]
        )
        medium_alerts = int(
            conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'MEDIUM'")
            .fetchone()["n"]
        )
        low_alerts = int(
            conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'LOW'")
            .fetchone()["n"]
        )
        # "Active" = an IP with an alert in the last 60 minutes
        active_cutoff = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cutoff_dt = (
                datetime.utcnow().replace(microsecond=0)
                - __import__("datetime").timedelta(minutes=60)
            )
            active_cutoff = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        active_ips = [
            row["source_ip"]
            for row in conn.execute(
                "SELECT DISTINCT source_ip FROM alerts "
                "WHERE timestamp >= ? ORDER BY source_ip",
                (active_cutoff,),
            ).fetchall()
        ]
        # Top attacker IPs (ever)
        top_ips = [
            {"ip": r["source_ip"], "count": r["n"]}
            for r in conn.execute(
                "SELECT source_ip, COUNT(*) AS n FROM alerts "
                "GROUP BY source_ip ORDER BY n DESC, source_ip ASC LIMIT 10"
            ).fetchall()
        ]
        # Alerts by country — derived from threat-intel cache
        country_rows = conn.execute(
            "SELECT source_ip, COUNT(*) AS n FROM alerts GROUP BY source_ip"
        ).fetchall()

    # ---- Threat-intel aggregates ----
    countries: Counter[str] = Counter()
    abuse_scores: list[int] = []
    malicious_ips: set[str] = set()
    ips_with_intel = 0

    if _ti_cache_path().exists():
        with sqlite3.connect(str(_ti_cache_path())) as ti_conn:
            ti_conn.row_factory = sqlite3.Row
            for row in ti_conn.execute(
                "SELECT ip, payload FROM threat_intel_cache"
            ).fetchall():
                ips_with_intel += 1
                try:
                    payload = json.loads(row["payload"])
                except (TypeError, ValueError):
                    continue
                country = payload.get("country")
                if country:
                    countries[country] += 1
                score = payload.get("abuse_score")
                if isinstance(score, (int, float)):
                    abuse_scores.append(int(score))
                if payload.get("malicious"):
                    malicious_ips.add(row["ip"])

    average_abuse_score = (
        round(sum(abuse_scores) / len(abuse_scores), 2) if abuse_scores else None
    )

    # ---- MITRE coverage ----
    mitre_summary = _load_mitre_summary()
    # `_load_mitre_summary` normalises both branches (live build +
    # on-disk JSON) to the same key set. See its return shape.
    techniques_covered = mitre_summary.get("techniques_covered", 0)
    total_techniques = mitre_summary.get("total_techniques", 0)

    # ---- Incidents count from on-disk JSON reports ----
    incidents = list(_iter_incident_files())
    incidents_count = len(incidents)

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "active_attacker_ips": active_ips,
        "active_attacker_count": len(active_ips),
        "incidents_generated": incidents_count,
        "mitre_techniques_covered": techniques_covered,
        "mitre_total_techniques": total_techniques,
        "average_abuse_score": average_abuse_score,
        "malicious_ip_count": len(malicious_ips),
        "ips_with_intel": ips_with_intel,
        "top_attacker_ips": top_ips,
        "top_countries": [
            {"country": c, "count": n} for c, n in countries.most_common(10)
        ],
    }


def get_alerts_over_time(bucket_minutes: int = 60) -> list[dict]:
    """Return [{ "bucket": "2026-06-17 08:00", "count": N }, ...]."""
    with _connect_alerts() as conn:
        rows = conn.execute(
            "SELECT timestamp FROM alerts ORDER BY timestamp ASC"
        ).fetchall()
    counter: Counter[str] = Counter()
    for r in rows:
        ts_raw = r["timestamp"]
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            ts = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
        # bucket floor
        minute = (ts.minute // bucket_minutes) * bucket_minutes
        bucket = ts.replace(minute=minute, second=0, microsecond=0)
        counter[bucket.strftime("%Y-%m-%d %H:%M")] += 1
    return [
        {"bucket": b, "count": counter[b]} for b in sorted(counter.keys())
    ]


def get_severity_distribution() -> list[dict]:
    with _connect_alerts() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
        ).fetchall()
    counts = {r["severity"]: r["n"] for r in rows}
    # Stable order matching the dashboard legend
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return [{"severity": s, "count": counts.get(s, 0)} for s in order]


def get_top_attacker_ips(limit: int = 10) -> list[dict]:
    with _connect_alerts() as conn:
        rows = conn.execute(
            "SELECT source_ip AS ip, COUNT(*) AS n FROM alerts "
            "GROUP BY source_ip ORDER BY n DESC, source_ip ASC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"ip": r["ip"], "count": r["n"]} for r in rows]


def get_tactic_distribution() -> list[dict]:
    with _connect_alerts() as conn:
        rows = conn.execute("SELECT detector FROM alerts").fetchall()
    detectors = [r["detector"] for r in rows]
    counts = _mitre.tactic_frequency(detectors)
    return [{"tactic": t, "count": n} for t, n in counts.items()]


def get_technique_distribution() -> list[dict]:
    with _connect_alerts() as conn:
        rows = conn.execute("SELECT detector FROM alerts").fetchall()
    detectors = [r["detector"] for r in rows]
    counts = _mitre.technique_frequency(detectors)
    out: list[dict] = []
    for tid, n in counts.items():
        ref = _mitre.get_ref(tid)
        out.append({
            "technique_id": tid,
            "technique_name": ref.technique_name if ref else "?",
            "tactic": ref.tactic if ref else "?",
            "count": n,
        })
    return out


def get_attacks_by_country() -> list[dict]:
    """Cross-reference attacker IPs with cached threat-intel data.

    Returns [{ "country": "US", "count": N, "ips": [..] }, ...].
    """
    with _connect_alerts() as conn:
        ip_rows = conn.execute(
            "SELECT source_ip, COUNT(*) AS n FROM alerts GROUP BY source_ip"
        ).fetchall()

    by_country: dict[str, dict] = {}
    for row in ip_rows:
        ip = row["source_ip"]
        ti = get_threat_intel_for_ip(ip) or {}
        country = ti.get("country") or "UNKNOWN"
        entry = by_country.setdefault(
            country, {"country": country, "count": 0, "ips": []}
        )
        entry["count"] += row["n"]
        if ip not in entry["ips"]:
            entry["ips"].append(ip)

    # Sort descending by count
    return sorted(by_country.values(), key=lambda x: -x["count"])


# ---------- Threat intel ----------

def get_threat_intel_for_ip(ip: str) -> dict | None:
    """Return the cached threat-intel dict for `ip`, or None."""
    if not _IP_PATTERN.match(ip or ""):
        return None
    payload = ti_cache.get(ip)
    if not payload:
        return None
    # The cache stores the full ThreatIntel dict. We re-export it as-is
    # so the templates can render every field the upstream wrote.
    payload = dict(payload)
    payload.setdefault("ip", ip)
    return payload


def list_threat_intel(
    *,
    min_score: int | None = None,
    malicious_only: bool = False,
    country: str | None = None,
    search: str | None = None,
) -> list[dict]:
    """Return all cached threat-intel records, optionally filtered."""
    if not _ti_cache_path().exists():
        return []
    with sqlite3.connect(str(_ti_cache_path())) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ip, payload, fetched_at FROM threat_intel_cache"
        ).fetchall()

    out: list[dict] = []
    for r in rows:
        try:
            payload = json.loads(r["payload"])
        except (TypeError, ValueError):
            continue
        record = dict(payload)
        record.setdefault("ip", r["ip"])
        record.setdefault("fetched_at", r["fetched_at"])

        if malicious_only and not record.get("malicious"):
            continue
        if min_score is not None:
            score = record.get("abuse_score")
            if not isinstance(score, (int, float)) or int(score) < min_score:
                continue
        if country and (record.get("country") or "").upper() != country.upper():
            continue
        if search and _IP_PATTERN.match(search.strip()):
            term = search.strip().lower()
            haystack = " ".join(
                str(record.get(k, "")) for k in ("ip", "country", "isp")
            ).lower()
            if term not in haystack:
                continue
        out.append(record)

    out.sort(
        key=lambda x: (
            -(int(x.get("abuse_score")) if isinstance(x.get("abuse_score"), (int, float)) else -1),
            x.get("ip", ""),
        )
    )
    return out


# ---------- Incidents / campaigns ----------

def _iter_incident_files() -> Iterable[Path]:
    """Yield every on-disk incident JSON file. Sorted newest first."""
    if not INCIDENTS_DIR.exists():
        return []
    files = sorted(
        INCIDENTS_DIR.glob("incident_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files


def _campaign_key_from_payload(payload: dict) -> str:
    """Stable identifier for an incident in the dashboard URLs."""
    ip = payload.get("source_ip", "unknown")
    rule = payload.get("rule_id", "?")
    gen = payload.get("generated_at", "")
    safe_ip = re.sub(r"[^A-Za-z0-9._-]+", "_", ip)
    return f"{safe_ip}-rule{rule}-{gen}"


def get_incidents() -> list[dict]:
    """List all incidents (from on-disk JSON). Returns decorated dicts."""
    out: list[dict] = []
    for path in _iter_incident_files():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            logger.warning("failed to read incident file %s", path)
            continue
        # Build a stable URL slug
        payload["_id"] = _campaign_key_from_payload(payload)
        payload["_filename"] = path.name
        out.append(payload)
    # Newest first
    out.sort(
        key=lambda p: p.get("generated_at", "") or "",
        reverse=True,
    )
    return out


def get_incident_by_id(incident_id: str) -> dict | None:
    """Find an incident whose `_id` matches `incident_id`."""
    for inc in get_incidents():
        if inc.get("_id") == incident_id:
            return inc
    return None


def get_recent_incidents(limit: int = 5) -> list[dict]:
    """Return the N most recently generated incidents (newest first)."""
    return get_incidents()[: max(0, int(limit))]


# ---------- MITRE coverage ----------

def _load_mitre_summary() -> dict:
    """Read the on-disk coverage JSON and return the headline numbers.

    Normalises two key shapes — the live build (CoverageReport dataclass)
    and the persisted coverage JSON — into one shape so callers can rely
    on a single key set.

    Returned keys (stable):
        techniques_covered, total_techniques, tactics_covered,
        coverage_ratio, covered, uncovered, tactic_frequency,
        technique_frequency, most_common_tactic, most_common_technique,
        kill_chain, generated_at
    """
    if not COVERAGE_JSON_PATH.exists():
        # Fall back to a live build so the dashboard still has data
        alerts = alerts_db.get_all_alerts()
        from reports.coverage_report import build_coverage
        cov = build_coverage(alerts)
        return _normalise_coverage({
            "total_techniques_covered": cov.total_techniques_covered,
            "total_techniques_in_catalog": cov.total_techniques_in_catalog,
            "total_tactics_covered": cov.total_tactics_covered,
            "coverage_ratio": cov.coverage_ratio,
            "covered_techniques": cov.covered_techniques,
            "uncovered_techniques": cov.uncovered_techniques,
            "tactic_frequency": cov.tactic_frequency,
            "technique_frequency": cov.technique_frequency,
            "most_common_tactic": cov.most_common_tactic,
            "most_common_technique": cov.most_common_technique,
            "observed_kill_chain": cov.observed_kill_chain,
            "generated_at": cov.generated_at,
        })
    try:
        raw = json.loads(COVERAGE_JSON_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("failed to read coverage JSON at %s", COVERAGE_JSON_PATH)
        return _normalise_coverage({})
    return _normalise_coverage(raw)


def _normalise_coverage(raw: dict) -> dict:
    """Map the persisted JSON's long key names to the dashboard's short ones."""
    covered = raw.get("covered_techniques", raw.get("covered", [])) or []
    uncovered = raw.get("uncovered_techniques", raw.get("uncovered", [])) or []
    return {
        "techniques_covered": raw.get(
            "total_techniques_covered",
            raw.get("techniques_covered", 0),
        ),
        "total_techniques": raw.get(
            "total_techniques_in_catalog",
            raw.get("total_techniques", len(_mitre.MITRE_CATALOG)),
        ),
        "tactics_covered": raw.get(
            "total_tactics_covered",
            raw.get("tactics_covered", 0),
        ),
        "coverage_ratio": raw.get("coverage_ratio", 0.0),
        "covered": covered,
        "uncovered": uncovered,
        "tactic_frequency": raw.get("tactic_frequency", {}) or {},
        "technique_frequency": raw.get("technique_frequency", {}) or {},
        "most_common_tactic": raw.get("most_common_tactic"),
        "most_common_technique": raw.get("most_common_technique"),
        "kill_chain": raw.get(
            "observed_kill_chain",
            raw.get("kill_chain", []),
        ),
        "generated_at": raw.get("generated_at", ""),
    }


def get_mitre_coverage() -> dict:
    summary = _load_mitre_summary()

    # Build the ATT&CK matrix (tactic -> list of techniques)
    # Group covered + uncovered techniques by tactic.
    matrix: dict[str, list[dict]] = {}
    for tid, ref in _mitre.MITRE_CATALOG.items():
        matrix.setdefault(ref.tactic, []).append({
            "technique_id": tid,
            "technique_name": ref.technique_name,
            "covered": tid in {r["technique_id"] for r in summary.get("covered", [])},
            "observations": next(
                (
                    r.get("observations", 0)
                    for r in summary.get("covered", [])
                    if r["technique_id"] == tid
                ),
                0,
            ),
        })
    # Stable tactic order
    tactic_order = [
        _mitre.TACTIC_RECONNAISSANCE,
        _mitre.TACTIC_CREDENTIAL_ACCESS,
        _mitre.TACTIC_PRIVILEGE_ESCALATION,
    ]
    sorted_matrix = {t: matrix.get(t, []) for t in tactic_order if t in matrix}
    # Any extra tactics at the end
    for t, rows in matrix.items():
        if t not in sorted_matrix:
            sorted_matrix[t] = rows

    return {
        "summary": summary,
        "matrix": sorted_matrix,
    }
