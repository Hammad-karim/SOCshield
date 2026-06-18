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
import sys
from collections import Counter
from datetime import datetime, timedelta
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

def _alerts_db_path() -> Path | None:
    """Path of the SQLite file (None when on Postgres)."""
    return alerts_db.DB_PATH


def _ti_cache_path() -> Path | None:
    """Path of the threat-intel SQLite file (None when on Postgres)."""
    return ti_cache._CACHE_PATH


def _connect_alerts():
    """Open a fresh alerts-DB connection. The connection's `execute` and
    `cursor()` style depends on the active backend.

    Returns a wrapper that exposes:
        .execute(sql, params) -> cursor-like with .fetchone()/.fetchall()
        .close()
    The wrapper's `execute` always returns rows that are plain dicts,
    so callers don't need to special-case sqlite3.Row vs psycopg2 tuples.
    """
    return _AlertsConn()


class _AlertsConn:
    """Unified alerts-DB connection that returns plain-dict rows.

    Used by every read query in this module. On Postgres it opens a
    short-lived connection + cursor with RealDictCursor and returns
    dict rows. On SQLite it opens a sqlite3.Connection with row_factory
    and converts rows to dicts. Either way, callers can `with conn as c:`
    or use the context manager protocol below.
    """
    def __init__(self) -> None:
        if alerts_db.DB_BACKEND == "postgres":
            import psycopg2
            import psycopg2.extras
            self._conn = psycopg2.connect(alerts_db._postgres_dsn())
            self._cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            import sqlite3 as _sqlite3
            path = _alerts_db_path()
            self._conn = _sqlite3.connect(str(path))
            self._conn.row_factory = _sqlite3.Row
            self._cur = None  # use sqlite's execute directly
        self._backend = alerts_db.DB_BACKEND

    def execute(self, sql: str, params: list | tuple = ()) -> "_AlertsCursor":
        if self._backend == "postgres":
            self._cur.execute(sql, params)
            return _AlertsCursor(self._cur, self._backend)
        else:
            return _AlertsCursor(self._conn.execute(sql, params), self._backend)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        try:
            if self._cur is not None:
                self._cur.close()
        except Exception:
            pass
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "_AlertsConn":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self._conn.commit()
        else:
            try:
                self._conn.rollback()
            except Exception:
                pass
        self.close()


class _AlertsCursor:
    """Cursor wrapper that always returns plain dicts."""
    def __init__(self, cursor, backend: str) -> None:
        self._cur = cursor
        self._backend = backend

    def fetchone(self) -> dict | None:
        row = self._cur.fetchone()
        if row is None:
            return None
        if isinstance(row, dict):
            return row
        if self._backend == "sqlite":
            return {k: row[k] for k in row.keys()}
        return dict(row)

    def fetchall(self) -> list[dict]:
        rows = self._cur.fetchall()
        if self._backend == "sqlite":
            return [{k: r[k] for k in r.keys()} for r in rows]
        return [dict(r) for r in rows]


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


def _row_to_alert(row: dict) -> Any:
    """Materialize a row (now always a dict) as an Alert object."""
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

    # Placeholder translation for the active backend.
    def _ph(sql: str) -> str:
        return sql.replace("?", "%s") if alerts_db.DB_BACKEND == "postgres" else sql

    # Total count for pagination
    with _connect_alerts() as conn:
        total = int(
            conn.execute(
                _ph(f"SELECT COUNT(*) AS n FROM alerts {where_sql}"), params
            ).fetchone()["n"]
        )

        order_sql = (
            f"ORDER BY {sort_col} {sort_dir}, id DESC"
            if not in_memory_sort
            else "ORDER BY timestamp DESC, id DESC"
        )

        offset = (page - 1) * page_size
        cur = conn.execute(
            _ph(
                f"SELECT id, timestamp, source_ip, detector, severity, title, description "
                f"FROM alerts {where_sql} {order_sql} LIMIT ? OFFSET ?"
            ),
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

    All values come from the live alerts DB + the on-disk MITRE
    coverage JSON. Works on both SQLite (local/Docker) and Postgres
    (Vercel/Neon) backends.
    """
    def _ph(sql: str) -> str:
        return sql.replace("?", "%s") if alerts_db.DB_BACKEND == "postgres" else sql

    with _connect_alerts() as conn:
        total_alerts = int(
            conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        )
        critical_alerts = int(
            conn.execute(
                _ph("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'CRITICAL'")
            ).fetchone()["n"]
        )
        high_alerts = int(
            conn.execute(
                _ph("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'HIGH'")
            ).fetchone()["n"]
        )
        medium_alerts = int(
            conn.execute(
                _ph("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'MEDIUM'")
            ).fetchone()["n"]
        )
        low_alerts = int(
            conn.execute(
                _ph("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'LOW'")
            ).fetchone()["n"]
        )
        # "Active" = an IP with an alert in the last 60 minutes
        cutoff_dt = datetime.utcnow().replace(microsecond=0) - timedelta(minutes=60)
        active_cutoff = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        active_ips = [
            row["source_ip"]
            for row in conn.execute(
                _ph(
                    "SELECT DISTINCT source_ip FROM alerts "
                    "WHERE timestamp >= ? ORDER BY source_ip"
                ),
                (active_cutoff,),
            ).fetchall()
        ]
        # Top attacker IPs (ever)
        top_ips = [
            {"ip": r["source_ip"], "count": r["n"]}
            for r in conn.execute(
                _ph(
                    "SELECT source_ip, COUNT(*) AS n FROM alerts "
                    "GROUP BY source_ip ORDER BY n DESC, source_ip ASC LIMIT 10"
                )
            ).fetchall()
        ]
        # Alerts by country — derived from threat-intel cache
        country_rows = conn.execute(
            _ph("SELECT source_ip, COUNT(*) AS n FROM alerts GROUP BY source_ip")
        ).fetchall()

    # ---- Threat-intel aggregates ----
    countries: Counter[str] = Counter()
    abuse_scores: list[int] = []
    malicious_ips: set[str] = set()
    ips_with_intel = 0

    ti_path = _ti_cache_path()
    if ti_cache.CACHE_BACKEND == "postgres":
        # Pull from Postgres-backed cache.
        import psycopg2
        import psycopg2.extras
        dsn = ti_cache._postgres_dsn()
        try:
            with psycopg2.connect(dsn) as ti_conn:
                with ti_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    for row in cur.execute(
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
        except Exception:
            logger.exception("threat-intel cache read failed (postgres)")
    elif ti_path is not None and ti_path.exists():
        import sqlite3 as _sqlite3
        with _sqlite3.connect(str(ti_path)) as ti_conn:
            ti_conn.row_factory = _sqlite3.Row
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
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return [{"severity": s, "count": counts.get(s, 0)} for s in order]


def get_top_attacker_ips(limit: int = 10) -> list[dict]:
    def _ph(sql: str) -> str:
        return sql.replace("?", "%s") if alerts_db.DB_BACKEND == "postgres" else sql
    with _connect_alerts() as conn:
        rows = conn.execute(
            _ph(
                "SELECT source_ip AS ip, COUNT(*) AS n FROM alerts "
                "GROUP BY source_ip ORDER BY n DESC, source_ip ASC LIMIT ?"
            ),
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
    """Cross-reference attacker IPs with cached threat-intel data."""
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

    return sorted(by_country.values(), key=lambda x: -x["count"])


# ---------- Threat intel ----------

def get_threat_intel_for_ip(ip: str) -> dict | None:
    """Return the cached threat-intel dict for `ip`, or None."""
    if not _IP_PATTERN.match(ip or ""):
        return None
    payload = ti_cache.get(ip)
    if not payload:
        return None
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
    rows: list[dict] = []
    if ti_cache.CACHE_BACKEND == "postgres":
        import psycopg2
        import psycopg2.extras
        try:
            with psycopg2.connect(ti_cache._postgres_dsn()) as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    for r in cur.execute(
                        "SELECT ip, payload, fetched_at FROM threat_intel_cache"
                    ).fetchall():
                        rows.append(dict(r))
        except Exception:
            logger.exception("threat-intel cache read failed (postgres)")
    else:
        ti_path = _ti_cache_path()
        if ti_path is None or not ti_path.exists():
            return []
        import sqlite3 as _sqlite3
        with _sqlite3.connect(str(ti_path)) as conn:
            conn.row_factory = _sqlite3.Row
            for r in conn.execute(
                "SELECT ip, payload, fetched_at FROM threat_intel_cache"
            ).fetchall():
                rows.append({k: r[k] for k in r.keys()})

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
