"""
SOCshield - Flask routes.

Two blueprints:

  * `web_bp`  — HTML pages (dashboard, alerts, incidents, ...)
  * `api_bp`  — JSON endpoints used by the auto-refresh JS

Both read through `app.web.queries` (no raw SQL in the route layer).
Every route validates its inputs and degrades gracefully on error.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime

from flask import (
    Blueprint,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from app.web import health as health_registry
from app.web import helpers
from app.web.queries import (
    ALLOWED_SEVERITIES,
    ALLOWED_SORT_COLUMNS,
    DEFAULT_PAGE_SIZE,
    get_alerts,
    get_alerts_over_time,
    get_attacks_by_country,
    get_dashboard_summary,
    get_incident_by_id,
    get_incidents,
    get_mitre_coverage,
    get_recent_incidents,
    get_severity_distribution,
    get_tactic_distribution,
    get_technique_distribution,
    get_threat_intel_for_ip,
    get_top_attacker_ips,
    list_threat_intel,
)

logger = logging.getLogger("socshield.web.routes")

web_bp = Blueprint("web", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

# Whitelist pattern for path parameters (incident ids include dashes,
# colons, the `+` from an ISO 8601 timezone, and `.` from IP octets).
_INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:\-+]{1,200}$")


# ---------- Pages ----------

@web_bp.route("/")
def dashboard() -> str:
    """SOC homepage — KPI cards + charts."""
    try:
        summary = get_dashboard_summary()
        severity = get_severity_distribution()
        top_ips = get_top_attacker_ips(limit=10)
        tactics = get_tactic_distribution()
        techniques = get_technique_distribution()
        timeline = get_alerts_over_time(bucket_minutes=60)
        countries = get_attacks_by_country()
        recent_alerts = get_alerts(page=1, page_size=8, sort_by="timestamp", sort_dir="DESC")["rows"]
        recent_incidents = get_recent_incidents(limit=5)
    except Exception:  # noqa: BLE001
        logger.exception("dashboard render failed")
        abort(500)

    return render_template(
        "dashboard.html",
        summary=summary,
        severity_distribution=severity,
        top_ips=top_ips,
        tactic_distribution=tactics,
        technique_distribution=techniques,
        timeline=timeline,
        countries=countries,
        recent_alerts=recent_alerts,
        recent_incidents=recent_incidents,
        h=helpers,
    )


@web_bp.route("/alerts")
def alerts() -> str:
    """Alerts table with search, severity filter, sort, pagination."""
    search = (request.args.get("q") or "").strip() or None
    severity = (request.args.get("severity") or "").strip().upper() or None
    sort_by = request.args.get("sort", "timestamp")
    sort_dir = request.args.get("dir", "DESC")
    page = helpers.safe_int(request.args.get("page"), default=1, lo=1, hi=10_000)
    page_size = helpers.safe_int(
        request.args.get("page_size"), default=DEFAULT_PAGE_SIZE, lo=1, hi=200
    )

    # Reject if sort_by isn't whitelisted
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "timestamp"
    if severity and severity not in ALLOWED_SEVERITIES:
        severity = None
    if sort_dir.upper() not in ("ASC", "DESC"):
        sort_dir = "DESC"

    data = get_alerts(
        search=search,
        severity=severity,
        sort_by=sort_by,
        sort_dir=sort_dir,
        page=page,
        page_size=page_size,
    )

    return render_template(
        "alerts.html",
        data=data,
        severities=ALLOWED_SEVERITIES,
        sort_columns=list(ALLOWED_SORT_COLUMNS.keys()),
        h=helpers,
    )


@web_bp.route("/incidents")
def incidents() -> str:
    """Incident list with risk / source / timeline / narrative preview."""
    try:
        all_incidents = get_incidents()
    except Exception:  # noqa: BLE001
        logger.exception("incidents list render failed")
        abort(500)
    return render_template(
        "incidents.html",
        incidents=all_incidents,
        h=helpers,
    )


@web_bp.route("/incident/<incident_id>")
def incident_detail(incident_id: str) -> str:
    """Analyst-style detail view: timeline, MITRE, threat-intel, narrative."""
    if not _INCIDENT_ID_PATTERN.match(incident_id or ""):
        abort(404)
    try:
        incident = get_incident_by_id(incident_id)
    except Exception:  # noqa: BLE001
        logger.exception("incident detail render failed")
        abort(500)
    if not incident:
        abort(404)

    # Pull threat-intel for the source IP, if any
    src_ip = incident.get("source_ip")
    threat_intel = get_threat_intel_for_ip(src_ip) if src_ip else None

    return render_template(
        "incident_detail.html",
        incident=incident,
        threat_intel=threat_intel,
        h=helpers,
    )


@web_bp.route("/threat-intel")
def threat_intel() -> str:
    """Threat-intelligence index: known-bad IPs, abuse scores, countries."""
    search = (request.args.get("q") or "").strip() or None
    country = (request.args.get("country") or "").strip().upper() or None
    min_score_raw = request.args.get("min_score")
    min_score: int | None = None
    if min_score_raw:
        try:
            min_score = max(0, min(100, int(min_score_raw)))
        except ValueError:
            min_score = None
    malicious_only = request.args.get("malicious") == "1"

    try:
        records = list_threat_intel(
            min_score=min_score,
            malicious_only=malicious_only,
            country=country,
            search=search,
        )
    except Exception:  # noqa: BLE001
        logger.exception("threat intel render failed")
        records = []

    countries = sorted({r.get("country") for r in records if r.get("country")})

    return render_template(
        "threat_intel.html",
        records=records,
        countries=countries,
        filters={
            "q": search or "",
            "country": country or "",
            "min_score": min_score if min_score is not None else "",
            "malicious_only": malicious_only,
        },
        h=helpers,
    )


@web_bp.route("/mitre")
def mitre() -> str:
    """ATT&CK coverage matrix view."""
    try:
        coverage = get_mitre_coverage()
    except Exception:  # noqa: BLE001
        logger.exception("mitre render failed")
        abort(500)
    return render_template(
        "mitre.html",
        coverage=coverage,
        h=helpers,
    )


# ---------- JSON API (used by auto-refresh JS) ----------

@api_bp.route("/summary")
def api_summary() -> Response:
    """Return the dashboard KPI block (used by the 30s auto-refresh)."""
    return jsonify(get_dashboard_summary())


@api_bp.route("/alerts/recent")
def api_recent_alerts() -> Response:
    """Return the 10 most recent alerts."""
    data = get_alerts(page=1, page_size=10, sort_by="timestamp", sort_dir="DESC")
    return jsonify({
        "rows": [
            {
                "id": r.get("id"),
                "timestamp": helpers.format_timestamp(r.get("timestamp")),
                "source_ip": r.get("source_ip"),
                "detector": r.get("detector"),
                "severity": r.get("severity"),
                "title": r.get("title"),
                "mitre_technique": r.get("mitre_technique"),
                "mitre_tactic": r.get("mitre_tactic"),
            }
            for r in data["rows"]
        ],
        "total": data["total"],
    })


@api_bp.route("/alerts/timeline")
def api_timeline() -> Response:
    return jsonify(get_alerts_over_time(bucket_minutes=60))


@api_bp.route("/alerts/severity")
def api_severity() -> Response:
    return jsonify(get_severity_distribution())


@api_bp.route("/alerts/top-ips")
def api_top_ips() -> Response:
    return jsonify(get_top_attacker_ips(limit=10))


@api_bp.route("/alerts/tactics")
def api_tactics() -> Response:
    return jsonify(get_tactic_distribution())


@api_bp.route("/alerts/techniques")
def api_techniques() -> Response:
    return jsonify(get_technique_distribution())


@api_bp.route("/alerts/countries")
def api_countries() -> Response:
    return jsonify(get_attacks_by_country())


@api_bp.route("/health")
def api_health() -> Response:
    """Liveness probe — used by Docker HEALTHCHECK and load balancers."""
    return jsonify(health_registry.basic())


@api_bp.route("/health/deep")
def api_health_deep() -> tuple[Response, int]:
    """Readiness probe — checks DB, threat-intel cache, watcher log files.

    Returns 200 when every component is healthy, 503 otherwise.
    """
    payload = health_registry.deep()
    code = 200 if payload.get("status") == "ok" else 503
    return jsonify(payload), code


# ---------- Error handlers (scoped to this blueprint) ----------

@web_bp.app_errorhandler(404)
def _not_found(_e):  # noqa: ANN001
    return render_template("error.html", code=404, message="Not Found"), 404


@web_bp.app_errorhandler(500)
def _server_error(_e):  # noqa: ANN001
    return render_template("error.html", code=500, message="Server Error"), 500
