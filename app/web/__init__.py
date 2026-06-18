"""
SOCshield - Flask Web Application

The SOC analyst dashboard. This package is a presentation layer that
*consumes* the existing detection / correlation / threat-intel / coverage
modules — it does not modify or re-implement any detection logic.

Structure::

    app/web/
    ├── __init__.py          # create_app() factory
    ├── routes.py            # top-level blueprint (dashboard, alerts, incidents,
    │                        #   threat-intel, MITRE, API endpoints)
    ├── queries.py           # read-only data access (SQLite + on-disk reports)
    ├── helpers.py           # severity colors, formatting, validation
    ├── templates/
    │   ├── base.html
    │   ├── dashboard.html
    │   ├── alerts.html
    │   ├── incidents.html
    │   ├── incident_detail.html
    │   ├── threat_intel.html
    │   └── mitre.html
    └── static/
        ├── css/socshield.css
        ├── js/socshield.js
        └── img/architecture.png
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

# Make the repo root importable no matter how this package is loaded
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from flask import Flask  # noqa: E402

from app.web.routes import web_bp, api_bp  # noqa: E402

logger = logging.getLogger("socshield.web")

__all__ = ["create_app"]


def create_app() -> Flask:
    """Build and configure the Flask application.

    Wires the database + threat-intel cache (idempotent), registers the
    blueprints, and returns a ready-to-run app.
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    # Tighten a few defaults — the dashboard reads from SQLite on every
    # request, so we don't need cookies / sessions for the analyst view.
    app.config.update(
        SECRET_KEY="socshield-dashboard",
        JSON_SORT_KEYS=False,
        TEMPLATES_AUTO_RELOAD=True,
    )

    # Ensure the underlying data stores exist (no-op if already present)
    try:
        from database import db as alerts_db
        from threat_intel import cache as ti_cache
        alerts_db.init_db()
        ti_cache.init_cache()
        # Seed demo alerts if database is empty (for Vercel serverless deployment)
        try:
            alerts_db.seed_demo_alerts()
        except Exception:
            logger.debug("demo seeding skipped or failed", exc_info=True)
    except Exception:  # noqa: BLE001
        logger.exception("failed to initialize data stores on app startup")

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    return app
