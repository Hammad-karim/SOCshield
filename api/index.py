"""
SOCshield - Vercel entry point.

This module is the WSGI/ASGI target that Vercel's `@vercel/python` builder
loads. It re-exports a Flask `app` callable so Vercel can route every
incoming request through the existing dashboard.

Why this file exists (vs. `run_dashboard.py`):
    * `run_dashboard.py` is the local-dev CLI — it parses args and starts
      the dev server. Vercel does not need (or want) that.
    * Vercel's project filesystem is read-only except for `/tmp`. We
      redirect the SQLite stores to `/tmp/socshield/...` here, before any
      submodule computes its path. Local dev and Docker are unaffected:
      they set the env vars in their own entry points and fall through
      to the in-repo defaults.
    * The boot is wrapped in try/except: if anything fails (import error,
      bad config), we still return a Flask `app` so Vercel serves 5xx
      with JSON instead of a hard 502.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure the repo root is on sys.path so `from app.web import create_app`
# works no matter how Vercel invokes this module.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Vercel serverless filesystems: only /tmp is writable. Point the data
# stores there before importing any module that resolves DB paths at
# import time (database.db, threat_intel.cache).
os.environ.setdefault("SOCSHIELD_DB_PATH", "/tmp/socshield/alerts.db")
os.environ.setdefault("SOCSHIELD_TI_CACHE_PATH", "/tmp/socshield/threat_intel_cache.db")
os.environ.setdefault("SOCSHIELD_REPORTS_DIR", "/tmp/socshield/reports")
os.environ.setdefault("SOCSHIELD_LOGS_DIR", "/tmp/socshield/logs")

# Demo mode: always seed demo data when DB is empty on Vercel
os.environ.setdefault("SOCSHIELD_DEMO_MODE", "1")

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("socshield.vercel")

try:
    from app.web import create_app  # noqa: E402

    app = create_app()
    logger.info("SOCshield dashboard app created for Vercel")
except Exception:  # noqa: BLE001
    # Never let a startup error reach Vercel as a hard 502. Return a
    # tiny Flask app that always 500s with a JSON body so the user sees
    # something useful and we still get a proper HTTP response.
    logger.exception("create_app failed; serving minimal error app")
    from flask import Flask, jsonify

    app = Flask("socshield-error")

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def _fallback(path: str):  # noqa: ANN001
        return jsonify({"error": "socshield init failed", "path": f"/{path}"}), 500
