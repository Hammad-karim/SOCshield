"""
SOCshield - Vercel entry-point shim.

Vercel's `@vercel/python` builder looks for a top-level WSGI callable
(named `app`, `handler`, or `application`) in the file referenced by
`vercel.json`. Keeping that surface at the project root — separated from
the real entry logic in `api/index.py` — means the Vercel config can
point at a single, stable filename even if the internal layout changes.

This file does nothing except re-export the Flask app. Local dev is
unaffected: `run_dashboard.py` continues to be the developer entry.
"""
from __future__ import annotations

from api.index import app  # noqa: F401  (re-export)
