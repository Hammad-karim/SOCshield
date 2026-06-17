"""
SOCshield - Flask dashboard entry point.

Run with::

    python run_dashboard.py

Or::

    python run_dashboard.py --host 0.0.0.0 --port 5000 --debug
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure the repo root is on sys.path so `app.*` imports work
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="socshield-dashboard",
        description="SOCshield analyst dashboard (Flask).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="bind port (default 5000)")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug + auto-reload")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    from app.web import create_app
    app = create_app()

    print("=" * 72)
    print("SOCshield dashboard")
    print("=" * 72)
    print(f"  URL:    http://{args.host}:{args.port}/")
    print(f"  Debug:  {args.debug}")
    print("  Routes: / /alerts /incidents /threat-intel /mitre")
    print("  API:    /api/summary /api/alerts/recent /api/alerts/timeline ...")
    print("=" * 72)

    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=args.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
