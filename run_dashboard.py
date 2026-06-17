from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure repo root in path
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.web import create_app

# ✅ THIS is what Vercel needs
app = create_app()

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="socshield-dashboard",
        description="SOCshield analyst dashboard (Flask).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    print("=" * 72)
    print("SOCshield dashboard")
    print("=" * 72)
    print(f"  URL:    http://{args.host}:{args.port}/")
    print(f"  Debug:  {args.debug}")
    print("=" * 72)

    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()