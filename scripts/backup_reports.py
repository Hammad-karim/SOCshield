#!/usr/bin/env python3
"""
SOCshield - Reports backup.

Archives the JSON incident reports + the MITRE coverage report into
a single timestamped tarball. The destination is rotated to keep the
N most recent archives.

Usage:
    python scripts/backup_reports.py
    python scripts/backup_reports.py --dest /backups/socshield
    python scripts/backup_reports.py --retain 14

Exit codes:
    0  success (including "no reports to back up" — not an error)
    1  bad arguments
    2  archive write failed
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

# Make the repo root importable when run as a script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Reports dir resolves the same way as the running app (env override).
import os as _os
_DEFAULT_REPORTS = _REPO_ROOT / "reports"
REPORTS_DIR = Path(_os.environ.get("SOCSHIELD_REPORTS_DIR", str(_DEFAULT_REPORTS))).resolve()

logger = logging.getLogger("socshield.backup.reports")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_part(s: str) -> str:
    return _SAFE_NAME.sub("_", s).strip("_") or "reports"


def _prune(dest: Path, retain: int, prefix: str) -> int:
    if retain <= 0:
        return 0
    matches = sorted(
        dest.glob(f"{prefix}*.tar.gz"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    pruned = 0
    for stale in matches[retain:]:
        try:
            stale.unlink()
            pruned += 1
            logger.info("pruned old archive: %s", stale)
        except OSError as exc:
            logger.warning("failed to prune %s: %s", stale, exc)
    return pruned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dest",
        default=os.environ.get("SOCSHIELD_BACKUP_DIR", "/var/backups/socshield"),
        help="destination directory (default: /var/backups/socshield)",
    )
    parser.add_argument(
        "--retain",
        type=int,
        default=int(os.environ.get("SOCSHIELD_BACKUP_RETAIN", "14")),
        help="number of most recent archives to keep (default: 14, 0 = keep all)",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="override source reports dir",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    src = Path(args.source) if args.source else REPORTS_DIR
    if not src.exists():
        logger.error("reports directory does not exist: %s", src)
        return 1

    dest_dir = Path(args.dest)
    dest_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = dest_dir / f"socshield_reports_{stamp}.tar.gz"

    # Files to include: every incident JSON + mitre_coverage.json (if present).
    files: list[Path] = []
    incidents_dir = src / "incidents"
    if incidents_dir.exists():
        files.extend(sorted(incidents_dir.glob("incident_*.json")))
    coverage = src / "mitre_coverage.json"
    if coverage.exists():
        files.append(coverage)

    if not files:
        logger.warning("no reports found under %s — nothing to back up", src)
        return 0

    logger.info("archiving %d file(s) -> %s", len(files), out_path)
    try:
        with tarfile.open(out_path, "w:gz") as tar:
            for f in files:
                # Store each file under a stable prefix so a restore is
                # unambiguous about where the file came from.
                arcname = f"reports/{f.relative_to(src).as_posix()}"
                tar.add(str(f), arcname=arcname, recursive=False)
    except OSError as exc:
        logger.error("failed to write archive: %s", exc)
        return 2

    size = out_path.stat().st_size
    logger.info("archive complete: %s (%d bytes, %d file(s))", out_path, size, len(files))

    pruned = _prune(dest_dir, args.retain, "socshield_reports_")
    if pruned:
        logger.info("pruned %d old archive(s)", pruned)
    return 0


if __name__ == "__main__":
    sys.exit(main())
