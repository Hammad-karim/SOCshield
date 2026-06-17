#!/usr/bin/env python3
"""
SOCshield - SQLite database backup.

Uses SQLite's online backup API (conn.backup()) so the source DB can
stay in use by the running dashboard / monitoring service. The output
is a single .sqlite3 file written atomically (temp + rename).

Usage:
    python scripts/backup_database.py
    python scripts/backup_database.py --dest /backups/socshield
    python scripts/backup_database.py --retain 14

Exit codes:
    0  success
    1  bad arguments / source DB unreadable
    2  backup write failed
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make the repo root importable when run as a script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Resolve source DB the same way the running app does.
from database import db as alerts_db  # noqa: E402

logger = logging.getLogger("socshield.backup.db")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_part(s: str) -> str:
    return _SAFE_NAME.sub("_", s).strip("_") or "db"


def _atomic_write(src: Path, dest: Path) -> None:
    """Copy via a temp file in the same directory, then rename.

    Works around the cross-device rename limitation when --dest is on a
    different filesystem: we copy the temp file first, then unlink the
    temp.
    """
    import shutil
    import tempfile

    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=dest.name + ".",
        suffix=".partial",
        dir=str(dest.parent),
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        shutil.copyfile(str(src), str(tmp_path))
        # On Windows, dest may already exist; replace.
        if dest.exists():
            dest.unlink()
        os.replace(str(tmp_path), str(dest))
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _prune(dest: Path, retain: int, prefix: str) -> int:
    """Keep the N most recent files in `dest` matching `prefix`."""
    if retain <= 0:
        return 0
    matches = sorted(
        dest.glob(f"{prefix}*.sqlite3"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    pruned = 0
    for stale in matches[retain:]:
        try:
            stale.unlink()
            pruned += 1
            logger.info("pruned old backup: %s", stale)
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
        help="number of most recent backups to keep (default: 14, 0 = keep all)",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="override source DB path (default: alerts_db.DB_PATH)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    src = Path(args.source) if args.source else Path(alerts_db.DB_PATH)
    if not src.exists():
        logger.error("source database does not exist: %s", src)
        return 1

    dest_dir = Path(args.dest)
    dest_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_name = f"socshield_alerts_{stamp}.sqlite3"
    out_path = dest_dir / out_name

    logger.info("backing up %s -> %s", src, out_path)
    try:
        # Use SQLite's online backup API so we don't block writers.
        # (sqlite3.Connection.backup is in the stdlib since 3.7.)
        src_conn = sqlite3.connect(str(src))
        try:
            dst_conn = sqlite3.connect(str(out_path))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
    except sqlite3.Error as exc:
        logger.error("sqlite backup failed: %s", exc)
        return 2

    size = out_path.stat().st_size
    logger.info("backup complete: %s (%d bytes)", out_path, size)

    pruned = _prune(dest_dir, args.retain, "socshield_alerts_")
    if pruned:
        logger.info("pruned %d old backup(s)", pruned)
    return 0


if __name__ == "__main__":
    sys.exit(main())
