#!/bin/sh
# SOCshield - run both backup scripts in sequence. Suitable for cron
# or a systemd timer. Exit non-zero if either backup fails.
#
# Cron example (daily at 02:30, retain 30 days):
#   30 2 * * * /app/scripts/backup_all.sh >> /var/lib/socshield/logs/backup.log 2>&1

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BACKUP_DIR="${SOCSHIELD_BACKUP_DIR:-/var/backups/socshield}"
RETAIN="${SOCSHIELD_BACKUP_RETAIN:-30}"
export SOCSHIELD_BACKUP_DIR SOCSHIELD_BACKUP_RETAIN

mkdir -p "$BACKUP_DIR"

echo "[backup_all] $(date -u +%Y-%m-%dT%H:%M:%SZ) starting"

python "$REPO_ROOT/scripts/backup_database.py" --dest "$BACKUP_DIR" --retain "$RETAIN"
python "$REPO_ROOT/scripts/backup_reports.py"   --dest "$BACKUP_DIR" --retain "$RETAIN"

echo "[backup_all] $(date -u +%Y-%m-%dT%H:%M:%SZ) done"
