#!/bin/sh
# Install helper: copies the templated unit into /etc/systemd/system and enables it.
# Usage: sudo ./install_service.sh /absolute/path/to/repo

set -eu
REPO_PATH="${1:-}"
if [ -z "$REPO_PATH" ]; then
  echo "Usage: sudo $0 /absolute/path/to/socshield-repo"
  exit 2
fi

UNIT_SRC="$REPO_PATH/deployment/socshield.service"
UNIT_DST="/etc/systemd/system/socshield.service"

if [ ! -f "$UNIT_SRC" ]; then
  echo "Unit template not found at $UNIT_SRC"
  exit 1
fi

cp "$UNIT_SRC" "$UNIT_DST"
# Ensure the WorkingDirectory in the unit points to the actual path
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$REPO_PATH|" "$UNIT_DST"

systemctl daemon-reload
systemctl enable --now socshield.service

echo "socshield.service installed and started. Check status with:"
echo "  sudo systemctl status socshield.service"
