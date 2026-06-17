#!/bin/sh
# SOCshield - post-deployment validation.
# Runs the 8 checks from DEPLOYMENT.md §11 against a running
# `docker compose up -d` stack. Exits non-zero on the first failure
# so it can be used as a smoke test in CI.
#
# Usage:
#   ./scripts/validate_deployment.sh
#   SOCSHIELD_HOST=127.0.0.1:5000 ./scripts/validate_deployment.sh

set -eu

HOST="${SOCSHIELD_HOST:-127.0.0.1:5000}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; exit 1; }

echo "[1/8] container is running and healthy"
if ! docker compose -f "$COMPOSE_FILE" ps socshield > /tmp/_socshield_ps.log 2>&1; then
    cat /tmp/_socshield_ps.log
    fail "docker compose ps failed"
fi
grep -q '(healthy)' /tmp/_socshield_ps.log || fail "container status is not (healthy)"
pass "container healthy"

echo "[2/8] /api/health liveness"
H=$(curl -fsS "http://${HOST}/api/health") || fail "liveness request failed"
echo "$H" | grep -q '"status":"ok"' || fail "liveness payload does not say ok: $H"
pass "$H"

echo "[3/8] /api/health/deep readiness"
D=$(curl -fsS "http://${HOST}/api/health/deep") || fail "deep request failed"
echo "$D" | grep -q '"status":"ok"' || fail "deep payload does not say ok: $D"
pass "all components healthy"

echo "[4/8] dashboard renders"
curl -fsS "http://${HOST}/" -o /tmp/_dash.html
grep -q 'Overview\|Security Operations Dashboard' /tmp/_dash.html \
    || fail "dashboard HTML missing expected title"
pass "dashboard page OK"

echo "[5/8] /alerts renders"
curl -fsS "http://${HOST}/alerts" -o /tmp/_alerts.html
grep -q 'data-table\|soc-table' /tmp/_alerts.html \
    || fail "alerts HTML missing table"
pass "alerts page OK"

echo "[6/8] /incidents renders"
curl -fsS "http://${HOST}/incidents" -o /tmp/_incidents.html
grep -q 'incident-list\|incident-card' /tmp/_incidents.html \
    || fail "incidents HTML missing cards"
pass "incidents page OK"

echo "[7/8] non-root user inside the container"
UID_=$(docker compose -f "$COMPOSE_FILE" exec -T socshield id -u)
[ "$UID_" = "1000" ] || fail "container runs as uid=$UID_ (expected 1000)"
pass "uid=1000 (socshield)"

echo "[8/8] database lives on the persistent volume"
docker compose -f "$COMPOSE_FILE" exec -T socshield ls -la /var/lib/socshield/alerts.db \
    > /dev/null || fail "alerts.db not present on /var/lib/socshield"
pass "alerts.db present on volume"

echo
echo "All checks passed."
