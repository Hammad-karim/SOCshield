#!/bin/sh
# SOCshield container entrypoint.
#
# Pre-flight: load .env (if present), validate required env, ensure
# persistent directories exist, init the database, then exec the
# supervisor which runs the monitoring service in a background thread
# and the Flask dashboard in the foreground.
#
# The .env file is OPTIONAL. When present, it is loaded with `set -a`
# to export every variable it defines. Do NOT commit a .env with real
# secrets; the repo ships .env.example only.
set -eu

# ---- Paths (overridable; defaults match docker-compose volumes) ----
SOCSHIELD_DATA_DIR="${SOCSHIELD_DATA_DIR:-/var/lib/socshield}"
SOCSHIELD_LOGS_DIR="${SOCSHIELD_LOGS_DIR:-${SOCSHIELD_DATA_DIR}/logs}"
SOCSHIELD_REPORTS_DIR="${SOCSHIELD_REPORTS_DIR:-${SOCSHIELD_DATA_DIR}/reports}"
SOCSHIELD_DB_PATH="${SOCSHIELD_DB_PATH:-${SOCSHIELD_DATA_DIR}/alerts.db}"
SOCSHIELD_TI_CACHE_PATH="${SOCSHIELD_TI_CACHE_PATH:-${SOCSHIELD_DATA_DIR}/threat_intel_cache.db}"

# Tailed log files (consumed by the watchers; if missing on first run,
# the supervisor will skip them and warn).
SOCSHIELD_AUTH_LOG="${SOCSHIELD_AUTH_LOG:-${SOCSHIELD_LOGS_DIR}/auth.log}"
SOCSHIELD_FIREWALL_LOG="${SOCSHIELD_FIREWALL_LOG:-${SOCSHIELD_LOGS_DIR}/firewall.log}"
SOCSHIELD_PRIV_LOG="${SOCSHIELD_PRIV_LOG:-${SOCSHIELD_LOGS_DIR}/priv.log}"

export SOCSHIELD_DATA_DIR SOCSHIELD_LOGS_DIR SOCSHIELD_REPORTS_DIR
export SOCSHIELD_DB_PATH SOCSHIELD_TI_CACHE_PATH
export SOCSHIELD_AUTH_LOG SOCSHIELD_FIREWALL_LOG SOCSHIELD_PRIV_LOG

# ---- Load .env if present ----
if [ -f "/app/.env" ]; then
    echo "[entrypoint] loading /app/.env"
    set -a
    # shellcheck disable=SC1091
    . /app/.env
    set +a
fi

# ---- Ensure persistent directories exist ----
mkdir -p \
    "${SOCSHIELD_DATA_DIR}" \
    "${SOCSHIELD_LOGS_DIR}" \
    "${SOCSHIELD_REPORTS_DIR}" \
    "$(dirname "${SOCSHIELD_AUTH_LOG}")" \
    "$(dirname "${SOCSHIELD_FIREWALL_LOG}")" \
    "$(dirname "${SOCSHIELD_PRIV_LOG}")"

# ---- Pre-flight checks (warn-only; do not abort) ----
warn() { echo "[entrypoint][WARN] $*" >&2; }
info() { echo "[entrypoint] $*"; }

if [ -z "${ABUSEIPDB_API_KEY:-}" ] && [ -z "${VIRUSTOTAL_API_KEY:-}" ]; then
    warn "No threat-intel API keys set — SOCSHIELD_MOCK_TI will be enabled."
    export SOCSHIELD_MOCK_TI=1
fi

if [ ! -f "${SOCSHIELD_DB_PATH}" ]; then
    info "database not found at ${SOCSHIELD_DB_PATH} — will be created on startup"
fi

# ---- Optional: seed sample log files (first run only) ----
if [ "${SOCSHIELD_SEED_LOGS:-0}" = "1" ]; then
    if [ ! -s "${SOCSHIELD_AUTH_LOG}" ]; then
        info "seeding sample auth.log (SOCSHIELD_SEED_LOGS=1)"
        cp -n /app/logs/auth.log "${SOCSHIELD_AUTH_LOG}" 2>/dev/null || true
    fi
    if [ ! -s "${SOCSHIELD_FIREWALL_LOG}" ]; then
        cp -n /app/logs/firewall.log "${SOCSHIELD_FIREWALL_LOG}" 2>/dev/null || true
    fi
    if [ ! -s "${SOCSHIELD_PRIV_LOG}" ]; then
        cp -n /app/logs/priv.log "${SOCSHIELD_PRIV_LOG}" 2>/dev/null || true
    fi
fi

# ---- Sanity: write a startup marker to the runtime logs ----
echo "[entrypoint] $(date -u +%Y-%m-%dT%H:%M:%SZ) SOCshield starting (PID $$)" \
    >> "${SOCSHIELD_LOGS_DIR}/startup.log"

# ---- Exec the supervisor (becomes PID 1 in the container) ----
info "exec: python -m app.supervisor"
exec python -m app.supervisor
