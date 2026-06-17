# ===================================================================
# SOCshield — production image
# -------------------------------------------------------------------
# - Base: python:3.12-slim (Debian bookworm, minimal)
# - Non-root user (uid 1000, name "socshield")
# - Layer-cached dependency install
# - Healthcheck calls /api/health (liveness)
# - Entrypoint is /app/docker/entrypoint.sh
# ===================================================================

FROM python:3.12-slim AS base

# ---- Environment ----
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONFAULTHANDLER=1 \
    # Default paths (overridden by env / docker-compose)
    SOCSHIELD_DATA_DIR=/var/lib/socshield \
    SOCSHIELD_LOGS_DIR=/var/lib/socshield/logs \
    SOCSHIELD_REPORTS_DIR=/var/lib/socshield/reports \
    SOCSHIELD_DB_PATH=/var/lib/socshield/alerts.db \
    SOCSHIELD_TI_CACHE_PATH=/var/lib/socshield/threat_intel_cache.db \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    FLASK_DEBUG=0 \
    SOCSHIELD_SERVER=flask \
    GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=4 \
    GUNICORN_TIMEOUT=60 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# ---- OS packages: tini for PID 1 + minimal runtime deps ----
# We deliberately avoid build tools in the final image; wheels cover
# all our deps. `tini` gives us proper signal forwarding (SIGTERM to
# Flask + the monitoring service thread).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        tini \
        ca-certificates \
        curl \
 && rm -rf /var/lib/apt/lists/*

# ---- Create non-root user ----
# UID 1000 matches the typical "first user" on most hosts, so volume
# mounts from the host don't end up owned by root.
RUN groupadd --system --gid 1000 socshield \
 && useradd  --system --uid 1000 --gid socshield \
              --home-dir /app --shell /usr/sbin/nologin \
              --comment "SOCshield service account" socshield

# ---- Workdir + dependency install ----
WORKDIR /app

# Copy ONLY the requirements file first so the install layer is cached
# when only the application code changes.
COPY --chown=socshield:socshield requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && pip install --no-cache-dir gunicorn==22.0.0

# ---- Copy application source ----
COPY --chown=socshield:socshield . /app

# Ensure the docker scripts are executable.
RUN chmod +x /app/docker/entrypoint.sh

# ---- Persistent data directories (mounted as volumes in compose) ----
RUN mkdir -p /var/lib/socshield/logs \
             /var/lib/socshield/reports \
    && chown -R socshield:socshield /var/lib/socshield

# Drop privileges
USER socshield

# ---- Expose the dashboard / API port ----
EXPOSE 5000

# ---- Healthcheck ----
# - interval: 30s (matches dashboard auto-refresh)
# - timeout:  5s
# - start_period: 20s (allow DB init + first detection loop)
# - retries:   3
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${FLASK_PORT}/api/health" || exit 1

# ---- Entrypoint ----
# `tini` is the PID 1 stub that forwards signals to the supervisor.
ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]
