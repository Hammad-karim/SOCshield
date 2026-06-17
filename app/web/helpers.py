"""
SOCshield - Dashboard view helpers.

Pure functions that turn raw backend values into analyst-friendly
display strings / color codes. Kept separate from queries.py so the
templates can import the constants without dragging the DB layer in.
"""
from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any

# ---- Severity color palette (Bootstrap 5 + dark theme) ----
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#dc2626",  # red
    "HIGH":     "#ea580c",  # orange
    "MEDIUM":   "#ca8a04",  # amber
    "LOW":      "#16a34a",  # green
}
SEVERITY_BADGE: dict[str, str] = {
    "CRITICAL": "bg-danger",
    "HIGH":     "bg-warning text-dark",
    "MEDIUM":   "bg-info text-dark",
    "LOW":      "bg-success",
}
SEVERITY_RANK: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Tactic -> color (matches the ATT&CK palette where possible)
TACTIC_COLORS: dict[str, str] = {
    "Reconnaissance": "#1e40af",
    "Credential Access": "#7c2d12",
    "Privilege Escalation": "#581c87",
}

# Detector -> short human label
DETECTOR_LABELS: dict[str, str] = {
    "BRUTE_FORCE":           "Brute Force",
    "PORT_SCAN:HORIZONTAL":  "Port Scan — Horizontal",
    "PORT_SCAN:VERTICAL":    "Port Scan — Vertical",
    "PORT_SCAN:SYN_FLOOD":   "Port Scan — SYN Flood",
    "PRIV_ESC":              "Privilege Escalation",
}


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get((severity or "").upper(), "#6b7280")


def severity_badge(severity: str | None) -> str:
    return SEVERITY_BADGE.get((severity or "").upper(), "bg-secondary")


def tactic_color(tactic: str | None) -> str:
    return TACTIC_COLORS.get(tactic or "", "#374151")


def detector_label(detector: str | None) -> str:
    if not detector:
        return "-"
    return DETECTOR_LABELS.get(detector, detector)


def format_timestamp(value: Any) -> str:
    """Return 'YYYY-MM-DD HH:MM:SS' from an ISO / sqlite string / datetime."""
    if not value:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    s = str(value)
    try:
        return datetime.fromisoformat(s).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return s


def format_date(value: Any) -> str:
    if not value:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    s = str(value)
    try:
        return datetime.fromisoformat(s).strftime("%Y-%m-%d")
    except ValueError:
        return s[:10] if len(s) >= 10 else s


def truncate(value: Any, length: int = 80) -> str:
    if value is None:
        return ""
    s = str(value)
    if len(s) <= length:
        return s
    return s[: length - 1] + "…"


# ---- Input validation ----

_SAFE_PARAM = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def is_safe_param(value: str | None) -> bool:
    """Conservative whitelist for free-form URL params (search, etc.).

    Anything that doesn't look like an IP, hostname, detector name, or
    MITRE technique id is rejected. This protects against trivial
    injection attempts even though all DB calls are parameterised.
    """
    if value is None:
        return True
    return bool(_SAFE_PARAM.match(value))


def safe_int(value: Any, default: int = 0, lo: int = 0, hi: int = 10_000) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def escape(text: Any) -> str:
    if text is None:
        return ""
    return html.escape(str(text))


def abuse_score_label(score: int | float | None) -> str:
    if score is None:
        return "Unknown"
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "Unknown"
    if s >= 90:
        return f"{s} (Critical)"
    if s >= 70:
        return f"{s} (High)"
    if s >= 40:
        return f"{s} (Medium)"
    return f"{s} (Low)"
