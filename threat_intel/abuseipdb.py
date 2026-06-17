"""AbuseIPDB threat intelligence provider.

Provides ``check_ip`` which queries the AbuseIPDB v2 check endpoint for an IP
address and returns a normalised :class:`ProviderResult`.

The module can run in MOCK mode — triggered by either the ``SOCSHIELD_MOCK_TI``
environment variable being set to ``"1"`` or by an API key starting with
``"mock_"`` — in which case synthetic but plausible data is produced without
any network access. This lets the whole threat-intel pipeline operate
end-to-end without real API keys.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

# Ensure the repo root is importable so ``import threat_intel`` works no matter
# how this file is loaded (script, test, etc.).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - allow mock-only environments
    requests = None  # type: ignore


_API_URL = "https://api.abuseipdb.com/api/v2/check"
_DEFAULT_MAX_AGE_DAYS = 90
_COUNTRIES = ("RU", "CN", "US", "NL", "DE", "FR", "BR", "IN", "UA", "RO")
_ISPS = (
    "MockISP-Cloud",
    "MockISP-Broadband",
    "MockISP-Mobile",
    "MockISP-Datacenter",
    "MockISP-Residential",
    "MockISP-Tor",
)


@dataclass
class ProviderResult:
    """Normalised result returned by every threat-intel provider."""

    success: bool
    data: dict = field(default_factory=dict)
    error: str = ""


def _is_mock(api_key: str | None) -> bool:
    """Return True when the caller wants the synthetic MOCK path."""
    if os.environ.get("SOCSHIELD_MOCK_TI") == "1":
        return True
    if api_key is None:
        return False
    return api_key.startswith("mock_")


def _mock_check(ip: str) -> ProviderResult:
    """Build a deterministic, plausible-looking mock response."""
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    abuse = digest[0]  # 0..255
    total = (digest[1] % 200) + 1  # 1..200
    country = _COUNTRIES[digest[2] % len(_COUNTRIES)]
    isp = _ISPS[digest[3] % len(_ISPS)]
    return ProviderResult(
        success=True,
        data={
            "abuse_confidence_score": int(abuse * 100 / 255),
            "total_reports": int(total),
            "country_code": country,
            "is": isp,  # AbuseIPDB actually returns "isp" as "is"; normalise below
            "isp": isp,
        },
        error="",
    )


def _real_check(
    ip: str, api_key: str, timeout: float
) -> ProviderResult:
    """Perform the real HTTPS call to AbuseIPDB with a small retry loop."""
    if requests is None:  # pragma: no cover - defensive
        return ProviderResult(
            success=False, data={}, error="requests_unavailable"
        )

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": _DEFAULT_MAX_AGE_DAYS,
    }

    last_exc: Exception | None = None
    for attempt in range(3):  # initial + 2 retries
        try:
            resp = requests.get(
                _API_URL, headers=headers, params=params, timeout=timeout
            )
        except Exception as exc:  # network-level error
            last_exc = exc
            if attempt < 2:
                time.sleep(0.5)
                continue
            return ProviderResult(
                success=False,
                data={},
                error=f"network_error: {exc.__class__.__name__}",
            )

        status = resp.status_code
        if status == 429:
            return ProviderResult(success=False, data={}, error="rate_limit")
        if status != 200:
            return ProviderResult(
                success=False, data={}, error=f"http_{status}"
            )

        try:
            payload: Any = resp.json()
        except Exception as exc:
            return ProviderResult(
                success=False,
                data={},
                error=f"json_error: {exc.__class__.__name__}",
            )

        raw = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(raw, dict):
            return ProviderResult(
                success=False, data={}, error="unexpected_payload"
            )

        data = {
            "abuse_confidence_score": int(
                raw.get("abuseConfidenceScore", 0) or 0
            ),
            "total_reports": int(raw.get("totalReports", 0) or 0),
            "country_code": raw.get("countryCode") or "",
            "isp": raw.get("isp") or "",
        }
        return ProviderResult(success=True, data=data, error="")

    # Should be unreachable, but keep mypy happy.
    return ProviderResult(
        success=False,
        data={},
        error=f"network_error: {last_exc.__class__.__name__ if last_exc else 'unknown'}",
    )


def check_ip(
    ip: str,
    api_key: str | None = None,
    *,
    timeout: float = 5.0,
) -> ProviderResult:
    """Look up an IP address via AbuseIPDB.

    Parameters
    ----------
    ip:
        The IPv4 / IPv6 string to check.
    api_key:
        AbuseIPDB API key. When ``None`` or empty, a failure result with
        ``error='no_api_key'`` is returned (no exception is raised).
    timeout:
        Per-request timeout in seconds (ignored in mock mode).

    Returns
    -------
    ProviderResult
        Always a :class:`ProviderResult` instance; never raises for control
        flow reasons.
    """
    if not api_key:
        return ProviderResult(success=False, data={}, error="no_api_key")

    if _is_mock(api_key):
        return _mock_check(ip)

    return _real_check(ip, api_key, timeout)


__all__ = ["ProviderResult", "check_ip"]
