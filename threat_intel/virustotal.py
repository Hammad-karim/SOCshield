"""VirusTotal threat intelligence provider.

Provides ``lookup_ip`` which queries the VirusTotal v3 ``ip_addresses`` endpoint
for an IP address and returns a normalised :class:`ProviderResult`.

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


_API_URL = "https://www.virustotal.com/api/v3/ip_addresses"

# Well-known malicious sample IPs that appear in E:\SOCshield\logs\auth.log.
# In MOCK mode these get a non-zero malicious count so downstream consumers
# can exercise the bad-IP paths without a real API key.
_KNOWN_BAD_IPS = frozenset(
    {
        "45.142.66.12",
        "185.220.101.45",
        "91.224.92.18",
        "103.45.211.7",
    }
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


def _mock_lookup(ip: str) -> ProviderResult:
    """Build a deterministic, plausible-looking mock VirusTotal response.

    Well-known bad IPs from the sample auth.log get a non-zero ``malicious``
    count; every other IP is treated as clean.
    """
    if ip in _KNOWN_BAD_IPS:
        digest = hashlib.sha256(ip.encode("utf-8")).digest()
        malicious = (digest[0] % 12) + 3  # 3..14
        suspicious = (digest[1] % 4) + 1  # 1..4
        harmless = 60 + (digest[2] % 20)  # 60..79
        undetected = 10 + (digest[3] % 10)  # 10..19
        # VT computes reputation roughly as -(malicious) + (harmless / 10).
        reputation = -malicious + (harmless // 10)
        return ProviderResult(
            success=True,
            data={
                "reputation": int(reputation),
                "malicious": int(malicious),
                "suspicious": int(suspicious),
                "harmless": int(harmless),
                "undetected": int(undetected),
            },
            error="",
        )

    # Clean IP — no detections.
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    harmless = 70 + (digest[0] % 20)  # 70..89
    undetected = 10 + (digest[1] % 10)  # 10..19
    reputation = harmless // 5  # positive reputation
    return ProviderResult(
        success=True,
        data={
            "reputation": int(reputation),
            "malicious": 0,
            "suspicious": 0,
            "harmless": int(harmless),
            "undetected": int(undetected),
        },
        error="",
    )


def _real_lookup(
    ip: str, api_key: str, timeout: float
) -> ProviderResult:
    """Perform the real HTTPS call to VirusTotal with a small retry loop."""
    if requests is None:  # pragma: no cover - defensive
        return ProviderResult(
            success=False, data={}, error="requests_unavailable"
        )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    url = f"{_API_URL}/{ip}"

    last_exc: Exception | None = None
    for attempt in range(3):  # initial + 2 retries
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
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

        if not isinstance(payload, dict):
            return ProviderResult(
                success=False, data={}, error="unexpected_payload"
            )

        attrs = payload.get("attributes") if isinstance(payload, dict) else None
        if not isinstance(attrs, dict):
            return ProviderResult(
                success=False, data={}, error="unexpected_payload"
            )

        stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
        if not isinstance(stats, dict):
            return ProviderResult(
                success=False, data={}, error="unexpected_payload"
            )

        data = {
            "reputation": int(attrs.get("reputation", 0) or 0),
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
        }
        return ProviderResult(success=True, data=data, error="")

    # Should be unreachable, but keep mypy happy.
    return ProviderResult(
        success=False,
        data={},
        error=f"network_error: {last_exc.__class__.__name__ if last_exc else 'unknown'}",
    )


def lookup_ip(
    ip: str,
    api_key: str | None = None,
    *,
    timeout: float = 5.0,
) -> ProviderResult:
    """Look up an IP address via VirusTotal.

    Parameters
    ----------
    ip:
        The IPv4 / IPv6 string to check.
    api_key:
        VirusTotal API key. When ``None`` or empty, a failure result with
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
        return _mock_lookup(ip)

    return _real_lookup(ip, api_key, timeout)


__all__ = ["ProviderResult", "lookup_ip"]
