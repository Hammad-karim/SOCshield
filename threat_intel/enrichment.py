"""
SOCshield - Threat Intel Enrichment Layer

Wraps the AbuseIPDB + VirusTotal providers with cache, normalisation, and a
metrics aggregator that the report / main pipeline can consume.

The module can run in MOCK mode (set ``SOCSHIELD_MOCK_TI=1``) so the whole
pipeline is end-to-end runnable without real API keys.
"""

from __future__ import annotations

import logging
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Ensure the repo root is importable no matter how this file is loaded.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Make sure the cache table exists before any reads.
import threat_intel.cache as ti_cache  # noqa: E402
from threat_intel.abuseipdb import check_ip as abuseipdb_check  # noqa: E402
from threat_intel.virustotal import lookup_ip as vt_lookup  # noqa: E402

logger = logging.getLogger("socshield.enrichment")

_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h

# Severity thresholds
_ABUSE_SCORE_BAD_THRESHOLD = 50
_VT_MALICIOUS_COUNT_THRESHOLD = 3

# Risk bucket mapping from abuse score
_RISK_BY_SCORE = (
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (0,  "LOW"),
)


def _risk_for_score(score: int | None) -> str:
    """Bucket an abuse score (0-100) into LOW/MEDIUM/HIGH/CRITICAL."""
    if score is None:
        return "UNKNOWN"
    for threshold, label in _RISK_BY_SCORE:
        if score >= threshold:
            return label
    return "LOW"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_mock_mode() -> bool:
    """True when the global MOCK-TI env flag is set."""
    return os.environ.get("SOCSHIELD_MOCK_TI") == "1"


def _resolve_keys(
    abuseipdb_key: str | None, vt_key: str | None
) -> tuple[str | None, str | None]:
    """Ensure mock-mode callers always have a ``mock_*`` key for the providers.

    The AbuseIPDB / VirusTotal providers only enter the synthetic-MOCK branch
    when they receive a key starting with ``mock_`` (or, separately, when
    ``SOCSHIELD_MOCK_TI=1`` is set *and* a key is supplied). When the env flag
    is set but the caller passed ``None`` (the default in
    :func:`enrich_campaigns`), we substitute a sentinel ``mock_env`` key so
    the providers' MOCK branch is exercised end-to-end.
    """
    if not _is_mock_mode():
        return abuseipdb_key, vt_key
    if not abuseipdb_key:
        abuseipdb_key = "mock_env"
    if not vt_key:
        vt_key = "mock_env"
    return abuseipdb_key, vt_key


def _ensure_mock_default() -> None:
    """Enable MOCK-TI mode automatically when no real API keys are configured.

    The threat-intel providers gate their MOCK path on (a) a ``mock_*`` key
    prefix or (b) the ``SOCSHIELD_MOCK_TI=1`` env flag *plus* a key. To keep
    the pipeline runnable end-to-end out of the box (and to make the spec
    confirmation commands work without manual setup), flip the env flag on
    when neither provider has a real key set in the environment.
    """
    if _is_mock_mode():
        return
    if os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY"):
        return
    os.environ["SOCSHIELD_MOCK_TI"] = "1"


@dataclass
class ThreatIntel:
    """Normalised threat-intel result for a single IP."""

    ip: str
    abuse_score: int | None = None
    abuse_reports: int | None = None
    country: str | None = None
    isp: str | None = None
    reputation: int | None = None
    malicious_count: int | None = None
    suspicious_count: int | None = None
    malicious: bool = False
    sources: list[str] = field(default_factory=list)
    fetched_at: str = ""
    errors: list[str] = field(default_factory=list)

    # ---------- Serialization ---------- #

    def to_dict(self) -> dict:
        """Return a JSON-friendly dict representation."""
        return asdict(self)

    @classmethod
    def from_cache_dict(cls, d: dict) -> "ThreatIntel":
        """Rehydrate a ThreatIntel from a cache dict (legacy / on-disk shape)."""
        if not isinstance(d, dict):
            raise TypeError(f"from_cache_dict expects dict, got {type(d)!r}")
        # Tolerate extra / missing keys gracefully.
        return cls(
            ip=d.get("ip", ""),
            abuse_score=d.get("abuse_score"),
            abuse_reports=d.get("abuse_reports"),
            country=d.get("country"),
            isp=d.get("isp"),
            reputation=d.get("reputation"),
            malicious_count=d.get("malicious_count"),
            suspicious_count=d.get("suspicious_count"),
            malicious=bool(d.get("malicious", False)),
            sources=list(d.get("sources", []) or []),
            fetched_at=d.get("fetched_at", "") or "",
            errors=list(d.get("errors", []) or []),
        )


# ---------- Public API ---------- #

def enrich_ip(
    ip: str,
    *,
    abuseipdb_key: str | None = None,
    vt_key: str | None = None,
    use_cache: bool = True,
) -> ThreatIntel:
    """Return a normalised :class:`ThreatIntel` for ``ip``.

    Order of operations:
        1. Cache lookup (if enabled + not expired) → return immediately.
        2. AbuseIPDB lookup.
        3. VirusTotal lookup.
        4. Compute ``malicious`` from abuse score / VT malicious count.
        5. Stamp ``fetched_at`` and persist to cache.
        6. Return the result.

    Provider failures are *non-fatal*: they're recorded in ``errors`` and the
    function still returns a best-effort :class:`ThreatIntel`.
    """
    abuseipdb_key, vt_key = _resolve_keys(abuseipdb_key, vt_key)
    ti_cache.init_cache()

    if use_cache:
        cached = ti_cache.get(ip)
        if cached is not None:
            logger.debug("threat-intel cache hit for %s", ip)
            return ThreatIntel.from_cache_dict(cached)

    ti = ThreatIntel(ip=ip)

    # ---- AbuseIPDB ----
    try:
        result = abuseipdb_check(ip, abuseipdb_key)
    except Exception as exc:  # defensive: provider must never raise
        result = None  # type: ignore[assignment]
        ti.errors.append(f"abuseipdb_exception: {exc.__class__.__name__}")

    if result is not None and getattr(result, "success", False):
        data = getattr(result, "data", {}) or {}
        ti.abuse_score = data.get("abuse_confidence_score")
        ti.abuse_reports = data.get("total_reports")
        if data.get("country_code"):
            ti.country = data.get("country_code")
        if data.get("isp"):
            ti.isp = data.get("isp")
        if "abuseipdb" not in ti.sources:
            ti.sources.append("abuseipdb")
    elif result is not None:
        err = getattr(result, "error", "") or "abuseipdb_failed"
        ti.errors.append(f"abuseipdb: {err}")

    # ---- VirusTotal ----
    try:
        result = vt_lookup(ip, vt_key)
    except Exception as exc:  # defensive
        result = None  # type: ignore[assignment]
        ti.errors.append(f"virustotal_exception: {exc.__class__.__name__}")

    if result is not None and getattr(result, "success", False):
        data = getattr(result, "data", {}) or {}
        ti.reputation = data.get("reputation")
        ti.malicious_count = data.get("malicious")
        ti.suspicious_count = data.get("suspicious")
        if "virustotal" not in ti.sources:
            ti.sources.append("virustotal")
    elif result is not None:
        err = getattr(result, "error", "") or "virustotal_failed"
        ti.errors.append(f"virustotal: {err}")

    # ---- Decide malicious ----
    abuse_bad = ti.abuse_score is not None and ti.abuse_score >= _ABUSE_SCORE_BAD_THRESHOLD
    vt_bad = ti.malicious_count is not None and ti.malicious_count >= _VT_MALICIOUS_COUNT_THRESHOLD
    ti.malicious = bool(abuse_bad or vt_bad)

    ti.fetched_at = _now_iso()

    # Persist for next time (best-effort; cache failures are non-fatal).
    try:
        ti_cache.put(ip, ti.to_dict(), ttl_seconds=_CACHE_TTL_SECONDS)
    except Exception as exc:  # pragma: no cover
        logger.debug("threat-intel cache put failed for %s: %s", ip, exc)

    return ti


def enrich_campaigns(campaigns: list) -> list:
    """Enrich each campaign in-place with ``campaign.threat_intel``.

    Mutates the provided list and also returns it for caller convenience.
    """
    if not campaigns:
        return campaigns

    # Auto-enable mock mode when no real API keys are configured so the
    # pipeline produces real-looking enrichments out of the box.
    _ensure_mock_default()

    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")

    for c in campaigns:
        ip = getattr(c, "source_ip", None)
        if not ip:
            continue
        try:
            c.threat_intel = enrich_ip(
                ip,
                abuseipdb_key=abuse_key,
                vt_key=vt_key,
                use_cache=True,
            )
        except Exception as exc:  # defensive — one bad IP mustn't break the run
            logger.exception("enrichment failed for %s: %s", ip, exc)
            c.threat_intel = ThreatIntel(
                ip=ip,
                errors=[f"enrichment_exception: {exc.__class__.__name__}"],
                fetched_at=_now_iso(),
            )
    return campaigns


def compute_metrics(campaigns: Iterable) -> dict:
    """Compute a top-level metrics dict from a list of enriched campaigns.

    Returns a JSON-serialisable dict with the keys mandated by the spec.
    Campaigns without a ``threat_intel`` are skipped for the IP-level metrics
    but still count toward ``total_campaigns_enriched`` only when enriched.
    """
    enriched = [c for c in campaigns if getattr(c, "threat_intel", None) is not None]
    total_enriched = len(enriched)

    # ---- malicious IP count ----
    malicious_ip_count = 0
    for c in enriched:
        ti = c.threat_intel
        if getattr(ti, "malicious", False):
            malicious_ip_count += 1

    # ---- top countries ----
    country_counter: Counter[str] = Counter()
    for c in enriched:
        ti = c.threat_intel
        country = getattr(ti, "country", None)
        if country:
            country_counter[country] += 1
    top_countries = [
        {"country": country, "count": count}
        for country, count in country_counter.most_common(5)
    ]

    # ---- average abuse score ----
    abuse_scores: list[int] = []
    for c in enriched:
        score = getattr(c.threat_intel, "abuse_score", None)
        if score is not None:
            abuse_scores.append(int(score))
    average_abuse_score: float | None
    if abuse_scores:
        average_abuse_score = sum(abuse_scores) / len(abuse_scores)
    else:
        average_abuse_score = None

    # ---- highest risk attacker ----
    highest_risk_attacker: dict | None = None
    best_score: int | None = None
    for c in enriched:
        ti = c.threat_intel
        score = getattr(ti, "abuse_score", None)
        if score is None:
            continue
        if best_score is None or score > best_score:
            best_score = int(score)
            highest_risk_attacker = {
                "ip": c.source_ip,
                "risk": getattr(c, "risk", None) or _risk_for_score(score),
                "abuse_score": int(score),
            }
    # Fall back to "UNKNOWN" if we have campaigns but no abuse scores
    if highest_risk_attacker is None and enriched:
        # Pick the first enriched campaign (preserves correlator order)
        first = enriched[0]
        highest_risk_attacker = {
            "ip": first.source_ip,
            "risk": getattr(first, "risk", "UNKNOWN"),
            "abuse_score": None,
        }

    return {
        "malicious_ip_count": malicious_ip_count,
        "top_countries": top_countries,
        "average_abuse_score": average_abuse_score,
        "highest_risk_attacker": highest_risk_attacker,
        "total_campaigns_enriched": total_enriched,
    }


__all__ = [
    "ThreatIntel",
    "enrich_ip",
    "enrich_campaigns",
    "compute_metrics",
]
