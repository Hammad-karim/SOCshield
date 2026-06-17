"""
SOCshield - Security Operations Center Shield

Main entry point. Wires together the pipeline layers:

    database (SQLite)
        ^
    orchestrator  -->  runs detectors, collects Alert objects
        ^
    correlator    -->  groups by source_ip, matches chain rules
        ^
    report_generator  -->  writes one JSON incident per campaign

Expected console output (per spec):
    Alerts collected: X
    Correlated campaigns: Y
    Incident reports generated: Z
"""

from __future__ import annotations

import argparse
import logging
import logging.config
import sys
from collections import Counter
from pathlib import Path

import yaml

# Load .env if present (optional dep — graceful when missing)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

# Project layout
BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"
LOGS_DIR = BASE_DIR / "logs"
DETECTORS_DIR = BASE_DIR / "detectors"
THREAT_INTEL_DIR = BASE_DIR / "threat_intel"
REPORTS_DIR = BASE_DIR / "reports"
DATABASE_DIR = BASE_DIR / "database"
TESTS_DIR = BASE_DIR / "tests"

CONFIG_PATH = APP_DIR / "config.yaml"


def setup_logging() -> None:
    """Configure file + console logging. Honors `app/config.yaml` if present."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "default",
                "stream": sys.stdout,
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "DEBUG",
                "formatter": "default",
                "filename": str(LOGS_DIR / "socshield.log"),
                "maxBytes": 5 * 1024 * 1024,
                "backupCount": 5,
                "encoding": "utf-8",
            },
        },
        "loggers": {
            "socshield": {
                "level": "DEBUG",
                "handlers": ["console", "file"],
                "propagate": False,
            },
        },
    }

    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            if "logging" in user_config:
                for handler in user_config["logging"].get("handlers", {}).values():
                    if "filename" in handler:
                        handler["filename"] = str(LOGS_DIR / Path(handler["filename"]).name)
                log_config.update(user_config["logging"])
        except Exception as exc:  # noqa: BLE001
            print(f"[socshield] Failed to load logging config: {exc}", file=sys.stderr)

    logging.config.dictConfig(log_config)


def _print_pipeline_summary(
    *,
    alerts_total: int,
    alerts_by_detector: dict[str, int],
    campaign_count: int,
    campaigns_by_rule: dict[str, int],
    report_count: int,
) -> None:
    """Pretty console summary — the spec's expected output format."""
    print("=" * 72)
    print("SOCshield pipeline summary")
    print("=" * 72)
    print(f"Alerts collected: {alerts_total}")
    for det, n in sorted(alerts_by_detector.items()):
        print(f"  - {det:<10} : {n}")
    print(f"Correlated campaigns: {campaign_count}")
    for rule, n in sorted(campaigns_by_rule.items()):
        print(f"  - Rule {rule:<4} : {n}")
    print(f"Incident reports generated: {report_count}")


def _print_metrics(metrics: dict) -> None:
    """Print the threat-intel metrics block."""
    print("=" * 72)
    print("Threat-intel metrics")
    print("=" * 72)
    print(f"Malicious IPs: {metrics.get('malicious_ip_count', 0)}")
    avg = metrics.get("average_abuse_score")
    print(f"Average abuse score: {avg if avg is None else round(avg, 2)}")
    top = metrics.get("top_countries", []) or []
    if top:
        print("Top countries:")
        for row in top:
            print(f"  - {row.get('country')!s:<4} : {row.get('count')}")
    else:
        print("Top countries: (none)")
    hra = metrics.get("highest_risk_attacker")
    if hra:
        print(
            f"Highest-risk attacker: {hra.get('ip')} "
            f"(risk={hra.get('risk')}, abuse_score={hra.get('abuse_score')})"
        )
    else:
        print("Highest-risk attacker: (none)")
    print(f"Campaigns enriched: {metrics.get('total_campaigns_enriched', 0)}")


def _print_mitre_stats(coverage) -> None:
    """Print the MITRE ATT&CK stats block."""
    print("=" * 72)
    print("MITRE ATT&CK stats")
    print("=" * 72)
    print(
        f"Techniques covered: {coverage.total_techniques_covered} / "
        f"{coverage.total_techniques_in_catalog} "
        f"({coverage.coverage_ratio * 100:.0f}%)"
    )
    print(f"Tactics covered: {coverage.total_tactics_covered}")
    print(f"Most common tactic: {coverage.most_common_tactic or '-'}")
    print(f"Most common technique: {coverage.most_common_technique or '-'}")
    if coverage.tactic_frequency:
        print("Tactic frequency:")
        for tac, n in sorted(coverage.tactic_frequency.items(),
                             key=lambda kv: (-kv[1], kv[0])):
            print(f"  - {tac:<22} : {n}")
    if coverage.technique_frequency:
        print("Technique frequency:")
        from app import mitre as _mitre
        for tid, n in sorted(coverage.technique_frequency.items(),
                             key=lambda kv: (-kv[1], kv[0])):
            ref = _mitre.get_ref(tid)
            name = ref.technique_name if ref else "?"
            print(f"  - {tid:<8} {name:<32} : {n}")
    if coverage.observed_kill_chain:
        print("Observed kill chain: " + " -> ".join(coverage.observed_kill_chain))


def main() -> int:
    setup_logging()
    logger = logging.getLogger("socshield")

    logger.info("SOCshield starting up")
    logger.debug("Base directory: %s", BASE_DIR)

    # Local imports keep startup cheap and respect the clean-architecture
    # boundary (storage -> orchestrator -> correlator -> reports).
    from database import db as alerts_db
    from app.orchestrator import run_pipeline
    from app.correlator import correlate
    from reports.report_generator import generate_reports
    from reports.coverage_report import generate as generate_coverage_report
    from threat_intel.enrichment import enrich_campaigns, compute_metrics

    # 1. Initialize database
    logger.info("initializing SQLite alert store")
    alerts_db.init_db()

    # 2. Run orchestrator (detectors -> alerts -> DB)
    logger.info("running detection pipeline")
    result = run_pipeline(init_database=False, persist=True)
    logger.info("pipeline produced %d alert(s)", result.total)

    # 3. Run correlator
    logger.info("correlating alerts into attack campaigns")
    campaigns = correlate(result.alerts)
    logger.info("correlator produced %d campaign(s)", len(campaigns))

    # 4. Enrich campaigns with threat-intel (AbuseIPDB + VirusTotal)
    logger.info("enriching campaigns with threat intel")
    enrich_campaigns(campaigns)
    for c in campaigns:
        ti = c.threat_intel
        if ti is None:
            print(f"  [enrich] {c.source_ip:<18} rule={c.rule_id} no data")
            continue
        score = getattr(ti, "abuse_score", None)
        bad = "MALICIOUS" if getattr(ti, "malicious", False) else "clean"
        print(
            f"  [enrich] {c.source_ip:<18} rule={c.rule_id} abuse={score!s:>3} "
            f"vt_malicious={getattr(ti, 'malicious_count', 'n/a')!s:>3} {bad}"
        )

    # 5. Generate incident reports
    logger.info("writing incident reports")
    report_result = generate_reports(campaigns)
    logger.info("wrote %d incident report(s)", report_result.total)

    # 5b. Generate MITRE ATT&CK coverage report (JSON + Markdown)
    logger.info("writing MITRE coverage report")
    coverage = generate_coverage_report(result.alerts)
    logger.info(
        "MITRE coverage: %d/%d techniques (%.0f%%)",
        coverage.total_techniques_covered,
        coverage.total_techniques_in_catalog,
        coverage.coverage_ratio * 100,
    )

    # 6. Print spec-mandated summary
    alerts_by_detector = dict(result.by_detector)
    campaigns_by_rule = dict(Counter(c.rule_id for c in campaigns))
    _print_pipeline_summary(
        alerts_total=result.total,
        alerts_by_detector=alerts_by_detector,
        campaign_count=len(campaigns),
        campaigns_by_rule=campaigns_by_rule,
        report_count=report_result.total,
    )

    # 7. Threat-intel metrics block
    metrics = compute_metrics(campaigns)
    _print_metrics(metrics)

    # 8. MITRE ATT&CK stats block
    _print_mitre_stats(coverage)

    # Exit non-zero if any CRITICAL campaign exists
    has_critical = any(c.risk == "CRITICAL" for c in campaigns)
    return 2 if has_critical else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="socshield",
        description="SOCshield — detection, correlation, threat-intel, MITRE coverage",
    )
    parser.add_argument(
        "--service",
        action="store_true",
        help="Run the long-running real-time monitoring service instead of the batch pipeline.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="(service mode) auto-stop after this many seconds. Useful for tests.",
    )
    args, _unknown = parser.parse_known_args()

    if args.service:
        from app.service import run_service
        sys.exit(run_service(stop_after_seconds=args.duration))

    sys.exit(main())
