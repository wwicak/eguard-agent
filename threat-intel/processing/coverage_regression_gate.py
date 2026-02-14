#!/usr/bin/env python3
"""Fail CI when signature database coverage regresses too far."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _measured(report: dict) -> dict:
    measured = report.get("measured")
    if isinstance(measured, dict):
        return measured
    return report


def _to_int(metrics: dict, field: str) -> int:
    value = metrics.get(field, 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _pct_drop(previous: int, current: int) -> float:
    if previous <= 0:
        return 0.0
    return ((previous - current) * 100.0) / previous


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate coverage regression constraints")
    parser.add_argument("--current", required=True, help="Current coverage metrics JSON")
    parser.add_argument("--previous", default="", help="Previous coverage metrics JSON")
    parser.add_argument("--output", default="", help="Optional regression report path")

    parser.add_argument("--max-drop-sigma-pct", type=float, default=35.0)
    parser.add_argument("--max-drop-yara-pct", type=float, default=35.0)
    parser.add_argument("--max-drop-suricata-pct", type=float, default=35.0)
    parser.add_argument("--max-drop-elastic-pct", type=float, default=35.0)
    parser.add_argument("--max-drop-ioc-total-pct", type=float, default=35.0)
    parser.add_argument("--max-drop-cve-pct", type=float, default=35.0)
    parser.add_argument("--max-drop-signature-total-pct", type=float, default=20.0)
    parser.add_argument("--max-drop-database-total-pct", type=float, default=20.0)
    parser.add_argument("--max-drop-yara-sources", type=int, default=1)
    parser.add_argument("--max-drop-sigma-sources", type=int, default=1)
    return parser


def _write_report(path_arg: str, report: dict) -> None:
    if not path_arg:
        return
    path = Path(path_arg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _build_parser().parse_args()
    current_path = Path(args.current)
    previous_path = Path(args.previous) if args.previous else None

    if not current_path.is_file():
        print(f"coverage regression gate failed: current report not found: {current_path}")
        return 1

    current_report = _load_json(current_path)
    current_metrics = _measured(current_report)

    current = {
        "sigma_count": _to_int(current_metrics, "sigma_count"),
        "yara_count": _to_int(current_metrics, "yara_count"),
        "suricata_count": _to_int(current_metrics, "suricata_count"),
        "elastic_count": _to_int(current_metrics, "elastic_count"),
        "ioc_total": _to_int(current_metrics, "ioc_total"),
        "cve_count": _to_int(current_metrics, "cve_count"),
        "signature_total": _to_int(current_metrics, "signature_total"),
        "database_total": _to_int(current_metrics, "database_total"),
        "yara_source_count": _to_int(current_metrics, "yara_source_count"),
        "sigma_source_count": _to_int(current_metrics, "sigma_source_count"),
    }

    thresholds = {
        "max_drop_sigma_pct": args.max_drop_sigma_pct,
        "max_drop_yara_pct": args.max_drop_yara_pct,
        "max_drop_suricata_pct": args.max_drop_suricata_pct,
        "max_drop_elastic_pct": args.max_drop_elastic_pct,
        "max_drop_ioc_total_pct": args.max_drop_ioc_total_pct,
        "max_drop_cve_pct": args.max_drop_cve_pct,
        "max_drop_signature_total_pct": args.max_drop_signature_total_pct,
        "max_drop_database_total_pct": args.max_drop_database_total_pct,
        "max_drop_yara_sources": args.max_drop_yara_sources,
        "max_drop_sigma_sources": args.max_drop_sigma_sources,
    }

    if previous_path is None or not previous_path.is_file():
        report = {
            "suite": "bundle_signature_coverage_regression_gate",
            "status": "skipped_no_baseline",
            "current": current,
            "previous": {},
            "thresholds": thresholds,
            "regressions": [],
        }
        _write_report(args.output, report)
        print("Bundle coverage regression gate skipped (no baseline report)")
        return 0

    previous_report = _load_json(previous_path)
    previous_metrics = _measured(previous_report)
    previous = {
        "sigma_count": _to_int(previous_metrics, "sigma_count"),
        "yara_count": _to_int(previous_metrics, "yara_count"),
        "suricata_count": _to_int(previous_metrics, "suricata_count"),
        "elastic_count": _to_int(previous_metrics, "elastic_count"),
        "ioc_total": _to_int(previous_metrics, "ioc_total"),
        "cve_count": _to_int(previous_metrics, "cve_count"),
        "signature_total": _to_int(previous_metrics, "signature_total"),
        "database_total": _to_int(previous_metrics, "database_total"),
        "yara_source_count": _to_int(previous_metrics, "yara_source_count"),
        "sigma_source_count": _to_int(previous_metrics, "sigma_source_count"),
    }

    regressions: list[str] = []

    drop_checks = [
        ("sigma_count", args.max_drop_sigma_pct),
        ("yara_count", args.max_drop_yara_pct),
        ("suricata_count", args.max_drop_suricata_pct),
        ("elastic_count", args.max_drop_elastic_pct),
        ("ioc_total", args.max_drop_ioc_total_pct),
        ("cve_count", args.max_drop_cve_pct),
        ("signature_total", args.max_drop_signature_total_pct),
        ("database_total", args.max_drop_database_total_pct),
    ]
    for metric, max_drop_pct in drop_checks:
        prev = previous[metric]
        cur = current[metric]
        if prev <= 0:
            continue
        drop_pct = _pct_drop(prev, cur)
        if drop_pct > max_drop_pct:
            regressions.append(
                f"{metric} regressed by {drop_pct:.2f}% ({cur} vs {prev}) beyond {max_drop_pct:.2f}%"
            )

    for metric, max_drop_abs in (
        ("yara_source_count", args.max_drop_yara_sources),
        ("sigma_source_count", args.max_drop_sigma_sources),
    ):
        prev = previous[metric]
        cur = current[metric]
        drop = prev - cur
        if drop > max_drop_abs:
            regressions.append(
                f"{metric} regressed by {drop} ({cur} vs {prev}) beyond {max_drop_abs}"
            )

    status = "fail" if regressions else "pass"
    report = {
        "suite": "bundle_signature_coverage_regression_gate",
        "status": status,
        "current": current,
        "previous": previous,
        "thresholds": thresholds,
        "regressions": regressions,
    }
    _write_report(args.output, report)

    print("Bundle coverage regression snapshot:")
    for key in (
        "sigma_count",
        "yara_count",
        "suricata_count",
        "elastic_count",
        "ioc_total",
        "cve_count",
        "signature_total",
        "database_total",
        "yara_source_count",
        "sigma_source_count",
    ):
        print(f"- {key}: current={current[key]} previous={previous[key]}")

    if regressions:
        print("\nBundle coverage regression gate failed:")
        for item in regressions:
            print(f"- {item}")
        return 1

    print("\nBundle coverage regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
