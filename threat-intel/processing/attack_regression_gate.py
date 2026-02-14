#!/usr/bin/env python3
"""Fail CI when ATT&CK coverage regresses too far."""

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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate ATT&CK coverage regression constraints")
    parser.add_argument("--current", required=True, help="Current attack coverage report JSON")
    parser.add_argument("--previous", default="", help="Previous attack coverage report JSON")
    parser.add_argument("--output", default="", help="Optional regression report path")

    parser.add_argument("--max-drop-total-techniques-pct", type=float, default=20.0)
    parser.add_argument("--max-drop-total-tactics-pct", type=float, default=20.0)
    parser.add_argument("--max-drop-sigma-rules-with-attack-pct", type=float, default=25.0)
    parser.add_argument("--max-drop-elastic-rules-with-attack-pct", type=float, default=25.0)
    parser.add_argument("--max-drop-sigma-techniques-pct", type=float, default=25.0)
    parser.add_argument("--max-drop-elastic-techniques-pct", type=float, default=25.0)
    return parser


def _write_report(path_arg: str, report: dict) -> None:
    if not path_arg:
        return
    path = Path(path_arg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _parser().parse_args()

    current_path = Path(args.current)
    previous_path = Path(args.previous) if args.previous else None

    if not current_path.is_file():
        print(f"attack regression gate failed: current report not found: {current_path}")
        return 1

    current_metrics = _measured(_load_json(current_path))
    current = {
        "total_techniques": _to_int(current_metrics, "total_techniques"),
        "total_tactics": _to_int(current_metrics, "total_tactics"),
        "sigma_rules_with_attack": _to_int(current_metrics, "sigma_rules_with_attack"),
        "elastic_rules_with_attack": _to_int(current_metrics, "elastic_rules_with_attack"),
        "sigma_techniques_count": _to_int(current_metrics, "sigma_techniques_count"),
        "elastic_techniques_count": _to_int(current_metrics, "elastic_techniques_count"),
    }

    thresholds = {
        "max_drop_total_techniques_pct": args.max_drop_total_techniques_pct,
        "max_drop_total_tactics_pct": args.max_drop_total_tactics_pct,
        "max_drop_sigma_rules_with_attack_pct": args.max_drop_sigma_rules_with_attack_pct,
        "max_drop_elastic_rules_with_attack_pct": args.max_drop_elastic_rules_with_attack_pct,
        "max_drop_sigma_techniques_pct": args.max_drop_sigma_techniques_pct,
        "max_drop_elastic_techniques_pct": args.max_drop_elastic_techniques_pct,
    }

    if previous_path is None or not previous_path.is_file():
        report = {
            "suite": "attack_coverage_regression_gate",
            "status": "skipped_no_baseline",
            "current": current,
            "previous": {},
            "thresholds": thresholds,
            "regressions": [],
        }
        _write_report(args.output, report)
        print("ATT&CK regression gate skipped (no baseline report)")
        return 0

    previous_metrics = _measured(_load_json(previous_path))
    previous = {
        "total_techniques": _to_int(previous_metrics, "total_techniques"),
        "total_tactics": _to_int(previous_metrics, "total_tactics"),
        "sigma_rules_with_attack": _to_int(previous_metrics, "sigma_rules_with_attack"),
        "elastic_rules_with_attack": _to_int(previous_metrics, "elastic_rules_with_attack"),
        "sigma_techniques_count": _to_int(previous_metrics, "sigma_techniques_count"),
        "elastic_techniques_count": _to_int(previous_metrics, "elastic_techniques_count"),
    }

    regressions: list[str] = []
    for metric, max_drop_pct in (
        ("total_techniques", args.max_drop_total_techniques_pct),
        ("total_tactics", args.max_drop_total_tactics_pct),
        ("sigma_rules_with_attack", args.max_drop_sigma_rules_with_attack_pct),
        ("elastic_rules_with_attack", args.max_drop_elastic_rules_with_attack_pct),
        ("sigma_techniques_count", args.max_drop_sigma_techniques_pct),
        ("elastic_techniques_count", args.max_drop_elastic_techniques_pct),
    ):
        prev = previous[metric]
        cur = current[metric]
        if prev <= 0:
            continue
        drop_pct = _pct_drop(prev, cur)
        if drop_pct > max_drop_pct:
            regressions.append(
                f"{metric} regressed by {drop_pct:.2f}% ({cur} vs {prev}) beyond {max_drop_pct:.2f}%"
            )

    status = "fail" if regressions else "pass"
    report = {
        "suite": "attack_coverage_regression_gate",
        "status": status,
        "current": current,
        "previous": previous,
        "thresholds": thresholds,
        "regressions": regressions,
    }
    _write_report(args.output, report)

    print("ATT&CK regression snapshot:")
    for key in (
        "total_techniques",
        "total_tactics",
        "sigma_rules_with_attack",
        "elastic_rules_with_attack",
        "sigma_techniques_count",
        "elastic_techniques_count",
    ):
        print(f"- {key}: current={current[key]} previous={previous[key]}")

    if regressions:
        print("\nATT&CK regression gate failed:")
        for item in regressions:
            print(f"- {item}")
        return 1

    print("\nATT&CK regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
