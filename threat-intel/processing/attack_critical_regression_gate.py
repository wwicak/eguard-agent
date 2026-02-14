#!/usr/bin/env python3
"""Fail CI when critical ATT&CK floor coverage regresses too far."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_metrics(report: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    measured = report.get("measured")
    if not isinstance(measured, dict):
        measured = report

    missing_required = report.get("missing_required_techniques", [])
    if not isinstance(missing_required, list):
        missing_required = []
    missing_required = sorted({str(item).strip().upper() for item in missing_required if str(item).strip()})

    metrics = {
        "critical_total": _to_int(measured.get("critical_total"), 0),
        "covered_count": _to_int(measured.get("covered_count"), 0),
        "covered_ratio": _to_float(measured.get("covered_ratio"), 0.0),
        "missing_count": _to_int(measured.get("missing_count"), 0),
        "missing_required_count": len(missing_required),
    }
    return metrics, missing_required


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate critical ATT&CK floor regression constraints")
    parser.add_argument("--current", required=True, help="Current critical ATT&CK gate report JSON")
    parser.add_argument("--previous", default="", help="Previous critical ATT&CK gate report JSON")
    parser.add_argument("--output", default="", help="Optional regression report output JSON")

    parser.add_argument("--max-covered-count-drop", type=int, default=2)
    parser.add_argument("--max-covered-ratio-drop", type=float, default=0.08)
    parser.add_argument("--max-missing-count-increase", type=int, default=2)
    parser.add_argument("--max-missing-required-increase", type=int, default=0)
    return parser


def _write_report(path_arg: str, report: dict[str, Any]) -> None:
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
        print(f"critical ATT&CK regression gate failed: current report not found: {current_path}")
        return 1

    current_report = _load_json(current_path)
    current_metrics, current_missing_required = _extract_metrics(current_report)

    thresholds = {
        "max_covered_count_drop": args.max_covered_count_drop,
        "max_covered_ratio_drop": args.max_covered_ratio_drop,
        "max_missing_count_increase": args.max_missing_count_increase,
        "max_missing_required_increase": args.max_missing_required_increase,
    }

    if previous_path is None or not previous_path.is_file():
        report = {
            "suite": "attack_critical_regression_gate",
            "status": "skipped_no_baseline",
            "current": current_metrics,
            "previous": {},
            "thresholds": thresholds,
            "deltas": {},
            "regressions": [],
        }
        _write_report(args.output, report)
        print("Critical ATT&CK regression gate skipped (no baseline report)")
        return 0

    previous_report = _load_json(previous_path)
    previous_metrics, previous_missing_required = _extract_metrics(previous_report)

    covered_count_delta = current_metrics["covered_count"] - previous_metrics["covered_count"]
    covered_ratio_delta = current_metrics["covered_ratio"] - previous_metrics["covered_ratio"]
    missing_count_delta = current_metrics["missing_count"] - previous_metrics["missing_count"]
    missing_required_delta = (
        current_metrics["missing_required_count"] - previous_metrics["missing_required_count"]
    )

    covered_count_drop = max(-covered_count_delta, 0)
    covered_ratio_drop = max(-covered_ratio_delta, 0.0)
    missing_count_increase = max(missing_count_delta, 0)
    missing_required_increase = max(missing_required_delta, 0)

    new_missing_required = sorted(set(current_missing_required) - set(previous_missing_required))
    resolved_missing_required = sorted(set(previous_missing_required) - set(current_missing_required))

    regressions: list[str] = []
    if covered_count_drop > args.max_covered_count_drop:
        regressions.append(
            "covered_count regressed by "
            f"{covered_count_drop} ({current_metrics['covered_count']} vs {previous_metrics['covered_count']}) "
            f"beyond {args.max_covered_count_drop}"
        )
    if covered_ratio_drop > args.max_covered_ratio_drop:
        regressions.append(
            "covered_ratio regressed by "
            f"{covered_ratio_drop:.4f} ({current_metrics['covered_ratio']:.4f} vs {previous_metrics['covered_ratio']:.4f}) "
            f"beyond {args.max_covered_ratio_drop:.4f}"
        )
    if missing_count_increase > args.max_missing_count_increase:
        regressions.append(
            "missing_count increased by "
            f"{missing_count_increase} ({current_metrics['missing_count']} vs {previous_metrics['missing_count']}) "
            f"beyond {args.max_missing_count_increase}"
        )
    if missing_required_increase > args.max_missing_required_increase:
        regressions.append(
            "missing_required_count increased by "
            f"{missing_required_increase} ({current_metrics['missing_required_count']} vs {previous_metrics['missing_required_count']}) "
            f"beyond {args.max_missing_required_increase}"
        )

    status = "fail" if regressions else "pass"
    report = {
        "suite": "attack_critical_regression_gate",
        "status": status,
        "current": current_metrics,
        "previous": previous_metrics,
        "thresholds": thresholds,
        "deltas": {
            "covered_count_delta": covered_count_delta,
            "covered_ratio_delta": round(covered_ratio_delta, 4),
            "missing_count_delta": missing_count_delta,
            "missing_required_count_delta": missing_required_delta,
            "new_missing_required_techniques": new_missing_required,
            "resolved_missing_required_techniques": resolved_missing_required,
        },
        "regressions": regressions,
    }
    _write_report(args.output, report)

    print("Critical ATT&CK regression snapshot:")
    print(
        f"- covered_count: current={current_metrics['covered_count']} previous={previous_metrics['covered_count']}"
    )
    print(
        f"- covered_ratio: current={current_metrics['covered_ratio']:.4f} previous={previous_metrics['covered_ratio']:.4f}"
    )
    print(
        f"- missing_count: current={current_metrics['missing_count']} previous={previous_metrics['missing_count']}"
    )
    print(
        "- missing_required_count: "
        f"current={current_metrics['missing_required_count']} previous={previous_metrics['missing_required_count']}"
    )

    if regressions:
        print("\nCritical ATT&CK regression gate failed:")
        for item in regressions:
            print(f"- {item}")
        return 1

    print("\nCritical ATT&CK regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
