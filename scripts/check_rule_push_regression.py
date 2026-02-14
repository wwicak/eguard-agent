#!/usr/bin/env python3
"""Fail CI when rule-push SLO metrics regress beyond tolerance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _to_float(payload: dict, field: str) -> float:
    value = payload.get(field, 0.0)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _pct_increase(previous: float, current: float) -> float:
    if previous <= 0.0:
        return 0.0
    return ((current - previous) * 100.0) / previous


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate rule-push SLO regression constraints")
    parser.add_argument("--current", required=True, help="Current rule-push metrics JSON")
    parser.add_argument("--previous", default="", help="Previous rule-push metrics JSON")
    parser.add_argument("--output", default="", help="Optional regression report path")

    parser.add_argument("--max-transfer-seconds", type=float, default=5.0)
    parser.add_argument("--max-rollout-seconds", type=float, default=30.0)
    parser.add_argument("--max-transfer-increase-pct", type=float, default=25.0)
    parser.add_argument("--max-rollout-increase-pct", type=float, default=25.0)
    return parser


def _write_report(output_arg: str, report: dict) -> None:
    if not output_arg:
        return
    output_path = Path(output_arg)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _extract_measured(payload: dict) -> dict:
    measured = payload.get("measured")
    if isinstance(measured, dict):
        return measured
    return {}


def main() -> int:
    args = _parser().parse_args()

    current_path = Path(args.current)
    previous_path = Path(args.previous) if args.previous else None

    if not current_path.is_file():
        print(f"rule-push regression gate failed: current metrics not found: {current_path}")
        return 1

    current_metrics = _extract_measured(_load_json(current_path))
    current_transfer_seconds = _to_float(current_metrics, "transfer_seconds_at_link_rate")
    current_rollout_seconds = _to_float(current_metrics, "fleet_rollout_seconds")

    thresholds = {
        "max_transfer_seconds": args.max_transfer_seconds,
        "max_rollout_seconds": args.max_rollout_seconds,
        "max_transfer_increase_pct": args.max_transfer_increase_pct,
        "max_rollout_increase_pct": args.max_rollout_increase_pct,
    }

    if previous_path is None or not previous_path.is_file():
        regressions: list[str] = []
        if current_transfer_seconds > args.max_transfer_seconds:
            regressions.append(
                f"transfer_seconds_at_link_rate exceeded absolute ceiling: "
                f"{current_transfer_seconds:.6f} > {args.max_transfer_seconds:.6f}"
            )
        if current_rollout_seconds > args.max_rollout_seconds:
            regressions.append(
                f"fleet_rollout_seconds exceeded absolute ceiling: "
                f"{current_rollout_seconds:.6f} > {args.max_rollout_seconds:.6f}"
            )

        status = "fail" if regressions else "skipped_no_baseline"
        report = {
            "suite": "rule_push_regression_gate",
            "status": status,
            "thresholds": thresholds,
            "current": {
                "transfer_seconds_at_link_rate": current_transfer_seconds,
                "fleet_rollout_seconds": current_rollout_seconds,
            },
            "previous": {},
            "deltas": {},
            "regressions": regressions,
        }
        _write_report(args.output, report)

        if regressions:
            print("Rule-push regression gate failed without baseline:")
            for regression in regressions:
                print(f"- {regression}")
            return 1

        print("Rule-push regression gate skipped (no baseline metrics)")
        return 0

    previous_metrics = _extract_measured(_load_json(previous_path))
    previous_transfer_seconds = _to_float(previous_metrics, "transfer_seconds_at_link_rate")
    previous_rollout_seconds = _to_float(previous_metrics, "fleet_rollout_seconds")

    transfer_increase_pct = _pct_increase(previous_transfer_seconds, current_transfer_seconds)
    rollout_increase_pct = _pct_increase(previous_rollout_seconds, current_rollout_seconds)

    regressions: list[str] = []
    if current_transfer_seconds > args.max_transfer_seconds:
        regressions.append(
            f"transfer_seconds_at_link_rate exceeded absolute ceiling: "
            f"{current_transfer_seconds:.6f} > {args.max_transfer_seconds:.6f}"
        )
    if current_rollout_seconds > args.max_rollout_seconds:
        regressions.append(
            f"fleet_rollout_seconds exceeded absolute ceiling: "
            f"{current_rollout_seconds:.6f} > {args.max_rollout_seconds:.6f}"
        )
    if previous_transfer_seconds > 0.0 and transfer_increase_pct > args.max_transfer_increase_pct:
        regressions.append(
            "transfer_seconds_at_link_rate increased by "
            f"{transfer_increase_pct:.2f}% ({current_transfer_seconds:.6f} vs {previous_transfer_seconds:.6f}) "
            f"beyond {args.max_transfer_increase_pct:.2f}%"
        )
    if previous_rollout_seconds > 0.0 and rollout_increase_pct > args.max_rollout_increase_pct:
        regressions.append(
            "fleet_rollout_seconds increased by "
            f"{rollout_increase_pct:.2f}% ({current_rollout_seconds:.6f} vs {previous_rollout_seconds:.6f}) "
            f"beyond {args.max_rollout_increase_pct:.2f}%"
        )

    status = "fail" if regressions else "pass"
    report = {
        "suite": "rule_push_regression_gate",
        "status": status,
        "thresholds": thresholds,
        "current": {
            "transfer_seconds_at_link_rate": current_transfer_seconds,
            "fleet_rollout_seconds": current_rollout_seconds,
        },
        "previous": {
            "transfer_seconds_at_link_rate": previous_transfer_seconds,
            "fleet_rollout_seconds": previous_rollout_seconds,
        },
        "deltas": {
            "transfer_seconds_delta": current_transfer_seconds - previous_transfer_seconds,
            "transfer_seconds_increase_pct": transfer_increase_pct,
            "fleet_rollout_seconds_delta": current_rollout_seconds - previous_rollout_seconds,
            "fleet_rollout_seconds_increase_pct": rollout_increase_pct,
        },
        "regressions": regressions,
    }
    _write_report(args.output, report)

    print("Rule-push regression snapshot:")
    print(
        "- transfer_seconds_at_link_rate: "
        f"current={current_transfer_seconds:.6f} previous={previous_transfer_seconds:.6f}"
    )
    print(
        "- fleet_rollout_seconds: "
        f"current={current_rollout_seconds:.6f} previous={previous_rollout_seconds:.6f}"
    )

    if regressions:
        print("\nRule-push regression gate failed:")
        for regression in regressions:
            print(f"- {regression}")
        return 1

    print("\nRule-push regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
