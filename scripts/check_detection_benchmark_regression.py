#!/usr/bin/env python3
"""Fail CI when detection benchmark latency regresses beyond tolerance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _to_int(payload: dict, field: str) -> int:
    value = payload.get(field, 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _pct_increase(previous: int, current: int) -> float:
    if previous <= 0:
        return 0.0
    return ((current - previous) * 100.0) / previous


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate detection benchmark regression constraints")
    parser.add_argument("--current", required=True, help="Current detection benchmark metrics JSON")
    parser.add_argument("--previous", default="", help="Previous detection benchmark metrics JSON")
    parser.add_argument("--output", default="", help="Optional regression report output path")
    parser.add_argument("--max-wall-clock-increase-pct", type=float, default=25.0)
    parser.add_argument("--max-wall-clock-ms", type=int, default=60000)
    return parser


def _write_report(output_arg: str, report: dict) -> None:
    if not output_arg:
        return
    output_path = Path(output_arg)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _build_parser().parse_args()

    current_path = Path(args.current)
    previous_path = Path(args.previous) if args.previous else None

    if not current_path.is_file():
        print(f"detection benchmark regression gate failed: current metrics not found: {current_path}")
        return 1

    current_metrics = _load_json(current_path)
    current_wall_ms = _to_int(current_metrics, "wall_clock_ms")

    thresholds = {
        "max_wall_clock_increase_pct": args.max_wall_clock_increase_pct,
        "max_wall_clock_ms": args.max_wall_clock_ms,
    }

    if previous_path is None or not previous_path.is_file():
        report = {
            "suite": "detection_benchmark_regression_gate",
            "status": "skipped_no_baseline",
            "thresholds": thresholds,
            "current": {"wall_clock_ms": current_wall_ms},
            "previous": {},
            "regressions": [],
        }
        _write_report(args.output, report)
        print("detection benchmark regression gate skipped (no baseline metrics)")
        return 0

    previous_metrics = _load_json(previous_path)
    previous_wall_ms = _to_int(previous_metrics, "wall_clock_ms")
    wall_clock_increase_pct = _pct_increase(previous_wall_ms, current_wall_ms)

    regressions: list[str] = []
    if current_wall_ms > args.max_wall_clock_ms:
        regressions.append(
            f"wall_clock_ms exceeded absolute ceiling: {current_wall_ms} > {args.max_wall_clock_ms}"
        )
    if previous_wall_ms > 0 and wall_clock_increase_pct > args.max_wall_clock_increase_pct:
        regressions.append(
            "wall_clock_ms increased by "
            f"{wall_clock_increase_pct:.2f}% ({current_wall_ms} vs {previous_wall_ms}) "
            f"beyond {args.max_wall_clock_increase_pct:.2f}%"
        )

    status = "fail" if regressions else "pass"
    report = {
        "suite": "detection_benchmark_regression_gate",
        "status": status,
        "thresholds": thresholds,
        "current": {"wall_clock_ms": current_wall_ms},
        "previous": {"wall_clock_ms": previous_wall_ms},
        "deltas": {
            "wall_clock_increase_pct": wall_clock_increase_pct,
            "wall_clock_delta_ms": current_wall_ms - previous_wall_ms,
        },
        "regressions": regressions,
    }
    _write_report(args.output, report)

    print("Detection benchmark regression snapshot:")
    print(f"- current wall_clock_ms: {current_wall_ms}")
    print(f"- previous wall_clock_ms: {previous_wall_ms}")
    print(f"- wall_clock increase pct: {wall_clock_increase_pct:.2f}")

    if regressions:
        print("\nDetection benchmark regression gate failed:")
        for regression in regressions:
            print(f"- {regression}")
        return 1

    print("\nDetection benchmark regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
