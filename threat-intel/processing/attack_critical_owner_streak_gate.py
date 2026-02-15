#!/usr/bin/env python3
"""Fail CI when owner-level P0 regressions persist across bundles."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_int_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, int] = {}
    for raw_key, raw_val in value.items():
        key = str(raw_key).strip()
        if not key:
            continue
        out[key] = _to_int(raw_val, 0)
    return out


def _load_history(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _owner_regression_map(row: dict[str, Any]) -> dict[str, int]:
    regressions = _to_int_map(row.get("owner_p0_regression_by_owner"))
    if regressions:
        return regressions

    # Backward-compatible fallback for old history schema.
    increases = _to_int_map(row.get("owner_p0_increase_by_owner"))
    return {owner: delta for owner, delta in increases.items() if delta > 0}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate owner-level P0 regression streak constraints")
    parser.add_argument("--history", required=True, help="Critical regression history NDJSON")
    parser.add_argument("--output", required=True, help="Owner streak gate report JSON")
    parser.add_argument("--window-size", type=int, default=10)
    parser.add_argument("--min-history-length", type=int, default=3)
    parser.add_argument("--max-consecutive-owner-regression", type=int, default=2)
    return parser


def main() -> int:
    args = _parser().parse_args()

    history_path = Path(args.history)
    output_path = Path(args.output)

    if args.window_size <= 0:
        raise SystemExit("window-size must be > 0")
    if args.min_history_length <= 0:
        raise SystemExit("min-history-length must be > 0")
    if args.max_consecutive_owner_regression < 0:
        raise SystemExit("max-consecutive-owner-regression must be >= 0")

    thresholds = {
        "window_size": args.window_size,
        "min_history_length": args.min_history_length,
        "max_consecutive_owner_regression": args.max_consecutive_owner_regression,
    }

    if not history_path.is_file():
        report = {
            "suite": "attack_critical_owner_streak_gate",
            "recorded_at_utc": _now_utc(),
            "status": "skipped_no_history",
            "thresholds": thresholds,
            "history_points": 0,
            "evaluated_points": 0,
            "owner_longest_streak": {},
            "owner_recent_streak": {},
            "current_regressing_owners": {},
            "failures": [],
        }
        _write_report(output_path, report)
        print("Critical owner-streak gate skipped (no history file)")
        return 0

    rows = _load_history(history_path)
    window = rows[-args.window_size :]

    if len(window) < args.min_history_length:
        report = {
            "suite": "attack_critical_owner_streak_gate",
            "recorded_at_utc": _now_utc(),
            "status": "skipped_insufficient_history",
            "thresholds": thresholds,
            "history_points": len(rows),
            "evaluated_points": len(window),
            "owner_longest_streak": {},
            "owner_recent_streak": {},
            "current_regressing_owners": {},
            "failures": [],
        }
        _write_report(output_path, report)
        print(
            "Critical owner-streak gate skipped "
            f"(need at least {args.min_history_length} points, got {len(window)})"
        )
        return 0

    owners: set[str] = set()
    parsed_window: list[dict[str, int]] = []
    for row in window:
        owner_map = _owner_regression_map(row)
        parsed_window.append(owner_map)
        owners.update(owner_map.keys())

    owner_longest_streak: dict[str, int] = {}
    owner_recent_streak: dict[str, int] = {}

    for owner in sorted(owners):
        longest = 0
        current = 0
        for row_map in parsed_window:
            if row_map.get(owner, 0) > 0:
                current += 1
                if current > longest:
                    longest = current
            else:
                current = 0
        owner_longest_streak[owner] = longest
        owner_recent_streak[owner] = current

    latest_owner_regressions = parsed_window[-1] if parsed_window else {}
    violating = {
        owner: streak
        for owner, streak in sorted(owner_longest_streak.items(), key=lambda item: (-item[1], item[0]))
        if streak > args.max_consecutive_owner_regression
    }

    failures: list[str] = []
    if violating:
        detail = "; ".join(f"{owner}(streak={streak})" for owner, streak in violating.items())
        failures.append(
            "owner-level P0 regression streak exceeded maximum "
            f"{args.max_consecutive_owner_regression}: {detail}"
        )

    report = {
        "suite": "attack_critical_owner_streak_gate",
        "recorded_at_utc": _now_utc(),
        "status": "fail" if failures else "pass",
        "thresholds": thresholds,
        "history_points": len(rows),
        "evaluated_points": len(window),
        "owner_longest_streak": owner_longest_streak,
        "owner_recent_streak": owner_recent_streak,
        "current_regressing_owners": {
            owner: count
            for owner, count in sorted(latest_owner_regressions.items(), key=lambda item: (-item[1], item[0]))
            if count > 0
        },
        "violating_owner_streaks": violating,
        "failures": failures,
    }
    _write_report(output_path, report)

    print("Critical owner-streak snapshot:")
    print(f"- history points: {len(rows)}")
    print(f"- evaluated points: {len(window)}")
    print(f"- owners tracked: {len(owners)}")

    if failures:
        print("\nCritical owner-streak gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nCritical owner-streak gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
