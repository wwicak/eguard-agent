#!/usr/bin/env python3
"""Append critical ATT&CK regression snapshots to bounded history."""

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


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Update critical ATT&CK regression history artifact")
    parser.add_argument("--current-report", required=True, help="Current critical regression report JSON")
    parser.add_argument("--previous-history", default="", help="Previous history NDJSON (optional)")
    parser.add_argument("--output-history", required=True, help="Output history NDJSON")
    parser.add_argument("--output-summary", default="", help="Optional output summary JSON")
    parser.add_argument("--max-entries", type=int, default=180, help="Maximum retained entries")
    return parser


def _read_previous_history(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []

    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _write_history(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _write_summary(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _build_snapshot(current_report: dict[str, Any]) -> dict[str, Any]:
    current = current_report.get("current", {})
    deltas = current_report.get("deltas", {})
    if not isinstance(current, dict):
        current = {}
    if not isinstance(deltas, dict):
        deltas = {}

    owner_p0_increase_by_owner = _to_int_map(deltas.get("owner_p0_increase_by_owner"))
    owner_p0_regression_by_owner = _to_int_map(deltas.get("owner_p0_regression_by_owner"))

    return {
        "recorded_at_utc": str(current_report.get("recorded_at_utc") or _now_utc()),
        "status": str(current_report.get("status", "unknown")),
        "covered_count": _to_int(current.get("covered_count"), 0),
        "covered_ratio": round(_to_float(current.get("covered_ratio"), 0.0), 4),
        "missing_count": _to_int(current.get("missing_count"), 0),
        "missing_required_count": _to_int(current.get("missing_required_count"), 0),
        "p0_uncovered_count": _to_int(current.get("p0_uncovered_count"), 0),
        "covered_count_delta": _to_int(deltas.get("covered_count_delta"), 0),
        "covered_ratio_delta": round(_to_float(deltas.get("covered_ratio_delta"), 0.0), 4),
        "missing_count_delta": _to_int(deltas.get("missing_count_delta"), 0),
        "missing_required_count_delta": _to_int(deltas.get("missing_required_count_delta"), 0),
        "p0_uncovered_count_delta": _to_int(deltas.get("p0_uncovered_count_delta"), 0),
        "owner_p0_increase_by_owner": owner_p0_increase_by_owner,
        "owner_p0_regression_count": _to_int(deltas.get("owner_p0_regression_count"), 0),
        "owner_p0_regression_by_owner": owner_p0_regression_by_owner,
    }


def _consecutive_passes(rows: list[dict[str, Any]]) -> int:
    streak = 0
    for row in reversed(rows):
        if str(row.get("status", "")).lower() == "pass":
            streak += 1
            continue
        break
    return streak


def _owner_regression_totals(rows: list[dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for row in rows:
        reg_map = _to_int_map(row.get("owner_p0_regression_by_owner"))
        for owner, count in reg_map.items():
            totals[owner] = totals.get(owner, 0) + max(count, 0)
    return {
        owner: count
        for owner, count in sorted(totals.items(), key=lambda item: (-item[1], item[0]))
    }


def main() -> int:
    args = _parser().parse_args()

    current_path = Path(args.current_report)
    previous_history_path = Path(args.previous_history) if args.previous_history else None
    output_history_path = Path(args.output_history)
    output_summary_path = Path(args.output_summary) if args.output_summary else None

    if not current_path.is_file():
        raise SystemExit(f"current regression report not found: {current_path}")
    if args.max_entries <= 0:
        raise SystemExit("max-entries must be > 0")

    current_report = json.loads(current_path.read_text(encoding="utf-8"))
    if not isinstance(current_report, dict):
        raise SystemExit("current regression report must be a JSON object")

    history = _read_previous_history(previous_history_path)
    snapshot = _build_snapshot(current_report)

    if history and str(history[-1].get("recorded_at_utc", "")) == snapshot["recorded_at_utc"]:
        history[-1] = snapshot
    else:
        history.append(snapshot)

    if len(history) > args.max_entries:
        history = history[-args.max_entries :]

    _write_history(output_history_path, history)

    window = history[-10:]
    failure_count = sum(1 for row in window if str(row.get("status", "")).lower() == "fail")
    pass_count = sum(1 for row in window if str(row.get("status", "")).lower() == "pass")
    summary = {
        "suite": "attack_critical_regression_history",
        "recorded_at_utc": _now_utc(),
        "history_points": len(history),
        "window_size": len(window),
        "window_failures": failure_count,
        "window_passes": pass_count,
        "consecutive_passes": _consecutive_passes(history),
        "window_owner_p0_regression_totals": _owner_regression_totals(window),
        "latest": snapshot,
    }
    if output_summary_path is not None:
        _write_summary(output_summary_path, summary)

    print(f"wrote critical ATT&CK regression history to {output_history_path}")
    if output_summary_path is not None:
        print(f"wrote critical ATT&CK regression history summary to {output_summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
