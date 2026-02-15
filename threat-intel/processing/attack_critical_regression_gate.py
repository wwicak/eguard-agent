#!/usr/bin/env python3
"""Fail CI when critical ATT&CK floor coverage regresses too far."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
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


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _uncovered_by_priority(report: dict[str, Any]) -> dict[str, int]:
    rows = report.get("critical_techniques", [])
    if not isinstance(rows, list):
        return {}

    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("covered") is True:
            continue
        priority = str(row.get("priority", "P99")).strip().upper() or "P99"
        counts[priority] = counts.get(priority, 0) + 1
    return counts


def _p0_uncovered_by_owner(report: dict[str, Any]) -> dict[str, int]:
    rows = report.get("critical_techniques", [])
    if not isinstance(rows, list):
        return {}

    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("covered") is True:
            continue
        priority = str(row.get("priority", "P99")).strip().upper() or "P99"
        if priority != "P0":
            continue
        owner = str(row.get("owner", "unassigned")).strip() or "unassigned"
        counts[owner] = counts.get(owner, 0) + 1
    return counts


def _extract_metrics(
    report: dict[str, Any],
) -> tuple[dict[str, Any], list[str], dict[str, int], dict[str, int]]:
    measured = report.get("measured")
    if not isinstance(measured, dict):
        measured = report

    uncovered_priority = _uncovered_by_priority(report)
    p0_uncovered_owner = _p0_uncovered_by_owner(report)

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
        "p0_uncovered_count": _to_int(uncovered_priority.get("P0"), 0),
        "p0_uncovered_owner_count": len(p0_uncovered_owner),
    }
    return metrics, missing_required, uncovered_priority, p0_uncovered_owner


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate critical ATT&CK floor regression constraints")
    parser.add_argument("--current", required=True, help="Current critical ATT&CK gate report JSON")
    parser.add_argument("--previous", default="", help="Previous critical ATT&CK gate report JSON")
    parser.add_argument("--output", default="", help="Optional regression report output JSON")

    parser.add_argument("--max-covered-count-drop", type=int, default=2)
    parser.add_argument("--max-covered-ratio-drop", type=float, default=0.08)
    parser.add_argument("--max-missing-count-increase", type=int, default=2)
    parser.add_argument("--max-missing-required-increase", type=int, default=0)
    parser.add_argument("--max-p0-uncovered-increase", type=int, default=0)
    parser.add_argument("--max-owner-p0-uncovered-increase", type=int, default=1)
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
    (
        current_metrics,
        current_missing_required,
        current_uncovered_priority,
        current_p0_uncovered_by_owner,
    ) = _extract_metrics(current_report)

    thresholds = {
        "max_covered_count_drop": args.max_covered_count_drop,
        "max_covered_ratio_drop": args.max_covered_ratio_drop,
        "max_missing_count_increase": args.max_missing_count_increase,
        "max_missing_required_increase": args.max_missing_required_increase,
        "max_p0_uncovered_increase": args.max_p0_uncovered_increase,
        "max_owner_p0_uncovered_increase": args.max_owner_p0_uncovered_increase,
    }

    if previous_path is None or not previous_path.is_file():
        report = {
            "suite": "attack_critical_regression_gate",
            "recorded_at_utc": _now_utc(),
            "status": "skipped_no_baseline",
            "current": current_metrics,
            "current_uncovered_by_priority": current_uncovered_priority,
            "current_p0_uncovered_by_owner": current_p0_uncovered_by_owner,
            "previous": {},
            "previous_uncovered_by_priority": {},
            "previous_p0_uncovered_by_owner": {},
            "thresholds": thresholds,
            "deltas": {},
            "regressions": [],
        }
        _write_report(args.output, report)
        print("Critical ATT&CK regression gate skipped (no baseline report)")
        return 0

    previous_report = _load_json(previous_path)
    (
        previous_metrics,
        previous_missing_required,
        previous_uncovered_priority,
        previous_p0_uncovered_by_owner,
    ) = _extract_metrics(previous_report)

    covered_count_delta = current_metrics["covered_count"] - previous_metrics["covered_count"]
    covered_ratio_delta = current_metrics["covered_ratio"] - previous_metrics["covered_ratio"]
    missing_count_delta = current_metrics["missing_count"] - previous_metrics["missing_count"]
    missing_required_delta = (
        current_metrics["missing_required_count"] - previous_metrics["missing_required_count"]
    )
    p0_uncovered_delta = current_metrics["p0_uncovered_count"] - previous_metrics["p0_uncovered_count"]

    covered_count_drop = max(-covered_count_delta, 0)
    covered_ratio_drop = max(-covered_ratio_delta, 0.0)
    missing_count_increase = max(missing_count_delta, 0)
    missing_required_increase = max(missing_required_delta, 0)
    p0_uncovered_increase = max(p0_uncovered_delta, 0)

    all_p0_owners = sorted(
        set(current_p0_uncovered_by_owner.keys()) | set(previous_p0_uncovered_by_owner.keys())
    )
    owner_p0_delta = {
        owner: current_p0_uncovered_by_owner.get(owner, 0) - previous_p0_uncovered_by_owner.get(owner, 0)
        for owner in all_p0_owners
        if current_p0_uncovered_by_owner.get(owner, 0)
        != previous_p0_uncovered_by_owner.get(owner, 0)
    }
    owner_p0_increase = {
        owner: delta for owner, delta in sorted(owner_p0_delta.items(), key=lambda item: (-item[1], item[0])) if delta > 0
    }

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
    if p0_uncovered_increase > args.max_p0_uncovered_increase:
        regressions.append(
            "p0_uncovered_count increased by "
            f"{p0_uncovered_increase} ({current_metrics['p0_uncovered_count']} vs {previous_metrics['p0_uncovered_count']}) "
            f"beyond {args.max_p0_uncovered_increase}"
        )

    owner_p0_regressions = {
        owner: increase
        for owner, increase in owner_p0_increase.items()
        if increase > args.max_owner_p0_uncovered_increase
    }
    if owner_p0_regressions:
        details = "; ".join(
            f"{owner}(+{increase})" for owner, increase in owner_p0_regressions.items()
        )
        regressions.append(
            "owner-level P0 uncovered regressions beyond threshold "
            f"{args.max_owner_p0_uncovered_increase}: {details}"
        )

    status = "fail" if regressions else "pass"
    report = {
        "suite": "attack_critical_regression_gate",
        "recorded_at_utc": _now_utc(),
        "status": status,
        "current": current_metrics,
        "current_uncovered_by_priority": current_uncovered_priority,
        "current_p0_uncovered_by_owner": current_p0_uncovered_by_owner,
        "previous": previous_metrics,
        "previous_uncovered_by_priority": previous_uncovered_priority,
        "previous_p0_uncovered_by_owner": previous_p0_uncovered_by_owner,
        "thresholds": thresholds,
        "deltas": {
            "covered_count_delta": covered_count_delta,
            "covered_ratio_delta": round(covered_ratio_delta, 4),
            "missing_count_delta": missing_count_delta,
            "missing_required_count_delta": missing_required_delta,
            "p0_uncovered_count_delta": p0_uncovered_delta,
            "owner_p0_delta_by_owner": owner_p0_delta,
            "owner_p0_increase_by_owner": owner_p0_increase,
            "owner_p0_regression_by_owner": owner_p0_regressions,
            "owner_p0_regression_count": len(owner_p0_regressions),
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
    print(
        f"- p0_uncovered_count: current={current_metrics['p0_uncovered_count']} previous={previous_metrics['p0_uncovered_count']}"
    )
    print(
        "- p0_uncovered_owner_count: "
        f"current={current_metrics['p0_uncovered_owner_count']} previous={previous_metrics['p0_uncovered_owner_count']}"
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
