#!/usr/bin/env python3
"""Track and gate ATT&CK coverage gap burn-down over time."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def _slug(raw: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", raw.strip().lower())
    return cleaned.strip("_")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _measured(report: dict[str, Any]) -> dict[str, Any]:
    measured = report.get("measured")
    if isinstance(measured, dict):
        return measured
    return report


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _read_observed_tactics(report: dict[str, Any]) -> set[str]:
    observed = report.get("observed_tactics")
    if not isinstance(observed, list):
        return set()
    return {_slug(str(tactic)) for tactic in observed if _slug(str(tactic))}


def _read_required_tactics(args: argparse.Namespace, current_report: dict[str, Any]) -> list[str]:
    if args.require_tactic:
        values = [_slug(item) for item in args.require_tactic if _slug(item)]
    else:
        thresholds = current_report.get("thresholds", {})
        required = thresholds.get("required_tactics", [])
        if isinstance(required, list):
            values = [_slug(item) for item in required if _slug(str(item))]
        else:
            values = []

    deduped: list[str] = []
    seen: set[str] = set()
    for tactic in values:
        if tactic in seen:
            continue
        seen.add(tactic)
        deduped.append(tactic)
    return deduped


def _goal_value(cli_value: int, fallback_value: Any) -> int:
    if cli_value > 0:
        return cli_value
    return max(_to_int(fallback_value, 0), 0)


def _gap(goal: int, actual: int) -> int:
    return max(goal - actual, 0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate ATT&CK gap burn-down from coverage reports")
    parser.add_argument("--current", required=True, help="Current attack coverage report JSON")
    parser.add_argument("--previous", default="", help="Previous attack coverage report JSON")
    parser.add_argument("--output", required=True, help="Gap burn-down report output JSON")

    parser.add_argument("--goal-techniques", type=int, default=0)
    parser.add_argument("--goal-tactics", type=int, default=0)
    parser.add_argument(
        "--require-tactic",
        action="append",
        default=[],
        help="Required ATT&CK tactic slug (repeatable), defaults to coverage gate required_tactics",
    )

    parser.add_argument("--max-technique-gap-increase", type=int, default=0)
    parser.add_argument("--max-tactic-gap-increase", type=int, default=0)
    parser.add_argument("--max-new-missing-required-tactics", type=int, default=0)
    parser.add_argument("--require-gap-reduction-if-positive", action="store_true")
    return parser


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _parser().parse_args()

    current_path = Path(args.current)
    output_path = Path(args.output)
    previous_path = Path(args.previous) if args.previous else None

    if not current_path.is_file():
        report = {
            "suite": "attack_gap_burndown_gate",
            "status": "fail",
            "failures": [f"missing current attack coverage report: {current_path}"],
        }
        _write_report(output_path, report)
        print(report["failures"][0])
        return 1

    current_report = _load_json(current_path)
    current_measured = _measured(current_report)
    thresholds = current_report.get("thresholds", {})
    if not isinstance(thresholds, dict):
        thresholds = {}

    goal_techniques = _goal_value(args.goal_techniques, thresholds.get("min_techniques"))
    goal_tactics = _goal_value(args.goal_tactics, thresholds.get("min_tactics"))
    required_tactics = _read_required_tactics(args, current_report)

    current_total_techniques = _to_int(current_measured.get("total_techniques"), 0)
    current_total_tactics = _to_int(current_measured.get("total_tactics"), 0)
    current_technique_gap = _gap(goal_techniques, current_total_techniques)
    current_tactic_gap = _gap(goal_tactics, current_total_tactics)

    current_observed_tactics = _read_observed_tactics(current_report)
    current_missing_required = sorted(
        [tactic for tactic in required_tactics if tactic not in current_observed_tactics]
    )

    previous_available = previous_path is not None and previous_path.is_file()
    previous_total_techniques = 0
    previous_total_tactics = 0
    previous_technique_gap = 0
    previous_tactic_gap = 0
    previous_missing_required: list[str] = []

    if previous_available:
        assert previous_path is not None
        previous_report = _load_json(previous_path)
        previous_measured = _measured(previous_report)

        previous_total_techniques = _to_int(previous_measured.get("total_techniques"), 0)
        previous_total_tactics = _to_int(previous_measured.get("total_tactics"), 0)
        previous_technique_gap = _gap(goal_techniques, previous_total_techniques)
        previous_tactic_gap = _gap(goal_tactics, previous_total_tactics)

        previous_observed_tactics = _read_observed_tactics(previous_report)
        previous_missing_required = sorted(
            [tactic for tactic in required_tactics if tactic not in previous_observed_tactics]
        )

    technique_gap_delta = current_technique_gap - previous_technique_gap
    tactic_gap_delta = current_tactic_gap - previous_tactic_gap

    new_missing_required = sorted(set(current_missing_required) - set(previous_missing_required))
    resolved_required = sorted(set(previous_missing_required) - set(current_missing_required))

    failures: list[str] = []
    if previous_available:
        if technique_gap_delta > args.max_technique_gap_increase:
            failures.append(
                "technique gap increased beyond allowed delta: "
                f"delta={technique_gap_delta} > {args.max_technique_gap_increase}"
            )
        if tactic_gap_delta > args.max_tactic_gap_increase:
            failures.append(
                "tactic gap increased beyond allowed delta: "
                f"delta={tactic_gap_delta} > {args.max_tactic_gap_increase}"
            )
        if len(new_missing_required) > args.max_new_missing_required_tactics:
            failures.append(
                "new missing required tactics exceeded allowed delta: "
                f"{len(new_missing_required)} > {args.max_new_missing_required_tactics} "
                f"({', '.join(new_missing_required)})"
            )

        if args.require_gap_reduction_if_positive:
            if previous_technique_gap > 0 and current_technique_gap >= previous_technique_gap:
                failures.append(
                    "positive technique gap did not burn down: "
                    f"current={current_technique_gap} previous={previous_technique_gap}"
                )
            if previous_tactic_gap > 0 and current_tactic_gap >= previous_tactic_gap:
                failures.append(
                    "positive tactic gap did not burn down: "
                    f"current={current_tactic_gap} previous={previous_tactic_gap}"
                )

    report = {
        "suite": "attack_gap_burndown_gate",
        "status": "fail" if failures else "pass",
        "baseline_status": "available" if previous_available else "missing",
        "goals": {
            "goal_techniques": goal_techniques,
            "goal_tactics": goal_tactics,
            "required_tactics": required_tactics,
        },
        "current": {
            "total_techniques": current_total_techniques,
            "total_tactics": current_total_tactics,
            "technique_gap": current_technique_gap,
            "tactic_gap": current_tactic_gap,
            "missing_required_tactics": current_missing_required,
        },
        "previous": {
            "total_techniques": previous_total_techniques,
            "total_tactics": previous_total_tactics,
            "technique_gap": previous_technique_gap,
            "tactic_gap": previous_tactic_gap,
            "missing_required_tactics": previous_missing_required,
        },
        "deltas": {
            "technique_gap_delta": technique_gap_delta if previous_available else None,
            "tactic_gap_delta": tactic_gap_delta if previous_available else None,
            "new_missing_required_tactics": new_missing_required if previous_available else [],
            "resolved_required_tactics": resolved_required if previous_available else [],
        },
        "burn_down": {
            "technique_gap_reduced_by": (
                max(previous_technique_gap - current_technique_gap, 0) if previous_available else None
            ),
            "tactic_gap_reduced_by": (
                max(previous_tactic_gap - current_tactic_gap, 0) if previous_available else None
            ),
        },
        "thresholds": {
            "max_technique_gap_increase": args.max_technique_gap_increase,
            "max_tactic_gap_increase": args.max_tactic_gap_increase,
            "max_new_missing_required_tactics": args.max_new_missing_required_tactics,
            "require_gap_reduction_if_positive": args.require_gap_reduction_if_positive,
        },
        "failures": failures,
    }

    _write_report(output_path, report)

    print("ATT&CK gap burn-down snapshot:")
    print(f"- goal techniques: {goal_techniques}")
    print(f"- goal tactics: {goal_tactics}")
    print(f"- current technique gap: {current_technique_gap}")
    print(f"- current tactic gap: {current_tactic_gap}")
    print(f"- current missing required tactics: {len(current_missing_required)}")

    if previous_available:
        print(f"- technique gap delta: {technique_gap_delta}")
        print(f"- tactic gap delta: {tactic_gap_delta}")
        if new_missing_required:
            print("- new missing required tactics: " + ", ".join(new_missing_required))
    else:
        print("- baseline status: missing (delta checks skipped)")

    if failures:
        print("\nATT&CK gap burn-down gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nATT&CK gap burn-down gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
