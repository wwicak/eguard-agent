#!/usr/bin/env python3
"""Gate adversary tournament metrics against absolute and regression budgets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _pct_increase(previous: float, current: float) -> float:
    if previous <= 0.0:
        return 0.0
    return ((current - previous) * 100.0) / previous


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate adversary tournament regression constraints")
    parser.add_argument("--current", required=True, help="Current adversary tournament metrics JSON")
    parser.add_argument("--previous", default="", help="Baseline adversary tournament metrics JSON")
    parser.add_argument("--output", default="", help="Optional gate report output path")

    parser.add_argument("--min-resilience-index", type=float, default=80.0)
    parser.add_argument("--min-adversary-final-score", type=float, default=92.0)
    parser.add_argument("--min-adversary-focus-score", type=float, default=95.0)
    parser.add_argument("--max-false-alarm-upper-bound", type=float, default=0.20)

    parser.add_argument("--max-detection-wall-clock-ms", type=float, default=60000.0)
    parser.add_argument("--max-runtime-tick-wall-clock-ms", type=float, default=180000.0)
    parser.add_argument("--max-replay-determinism-wall-clock-ms", type=float, default=60000.0)
    parser.add_argument("--max-rule-push-transfer-seconds", type=float, default=5.0)
    parser.add_argument("--max-rule-push-rollout-seconds", type=float, default=30.0)
    parser.add_argument("--max-ebpf-release-build-wall-ms", type=float, default=300000.0)

    parser.add_argument("--max-resilience-drop", type=float, default=4.0)
    parser.add_argument("--max-adversary-final-drop", type=float, default=2.0)
    parser.add_argument("--max-false-alarm-increase", type=float, default=0.02)
    parser.add_argument("--max-detection-wall-clock-increase-pct", type=float, default=25.0)
    parser.add_argument("--max-rule-push-rollout-increase-pct", type=float, default=25.0)
    parser.add_argument("--max-ebpf-release-build-increase-pct", type=float, default=25.0)
    parser.add_argument("--fail-on-regression", default="1")
    return parser


def _get_current_measurements(doc: dict[str, Any]) -> dict[str, float]:
    scores = doc.get("scores", {})
    if not isinstance(scores, dict):
        scores = {}

    measurements = doc.get("measurements", {})
    if not isinstance(measurements, dict):
        measurements = {}

    return {
        "resilience_index": _as_float(scores.get("resilience_index"), 0.0),
        "adversary_final_score": _as_float(scores.get("adversary_final_score"), 0.0),
        "adversary_focus_score": _as_float(scores.get("adversary_focus_score"), 0.0),
        "false_alarm_upper_bound": _as_float(measurements.get("false_alarm_upper_bound"), 1.0),
        "detection_wall_clock_ms": _as_float(
            measurements.get("detection_benchmark_wall_clock_ms"),
            0.0,
        ),
        "runtime_tick_wall_clock_ms": _as_float(
            measurements.get("runtime_tick_wall_clock_ms"),
            0.0,
        ),
        "replay_determinism_wall_clock_ms": _as_float(
            measurements.get("replay_determinism_wall_clock_ms"),
            0.0,
        ),
        "rule_push_transfer_seconds": _as_float(
            measurements.get("rule_push_transfer_seconds"),
            0.0,
        ),
        "rule_push_rollout_seconds": _as_float(
            measurements.get("rule_push_rollout_seconds"),
            0.0,
        ),
        "ebpf_release_build_wall_ms": _as_float(
            measurements.get("ebpf_release_build_wall_ms"),
            0.0,
        ),
    }


def _write_report(path_arg: str, report: dict[str, Any]) -> None:
    if not path_arg:
        return
    path = Path(path_arg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _build_parser().parse_args()

    current_path = Path(args.current)
    previous_path = Path(args.previous) if args.previous else None
    fail_on_regression = _parse_bool(args.fail_on_regression)

    if not current_path.is_file():
        report = {
            "suite": "adversary_tournament_gate",
            "status": "fail",
            "failures": [f"missing current metrics artifact: {current_path}"],
        }
        _write_report(args.output, report)
        print(f"missing current metrics artifact: {current_path}")
        return 1

    current_doc = _load_json(current_path)
    current = _get_current_measurements(current_doc)

    thresholds = {
        "min_resilience_index": args.min_resilience_index,
        "min_adversary_final_score": args.min_adversary_final_score,
        "min_adversary_focus_score": args.min_adversary_focus_score,
        "max_false_alarm_upper_bound": args.max_false_alarm_upper_bound,
        "max_detection_wall_clock_ms": args.max_detection_wall_clock_ms,
        "max_runtime_tick_wall_clock_ms": args.max_runtime_tick_wall_clock_ms,
        "max_replay_determinism_wall_clock_ms": args.max_replay_determinism_wall_clock_ms,
        "max_rule_push_transfer_seconds": args.max_rule_push_transfer_seconds,
        "max_rule_push_rollout_seconds": args.max_rule_push_rollout_seconds,
        "max_ebpf_release_build_wall_ms": args.max_ebpf_release_build_wall_ms,
        "max_resilience_drop": args.max_resilience_drop,
        "max_adversary_final_drop": args.max_adversary_final_drop,
        "max_false_alarm_increase": args.max_false_alarm_increase,
        "max_detection_wall_clock_increase_pct": args.max_detection_wall_clock_increase_pct,
        "max_rule_push_rollout_increase_pct": args.max_rule_push_rollout_increase_pct,
        "max_ebpf_release_build_increase_pct": args.max_ebpf_release_build_increase_pct,
        "fail_on_regression": fail_on_regression,
    }

    failures: list[str] = []
    if current["resilience_index"] < args.min_resilience_index:
        failures.append(
            "resilience_index below threshold: "
            f"{current['resilience_index']:.4f} < {args.min_resilience_index:.4f}"
        )
    if current["adversary_final_score"] < args.min_adversary_final_score:
        failures.append(
            "adversary_final_score below threshold: "
            f"{current['adversary_final_score']:.4f} < {args.min_adversary_final_score:.4f}"
        )
    if current["adversary_focus_score"] < args.min_adversary_focus_score:
        failures.append(
            "adversary_focus_score below threshold: "
            f"{current['adversary_focus_score']:.4f} < {args.min_adversary_focus_score:.4f}"
        )
    if current["false_alarm_upper_bound"] > args.max_false_alarm_upper_bound:
        failures.append(
            "false_alarm_upper_bound above threshold: "
            f"{current['false_alarm_upper_bound']:.6f} > {args.max_false_alarm_upper_bound:.6f}"
        )
    if current["detection_wall_clock_ms"] > args.max_detection_wall_clock_ms:
        failures.append(
            "detection_wall_clock_ms above threshold: "
            f"{current['detection_wall_clock_ms']:.2f} > {args.max_detection_wall_clock_ms:.2f}"
        )
    if current["runtime_tick_wall_clock_ms"] > args.max_runtime_tick_wall_clock_ms:
        failures.append(
            "runtime_tick_wall_clock_ms above threshold: "
            f"{current['runtime_tick_wall_clock_ms']:.2f} > {args.max_runtime_tick_wall_clock_ms:.2f}"
        )
    if current["replay_determinism_wall_clock_ms"] > args.max_replay_determinism_wall_clock_ms:
        failures.append(
            "replay_determinism_wall_clock_ms above threshold: "
            f"{current['replay_determinism_wall_clock_ms']:.2f} > {args.max_replay_determinism_wall_clock_ms:.2f}"
        )
    if current["rule_push_transfer_seconds"] > args.max_rule_push_transfer_seconds:
        failures.append(
            "rule_push_transfer_seconds above threshold: "
            f"{current['rule_push_transfer_seconds']:.6f} > {args.max_rule_push_transfer_seconds:.6f}"
        )
    if current["rule_push_rollout_seconds"] > args.max_rule_push_rollout_seconds:
        failures.append(
            "rule_push_rollout_seconds above threshold: "
            f"{current['rule_push_rollout_seconds']:.6f} > {args.max_rule_push_rollout_seconds:.6f}"
        )
    if current["ebpf_release_build_wall_ms"] > args.max_ebpf_release_build_wall_ms:
        failures.append(
            "ebpf_release_build_wall_ms above threshold: "
            f"{current['ebpf_release_build_wall_ms']:.2f} > {args.max_ebpf_release_build_wall_ms:.2f}"
        )

    previous: dict[str, float] | None = None
    deltas: dict[str, float] = {}
    history_status = "no_baseline"

    if previous_path is not None and previous_path.is_file():
        history_status = "baseline_available"
        previous_doc = _load_json(previous_path)
        previous = _get_current_measurements(previous_doc)

        deltas = {
            "resilience_drop": previous["resilience_index"] - current["resilience_index"],
            "adversary_final_drop": previous["adversary_final_score"] - current["adversary_final_score"],
            "false_alarm_increase": current["false_alarm_upper_bound"] - previous["false_alarm_upper_bound"],
            "detection_wall_clock_increase_pct": _pct_increase(
                previous["detection_wall_clock_ms"],
                current["detection_wall_clock_ms"],
            ),
            "rule_push_rollout_increase_pct": _pct_increase(
                previous["rule_push_rollout_seconds"],
                current["rule_push_rollout_seconds"],
            ),
            "ebpf_release_build_increase_pct": _pct_increase(
                previous["ebpf_release_build_wall_ms"],
                current["ebpf_release_build_wall_ms"],
            ),
        }

        if fail_on_regression:
            if deltas["resilience_drop"] > args.max_resilience_drop:
                failures.append(
                    "resilience index regressed beyond budget: "
                    f"drop={deltas['resilience_drop']:.4f} > {args.max_resilience_drop:.4f}"
                )
            if deltas["adversary_final_drop"] > args.max_adversary_final_drop:
                failures.append(
                    "adversary final score regressed beyond budget: "
                    f"drop={deltas['adversary_final_drop']:.4f} > {args.max_adversary_final_drop:.4f}"
                )
            if deltas["false_alarm_increase"] > args.max_false_alarm_increase:
                failures.append(
                    "false alarm upper bound regressed beyond budget: "
                    f"increase={deltas['false_alarm_increase']:.6f} > {args.max_false_alarm_increase:.6f}"
                )
            if deltas["detection_wall_clock_increase_pct"] > args.max_detection_wall_clock_increase_pct:
                failures.append(
                    "detection wall clock regressed beyond budget: "
                    f"increase={deltas['detection_wall_clock_increase_pct']:.2f}% > "
                    f"{args.max_detection_wall_clock_increase_pct:.2f}%"
                )
            if deltas["rule_push_rollout_increase_pct"] > args.max_rule_push_rollout_increase_pct:
                failures.append(
                    "rule-push rollout regressed beyond budget: "
                    f"increase={deltas['rule_push_rollout_increase_pct']:.2f}% > "
                    f"{args.max_rule_push_rollout_increase_pct:.2f}%"
                )
            if deltas["ebpf_release_build_increase_pct"] > args.max_ebpf_release_build_increase_pct:
                failures.append(
                    "ebpf release build wall clock regressed beyond budget: "
                    f"increase={deltas['ebpf_release_build_increase_pct']:.2f}% > "
                    f"{args.max_ebpf_release_build_increase_pct:.2f}%"
                )

    status = "fail" if failures else "pass"
    if not failures and history_status == "no_baseline":
        status = "pass_no_baseline"

    report = {
        "suite": "adversary_tournament_gate",
        "status": status,
        "history_status": history_status,
        "thresholds": thresholds,
        "current": current,
        "previous": previous,
        "deltas": deltas,
        "failures": failures,
    }
    _write_report(args.output, report)

    print("Adversary tournament gate snapshot:")
    print(f"- resilience_index: {current['resilience_index']:.4f}")
    print(f"- adversary_final_score: {current['adversary_final_score']:.4f}")
    print(f"- adversary_focus_score: {current['adversary_focus_score']:.4f}")
    print(f"- false_alarm_upper_bound: {current['false_alarm_upper_bound']:.6f}")

    if previous is not None:
        print(f"- previous resilience_index: {previous['resilience_index']:.4f}")
        print(f"- resilience_drop: {deltas['resilience_drop']:.4f}")

    if failures:
        print("\nAdversary tournament gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nAdversary tournament gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
