#!/usr/bin/env python3
"""Compute and enforce adversary-emulation quality score gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _extract_label_metrics(payload: dict[str, Any], label: str) -> dict[str, float] | None:
    if label == "focus":
        return {
            "precision": _as_float(payload.get("precision"), -1.0),
            "recall": _as_float(payload.get("recall"), -1.0),
            "false_alarm_upper_bound": _as_float(payload.get("false_alarm_upper_bound"), -1.0),
        }

    by_conf = payload.get("by_confidence_threshold")
    if not isinstance(by_conf, dict):
        return None

    class_metrics = by_conf.get(label)
    if not isinstance(class_metrics, dict):
        return None

    return {
        "precision": _as_float(class_metrics.get("precision"), -1.0),
        "recall": _as_float(class_metrics.get("recall"), -1.0),
        "false_alarm_upper_bound": _as_float(class_metrics.get("false_alarm_upper_bound"), -1.0),
    }


def _metric_score(
    metrics: dict[str, float] | None,
    *,
    target_precision: float,
    target_recall: float,
    target_far_max: float,
    weight_precision: float,
    weight_recall: float,
    weight_far: float,
) -> float:
    if metrics is None:
        return 0.0

    precision = metrics.get("precision", -1.0)
    recall = metrics.get("recall", -1.0)
    false_alarm_upper = metrics.get("false_alarm_upper_bound", -1.0)

    if precision < 0.0 or recall < 0.0 or false_alarm_upper < 0.0:
        return 0.0

    if target_precision <= 0.0:
        precision_component = 1.0
    else:
        precision_component = _clamp(precision / target_precision, 0.0, 1.0)

    if target_recall <= 0.0:
        recall_component = 1.0
    else:
        recall_component = _clamp(recall / target_recall, 0.0, 1.0)

    if target_far_max <= 0.0:
        false_alarm_component = 1.0 if false_alarm_upper <= 0.0 else 0.0
    else:
        false_alarm_component = _clamp((target_far_max - false_alarm_upper) / target_far_max, 0.0, 1.0)

    weight_total = weight_precision + weight_recall + weight_far
    if weight_total <= 0.0:
        return 0.0

    weighted = (
        precision_component * weight_precision
        + recall_component * weight_recall
        + false_alarm_component * weight_far
    )
    return 100.0 * (weighted / weight_total)


def _portfolio_score(label_scores: dict[str, float], weights: dict[str, float]) -> float:
    total_weight = sum(weights.values())
    if total_weight <= 0.0:
        return 0.0

    weighted_sum = 0.0
    for label, weight in weights.items():
        weighted_sum += label_scores.get(label, 0.0) * weight

    return weighted_sum / total_weight


def _compute_scores(
    *,
    payload: dict[str, Any],
    scenario_count: int,
    malicious_events: int,
    min_scenarios: int,
    min_malicious_events: int,
    target_precision: float,
    target_recall: float,
    target_far_max: float,
    weight_precision: float,
    weight_recall: float,
    weight_far: float,
    label_weights: dict[str, float],
) -> dict[str, Any]:
    label_scores: dict[str, float] = {}
    for label in ("focus", "definite", "very_high", "high"):
        label_scores[label] = _metric_score(
            _extract_label_metrics(payload, label),
            target_precision=target_precision,
            target_recall=target_recall,
            target_far_max=target_far_max,
            weight_precision=weight_precision,
            weight_recall=weight_recall,
            weight_far=weight_far,
        )

    portfolio_score = _portfolio_score(label_scores, label_weights)

    scenario_coverage = 1.0
    if min_scenarios > 0:
        scenario_coverage = _clamp(scenario_count / float(min_scenarios), 0.0, 1.0)

    malicious_coverage = 1.0
    if min_malicious_events > 0:
        malicious_coverage = _clamp(malicious_events / float(min_malicious_events), 0.0, 1.0)

    coverage_multiplier = min(scenario_coverage, malicious_coverage)
    final_score = portfolio_score * coverage_multiplier

    return {
        "label_scores": label_scores,
        "portfolio_score": portfolio_score,
        "coverage_multiplier": coverage_multiplier,
        "scenario_coverage": scenario_coverage,
        "malicious_coverage": malicious_coverage,
        "final_score": final_score,
    }


def _parse_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []

    entries: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Enforce adversary-emulation quality score gates")
    parser.add_argument("--metrics", required=True, help="detection-quality metrics JSON")
    parser.add_argument("--trend-path", default="", help="per-confidence trend NDJSON path")
    parser.add_argument("--output", required=True, help="score gate report output path")

    parser.add_argument("--target-precision", type=float, default=0.99)
    parser.add_argument("--target-recall", type=float, default=0.99)
    parser.add_argument("--target-far-max", type=float, default=0.20)

    parser.add_argument("--weight-precision", type=float, default=0.40)
    parser.add_argument("--weight-recall", type=float, default=0.40)
    parser.add_argument("--weight-far", type=float, default=0.20)

    parser.add_argument("--focus-weight", type=float, default=0.40)
    parser.add_argument("--definite-weight", type=float, default=0.25)
    parser.add_argument("--very-high-weight", type=float, default=0.20)
    parser.add_argument("--high-weight", type=float, default=0.15)

    parser.add_argument("--min-scenarios", type=int, default=12)
    parser.add_argument("--min-malicious-events", type=int, default=5)
    parser.add_argument("--min-focus-score", type=float, default=95.0)
    parser.add_argument("--min-final-score", type=float, default=92.0)
    parser.add_argument("--max-score-drop", type=float, default=2.0)
    parser.add_argument("--fail-on-score-drop", default="1")
    return parser


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _build_parser().parse_args()

    metrics_path = Path(args.metrics)
    output_path = Path(args.output)
    trend_path = Path(args.trend_path) if args.trend_path else None
    fail_on_score_drop = _parse_bool(args.fail_on_score_drop)

    if not metrics_path.is_file():
        report = {
            "suite": "adversary_emulation_score_gate",
            "status": "fail",
            "failures": [f"missing metrics artifact: {metrics_path}"],
        }
        _write_report(output_path, report)
        print(f"missing metrics artifact: {metrics_path}")
        return 1

    metrics_doc = json.loads(metrics_path.read_text(encoding="utf-8"))
    measured = metrics_doc.get("measured", {})
    if not isinstance(measured, dict):
        measured = {}
    corpus = metrics_doc.get("corpus", {})
    if not isinstance(corpus, dict):
        corpus = {}

    scenario_count = _as_int(corpus.get("scenario_count"), 0)
    malicious_events = _as_int(corpus.get("malicious_events"), 0)

    label_weights = {
        "focus": args.focus_weight,
        "definite": args.definite_weight,
        "very_high": args.very_high_weight,
        "high": args.high_weight,
    }

    current_scores = _compute_scores(
        payload=measured,
        scenario_count=scenario_count,
        malicious_events=malicious_events,
        min_scenarios=args.min_scenarios,
        min_malicious_events=args.min_malicious_events,
        target_precision=args.target_precision,
        target_recall=args.target_recall,
        target_far_max=args.target_far_max,
        weight_precision=args.weight_precision,
        weight_recall=args.weight_recall,
        weight_far=args.weight_far,
        label_weights=label_weights,
    )

    previous_scores: dict[str, Any] | None = None
    history_status = "no_trend"
    if trend_path is not None:
        entries = _parse_ndjson(trend_path)
        if len(entries) >= 2:
            history_status = "history_available"
            previous = entries[-2]
            prev_corpus = previous.get("corpus", {})
            if not isinstance(prev_corpus, dict):
                prev_corpus = {}
            previous_scores = _compute_scores(
                payload=previous,
                scenario_count=_as_int(prev_corpus.get("scenario_count"), 0),
                malicious_events=_as_int(prev_corpus.get("malicious_events"), 0),
                min_scenarios=args.min_scenarios,
                min_malicious_events=args.min_malicious_events,
                target_precision=args.target_precision,
                target_recall=args.target_recall,
                target_far_max=args.target_far_max,
                weight_precision=args.weight_precision,
                weight_recall=args.weight_recall,
                weight_far=args.weight_far,
                label_weights=label_weights,
            )
        else:
            history_status = "insufficient_history"

    score_drop = 0.0
    if previous_scores is not None:
        score_drop = previous_scores["final_score"] - current_scores["final_score"]

    failures: list[str] = []
    if scenario_count < args.min_scenarios:
        failures.append(
            f"scenario_count below threshold: {scenario_count} < {args.min_scenarios}"
        )
    if malicious_events < args.min_malicious_events:
        failures.append(
            "malicious_events below threshold: "
            f"{malicious_events} < {args.min_malicious_events}"
        )

    focus_score = current_scores["label_scores"].get("focus", 0.0)
    final_score = current_scores["final_score"]

    if focus_score < args.min_focus_score:
        failures.append(
            f"focus_score below threshold: {focus_score:.4f} < {args.min_focus_score:.4f}"
        )
    if final_score < args.min_final_score:
        failures.append(
            f"final_score below threshold: {final_score:.4f} < {args.min_final_score:.4f}"
        )

    if previous_scores is not None and score_drop > args.max_score_drop and fail_on_score_drop:
        failures.append(
            "final_score regressed beyond allowed drop: "
            f"drop={score_drop:.4f} > max_drop={args.max_score_drop:.4f}"
        )

    report = {
        "suite": "adversary_emulation_score_gate",
        "status": "fail" if failures else "pass",
        "history_status": history_status,
        "thresholds": {
            "target_precision": args.target_precision,
            "target_recall": args.target_recall,
            "target_far_max": args.target_far_max,
            "weight_precision": args.weight_precision,
            "weight_recall": args.weight_recall,
            "weight_far": args.weight_far,
            "focus_weight": args.focus_weight,
            "definite_weight": args.definite_weight,
            "very_high_weight": args.very_high_weight,
            "high_weight": args.high_weight,
            "min_scenarios": args.min_scenarios,
            "min_malicious_events": args.min_malicious_events,
            "min_focus_score": args.min_focus_score,
            "min_final_score": args.min_final_score,
            "max_score_drop": args.max_score_drop,
            "fail_on_score_drop": fail_on_score_drop,
        },
        "corpus": {
            "scenario_count": scenario_count,
            "malicious_events": malicious_events,
        },
        "scores": {
            "labels": current_scores["label_scores"],
            "portfolio_score": current_scores["portfolio_score"],
            "coverage_multiplier": current_scores["coverage_multiplier"],
            "scenario_coverage": current_scores["scenario_coverage"],
            "malicious_coverage": current_scores["malicious_coverage"],
            "focus_score": focus_score,
            "final_score": final_score,
            "previous_final_score": previous_scores["final_score"] if previous_scores else None,
            "final_score_drop": score_drop if previous_scores else None,
        },
        "failures": failures,
    }

    _write_report(output_path, report)

    print("Adversary-emulation score snapshot:")
    print(f"- focus score: {focus_score:.4f}")
    print(f"- final score: {final_score:.4f}")
    if previous_scores is not None:
        print(f"- previous final score: {previous_scores['final_score']:.4f}")
        print(f"- final score drop: {score_drop:.4f}")
    else:
        print(f"- history status: {history_status}")

    if failures:
        print("\nAdversary-emulation score gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nAdversary-emulation score gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
