#!/usr/bin/env python3
"""Evaluate signature-ML model offline with temporal holdout and drift checks."""

from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso_utc(raw: datetime) -> str:
    return raw.isoformat().replace("+00:00", "Z")


def _parse_ts(raw: Any) -> datetime | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sigmoid(raw: float) -> float:
    return 1.0 / (1.0 + math.exp(-raw))


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"missing feature snapshot dataset: {path}")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = line.strip()
        if not payload:
            continue
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _load_json_optional(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    return payload


def _load_ndjson_optional(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = line.strip()
        if not payload:
            continue
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _extract_model(
    model_payload: dict[str, Any] | None,
) -> tuple[dict[str, float], float, dict[str, float]]:
    if not model_payload:
        return {}, 0.0, {}
    weights_raw = model_payload.get("weights", {})
    if not isinstance(weights_raw, dict):
        return {}, 0.0, {}
    weights = {str(name): _as_float(value, 0.0) for name, value in weights_raw.items()}
    scales_raw = model_payload.get("feature_scales", {})
    scales = (
        {str(name): max(_as_float(value, 1.0), 1.0) for name, value in scales_raw.items()}
        if isinstance(scales_raw, dict)
        else {}
    )
    bias = _as_float(model_payload.get("bias"), 0.0)
    return weights, bias, scales


def _score_row(
    row: dict[str, Any],
    model_weights: dict[str, float],
    bias: float,
    feature_scales: dict[str, float],
) -> float:
    if model_weights:
        linear = bias
        for feature, weight in model_weights.items():
            scale = max(_as_float(feature_scales.get(feature), 1.0), 1.0)
            linear += weight * (_as_float(row.get(feature), 0.0) / scale)
        return _clamp(_sigmoid(linear), 0.001, 0.999)
    return _clamp(_as_float(row.get("model_score"), 0.0), 0.001, 0.999)


def _binary_metrics(labels: list[int], scores: list[float], threshold: float) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores):
        predicted = 1 if score >= threshold else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _candidate_thresholds(scores: list[float]) -> list[float]:
    if not scores:
        return [0.5]
    unique = sorted(set(round(score, 6) for score in scores))
    candidates = [0.0, *unique, 1.0]
    return sorted(set(candidates))


def _select_operating_threshold(
    labels: list[int],
    scores: list[float],
    min_precision: float,
) -> tuple[float, dict[str, Any], str]:
    best_threshold = 0.5
    best_metrics = _binary_metrics(labels, scores, best_threshold)
    best_key = (
        best_metrics["recall"],
        best_metrics["f1"],
        best_metrics["precision"],
        -abs(best_threshold - 0.5),
    )
    precision_floor_candidates: list[tuple[float, dict[str, Any]]] = []

    for threshold in _candidate_thresholds(scores):
        metrics = _binary_metrics(labels, scores, threshold)
        if metrics["precision"] >= min_precision:
            precision_floor_candidates.append((threshold, metrics))
        key = (
            metrics["recall"],
            metrics["f1"],
            metrics["precision"],
            -abs(threshold - 0.5),
        )
        if key > best_key:
            best_threshold = threshold
            best_metrics = metrics
            best_key = key

    if precision_floor_candidates:
        floor_best_threshold = precision_floor_candidates[0][0]
        floor_best_metrics = precision_floor_candidates[0][1]
        floor_best_key = (
            floor_best_metrics["recall"],
            floor_best_metrics["f1"],
            floor_best_metrics["precision"],
            -abs(floor_best_threshold - 0.5),
        )
        for threshold, metrics in precision_floor_candidates[1:]:
            key = (
                metrics["recall"],
                metrics["f1"],
                metrics["precision"],
                -abs(threshold - 0.5),
            )
            if key > floor_best_key:
                floor_best_threshold = threshold
                floor_best_metrics = metrics
                floor_best_key = key
        return floor_best_threshold, floor_best_metrics, "max_recall_with_precision_floor"

    return best_threshold, best_metrics, "max_recall_fallback"


def _roc_auc(labels: list[int], scores: list[float]) -> float:
    n = len(labels)
    if n <= 1:
        return 0.0
    positives = sum(1 for value in labels if value == 1)
    negatives = n - positives
    if positives == 0 or negatives == 0:
        return 0.0

    pairs = sorted(zip(scores, labels), key=lambda item: item[0])
    rank = 1
    sum_positive_ranks = 0.0
    idx = 0
    while idx < n:
        start = idx
        score = pairs[idx][0]
        while idx < n and pairs[idx][0] == score:
            idx += 1
        tie_count = idx - start
        average_rank = (rank + rank + tie_count - 1) / 2.0
        positive_in_tie = sum(1 for _, label in pairs[start:idx] if label == 1)
        sum_positive_ranks += positive_in_tie * average_rank
        rank += tie_count

    return (sum_positive_ranks - positives * (positives + 1) / 2.0) / (positives * negatives)


def _pr_auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(1 for label in labels if label == 1)
    if positives == 0:
        return 0.0

    pairs = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    tp = 0
    fp = 0
    points: list[tuple[float, float]] = [(0.0, 1.0)]
    for _, label in pairs:
        if label == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        points.append((recall, precision))

    auc = 0.0
    for idx in range(1, len(points)):
        recall_prev, precision_prev = points[idx - 1]
        recall_cur, precision_cur = points[idx]
        auc += (recall_cur - recall_prev) * ((precision_prev + precision_cur) / 2.0)
    return auc


def _brier_score(labels: list[int], scores: list[float]) -> float:
    if not labels:
        return 1.0
    return sum((score - label) ** 2 for label, score in zip(labels, scores)) / len(labels)


def _ece(labels: list[int], scores: list[float], bins: int = 10) -> float:
    if not labels:
        return 1.0
    total = len(labels)
    ece = 0.0
    for idx in range(bins):
        lower = idx / bins
        upper = (idx + 1) / bins
        bucket = [
            (label, score)
            for label, score in zip(labels, scores)
            if (score >= lower and score < upper) or (idx == bins - 1 and score == 1.0)
        ]
        if not bucket:
            continue
        avg_label = sum(label for label, _ in bucket) / len(bucket)
        avg_score = sum(score for _, score in bucket) / len(bucket)
        ece += (len(bucket) / total) * abs(avg_label - avg_score)
    return ece


def _write_ndjson(path: Path, entries: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline evaluation gate for signature ML model")
    parser.add_argument("--dataset", required=True, help="Feature dataset NDJSON")
    parser.add_argument("--model", default="", help="Optional model JSON (uses dataset model_score when omitted)")
    parser.add_argument("--previous-report", default="", help="Previous eval report JSON")
    parser.add_argument("--previous-trend", default="", help="Previous eval trend NDJSON")
    parser.add_argument("--output-report", required=True, help="Output eval report JSON")
    parser.add_argument("--output-trend", default="", help="Optional output trend NDJSON")
    parser.add_argument("--threshold", type=float, default=0.50)
    parser.add_argument("--auto-threshold", default="0")
    parser.add_argument("--eval-ratio", type=float, default=0.35)
    parser.add_argument("--min-eval-samples", type=int, default=120)
    parser.add_argument("--min-precision", type=float, default=0.75)
    parser.add_argument("--min-recall", type=float, default=0.70)
    parser.add_argument("--min-pr-auc", type=float, default=0.82)
    parser.add_argument("--min-roc-auc", type=float, default=0.82)
    parser.add_argument("--max-brier-score", type=float, default=0.20)
    parser.add_argument("--max-ece", type=float, default=0.10)
    parser.add_argument("--max-pr-auc-drop", type=float, default=0.05)
    parser.add_argument("--max-roc-auc-drop", type=float, default=0.05)
    parser.add_argument("--fail-on-threshold", default="0")
    parser.add_argument("--fail-on-regression", default="0")
    return parser


def main() -> int:
    args = _parser().parse_args()
    fail_on_threshold = _parse_bool(args.fail_on_threshold)
    fail_on_regression = _parse_bool(args.fail_on_regression)
    auto_threshold = _parse_bool(args.auto_threshold)

    try:
        rows = _read_ndjson(Path(args.dataset))
    except (FileNotFoundError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_offline_eval_gate",
            "recorded_at_utc": _iso_utc(_now_utc()),
            "status": "fail",
            "failures": [str(err)],
        }
        Path(args.output_report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(str(err))
        return 1

    model_payload = _load_json_optional(Path(args.model)) if args.model else None
    model_weights, model_bias, feature_scales = _extract_model(model_payload)

    valid_rows: list[dict[str, Any]] = []
    for row in rows:
        label = _as_int(row.get("label"), -1)
        if label not in (0, 1):
            continue
        observed = _parse_ts(row.get("observed_at_utc"))
        if observed is None:
            continue
        valid_rows.append({**row, "_label": label, "_observed": observed})

    valid_rows.sort(key=lambda row: row["_observed"])
    total_count = len(valid_rows)
    eval_ratio = _clamp(args.eval_ratio, 0.05, 0.95)
    eval_count = int(round(total_count * eval_ratio))
    eval_count = max(eval_count, args.min_eval_samples)
    if eval_count >= total_count and total_count > 1:
        eval_count = max(total_count // 2, 1)

    eval_rows = valid_rows[-eval_count:] if eval_count > 0 else []
    labels = [int(row["_label"]) for row in eval_rows]
    scores = [_score_row(row, model_weights, model_bias, feature_scales) for row in eval_rows]

    fixed_threshold = _clamp(args.threshold, 0.0, 1.0)
    if auto_threshold:
        operating_threshold, metrics, threshold_strategy = _select_operating_threshold(
            labels,
            scores,
            args.min_precision,
        )
    else:
        operating_threshold = fixed_threshold
        metrics = _binary_metrics(labels, scores, operating_threshold)
        threshold_strategy = "fixed"
    metrics["pr_auc"] = _pr_auc(labels, scores)
    metrics["roc_auc"] = _roc_auc(labels, scores)
    metrics["brier_score"] = _brier_score(labels, scores)
    metrics["ece"] = _ece(labels, scores)

    # Expanding-window temporal validation with 3 splits
    eval_ratios = [0.20, 0.30, 0.40]
    split_results: list[dict[str, Any]] = []

    for split_ratio in eval_ratios:
        split_eval_count = int(round(total_count * split_ratio))
        split_eval_count = max(split_eval_count, min(args.min_eval_samples, total_count // 2))
        if split_eval_count >= total_count and total_count > 1:
            split_eval_count = max(total_count // 2, 1)

        split_eval_rows = valid_rows[-split_eval_count:] if split_eval_count > 0 else []
        split_labels = [int(row["_label"]) for row in split_eval_rows]
        split_scores = [_score_row(row, model_weights, model_bias, feature_scales) for row in split_eval_rows]

        if auto_threshold:
            split_threshold, split_metrics, split_strategy = _select_operating_threshold(
                split_labels, split_scores, args.min_precision,
            )
        else:
            split_threshold = fixed_threshold
            split_metrics = _binary_metrics(split_labels, split_scores, split_threshold)
            split_strategy = "fixed"

        split_metrics["pr_auc"] = _pr_auc(split_labels, split_scores)
        split_metrics["roc_auc"] = _roc_auc(split_labels, split_scores)
        split_metrics["brier_score"] = _brier_score(split_labels, split_scores)
        split_metrics["ece"] = _ece(split_labels, split_scores)

        split_results.append({
            "eval_ratio": split_ratio,
            "eval_count": len(split_eval_rows),
            "threshold": round(split_threshold, 6),
            "strategy": split_strategy,
            "metrics": {k: round(v, 6) if isinstance(v, float) else v for k, v in split_metrics.items()},
        })

    # Use median metrics across splits for summary reporting
    def _median_of(values: list[float]) -> float:
        s = sorted(values)
        n = len(s)
        if n == 0:
            return 0.0
        if n % 2 == 1:
            return s[n // 2]
        return (s[n // 2 - 1] + s[n // 2]) / 2.0

    temporal_summary: dict[str, Any] = {}
    if split_results:
        temporal_summary = {
            "median_pr_auc": round(_median_of([s["metrics"].get("pr_auc", 0.0) for s in split_results]), 6),
            "median_roc_auc": round(_median_of([s["metrics"].get("roc_auc", 0.0) for s in split_results]), 6),
            "median_precision": round(_median_of([s["metrics"].get("precision", 0.0) for s in split_results]), 6),
            "median_recall": round(_median_of([s["metrics"].get("recall", 0.0) for s in split_results]), 6),
            "median_brier_score": round(_median_of([s["metrics"].get("brier_score", 0.0) for s in split_results]), 6),
            "median_ece": round(_median_of([s["metrics"].get("ece", 0.0) for s in split_results]), 6),
        }

    previous_report = _load_json_optional(Path(args.previous_report)) if args.previous_report else None
    previous_metrics = (
        previous_report.get("metrics", {})
        if isinstance(previous_report, dict) and isinstance(previous_report.get("metrics", {}), dict)
        else {}
    )

    pr_auc_drop = _as_float(previous_metrics.get("pr_auc"), metrics["pr_auc"]) - metrics["pr_auc"]
    roc_auc_drop = _as_float(previous_metrics.get("roc_auc"), metrics["roc_auc"]) - metrics["roc_auc"]

    failures: list[str] = []
    threshold_failures: list[str] = []
    regression_failures: list[str] = []

    if total_count < args.min_eval_samples:
        threshold_failures.append(
            f"total dataset count below min_eval_samples: {total_count} < {args.min_eval_samples}"
        )
    if len(eval_rows) < args.min_eval_samples:
        threshold_failures.append(
            f"eval sample count below min_eval_samples: {len(eval_rows)} < {args.min_eval_samples}"
        )
    if metrics["precision"] < args.min_precision:
        threshold_failures.append(
            f"precision below threshold: {metrics['precision']:.6f} < {args.min_precision:.6f}"
        )
    if metrics["recall"] < args.min_recall:
        threshold_failures.append(
            f"recall below threshold: {metrics['recall']:.6f} < {args.min_recall:.6f}"
        )
    if metrics["pr_auc"] < args.min_pr_auc:
        threshold_failures.append(
            f"pr_auc below threshold: {metrics['pr_auc']:.6f} < {args.min_pr_auc:.6f}"
        )
    if metrics["roc_auc"] < args.min_roc_auc:
        threshold_failures.append(
            f"roc_auc below threshold: {metrics['roc_auc']:.6f} < {args.min_roc_auc:.6f}"
        )
    if metrics["brier_score"] > args.max_brier_score:
        threshold_failures.append(
            f"brier_score above threshold: {metrics['brier_score']:.6f} > {args.max_brier_score:.6f}"
        )
    if metrics["ece"] > args.max_ece:
        threshold_failures.append(
            f"ece above threshold: {metrics['ece']:.6f} > {args.max_ece:.6f}"
        )

    if previous_report is not None:
        if pr_auc_drop > args.max_pr_auc_drop:
            regression_failures.append(
                f"pr_auc drop too high: {pr_auc_drop:.6f} > {args.max_pr_auc_drop:.6f}"
            )
        if roc_auc_drop > args.max_roc_auc_drop:
            regression_failures.append(
                f"roc_auc drop too high: {roc_auc_drop:.6f} > {args.max_roc_auc_drop:.6f}"
            )

    failures.extend(threshold_failures)
    failures.extend(regression_failures)

    if (threshold_failures and fail_on_threshold) or (regression_failures and fail_on_regression):
        status = "fail"
    elif failures:
        status = "shadow_alert"
    else:
        status = "pass"

    report = {
        "suite": "signature_ml_offline_eval_gate",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "status": status,
        "mode": "enforced" if (fail_on_threshold or fail_on_regression) else "shadow",
        "thresholds": {
            "threshold": fixed_threshold,
            "auto_threshold": auto_threshold,
            "operating_threshold": operating_threshold,
            "operating_threshold_strategy": threshold_strategy,
            "eval_ratio": eval_ratio,
            "min_eval_samples": args.min_eval_samples,
            "min_precision": args.min_precision,
            "min_recall": args.min_recall,
            "min_pr_auc": args.min_pr_auc,
            "min_roc_auc": args.min_roc_auc,
            "max_brier_score": args.max_brier_score,
            "max_ece": args.max_ece,
            "max_pr_auc_drop": args.max_pr_auc_drop,
            "max_roc_auc_drop": args.max_roc_auc_drop,
            "fail_on_threshold": fail_on_threshold,
            "fail_on_regression": fail_on_regression,
        },
        "counts": {
            "dataset_total": total_count,
            "eval_count": len(eval_rows),
            "positive_eval": sum(labels),
            "negative_eval": len(labels) - sum(labels),
        },
        "metrics": {
            "precision": round(metrics["precision"], 6),
            "recall": round(metrics["recall"], 6),
            "f1": round(metrics["f1"], 6),
            "pr_auc": round(metrics["pr_auc"], 6),
            "roc_auc": round(metrics["roc_auc"], 6),
            "brier_score": round(metrics["brier_score"], 6),
            "ece": round(metrics["ece"], 6),
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "tn": metrics["tn"],
            "fn": metrics["fn"],
            "operating_threshold": round(operating_threshold, 6),
            "operating_threshold_strategy": threshold_strategy,
            "previous_pr_auc": round(_as_float(previous_metrics.get("pr_auc"), 0.0), 6)
            if previous_report is not None
            else None,
            "previous_roc_auc": round(_as_float(previous_metrics.get("roc_auc"), 0.0), 6)
            if previous_report is not None
            else None,
            "pr_auc_drop": round(pr_auc_drop, 6) if previous_report is not None else None,
            "roc_auc_drop": round(roc_auc_drop, 6) if previous_report is not None else None,
        },
        "threshold_failures": threshold_failures,
        "regression_failures": regression_failures,
        "failures": failures,
        "temporal_splits": split_results,
        "temporal_summary": temporal_summary,
    }

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.output_trend:
        previous_trend = _load_ndjson_optional(Path(args.previous_trend)) if args.previous_trend else []
        trend_entry = {
            "recorded_at_utc": report["recorded_at_utc"],
            "suite": "signature_ml_offline_eval_trend",
            "status": status,
            "precision": report["metrics"]["precision"],
            "recall": report["metrics"]["recall"],
            "pr_auc": report["metrics"]["pr_auc"],
            "roc_auc": report["metrics"]["roc_auc"],
            "brier_score": report["metrics"]["brier_score"],
            "ece": report["metrics"]["ece"],
            "dataset_total": total_count,
            "eval_count": len(eval_rows),
            "model_mode": "trained_model" if model_weights else "pre_scored_dataset",
            "operating_threshold": report["metrics"]["operating_threshold"],
            "operating_threshold_strategy": threshold_strategy,
        }
        _write_ndjson(Path(args.output_trend), [*previous_trend, trend_entry])

    print("Signature ML offline eval snapshot:")
    print(f"- status: {status}")
    print(f"- eval samples: {len(eval_rows)}")
    print(f"- operating threshold: {operating_threshold:.6f}")
    print(f"- operating threshold strategy: {threshold_strategy}")
    print(f"- precision: {metrics['precision']:.6f}")
    print(f"- recall: {metrics['recall']:.6f}")
    print(f"- pr_auc: {metrics['pr_auc']:.6f}")
    print(f"- roc_auc: {metrics['roc_auc']:.6f}")
    print(f"- brier_score: {metrics['brier_score']:.6f}")
    print(f"- ece: {metrics['ece']:.6f}")
    if failures:
        print("\nSignature ML offline eval alerts:")
        for failure in failures:
            print(f"- {failure}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
