#!/usr/bin/env python3
"""A/B testing framework for comparing eGuard ML models.

Loads two model JSON files and a holdout dataset (NDJSON with features + labels),
scores each sample with both models, computes per-model metrics, and runs
McNemar's test for statistical significance.

Usage:
  python3 signature_ml_ab_test.py \
    --model-a model_a.json \
    --model-b model_b.json \
    --holdout holdout.ndjson \
    --output ab_result.json
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _sigmoid(raw: float) -> float:
    if raw >= 0:
        return 1.0 / (1.0 + math.exp(-raw))
    exp_val = math.exp(raw)
    return exp_val / (1.0 + exp_val)


def _load_model(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"model not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"model must be a JSON object: {path}")
    for required in ("features", "weights", "feature_scales", "bias", "threshold"):
        if required not in payload:
            raise ValueError(f"model missing required field '{required}': {path}")
    return payload


def _load_holdout(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"holdout dataset not found: {path}")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        payload = json.loads(raw)
        if isinstance(payload, dict) and payload.get("label") is not None:
            rows.append(payload)
    return rows


def _score_sample(
    row: dict[str, Any],
    features: list[str],
    weights: dict[str, float],
    feature_scales: dict[str, float],
    bias: float,
) -> float:
    logit = bias
    for feature in features:
        raw_val = _as_float(row.get(feature), 0.0)
        scale = max(_as_float(feature_scales.get(feature), 1.0), 1.0)
        scaled = raw_val / scale
        logit += _as_float(weights.get(feature), 0.0) * scaled
    return _sigmoid(logit)


def _compute_metrics(
    labels: list[int],
    scores: list[float],
    threshold: float,
) -> dict[str, float]:
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
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "pr_auc": round(_pr_auc(labels, scores), 6),
        "roc_auc": round(_roc_auc(labels, scores), 6),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def _roc_auc(labels: list[int], scores: list[float]) -> float:
    n = len(labels)
    if n <= 1:
        return 0.0
    positives = sum(1 for v in labels if v == 1)
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
    for i in range(1, len(points)):
        recall_prev, precision_prev = points[i - 1]
        recall_cur, precision_cur = points[i]
        auc += (recall_cur - recall_prev) * ((precision_prev + precision_cur) / 2.0)
    return auc


def _chi2_sf(x: float, df: int = 1) -> float:
    """Survival function (1 - CDF) of chi-squared distribution.

    Uses the regularized incomplete gamma function approximation for df=1.
    For df=1, chi2_sf(x) = erfc(sqrt(x/2)).
    """
    if x <= 0.0:
        return 1.0
    if df != 1:
        # Fallback: use scipy if available, otherwise approximate
        try:
            from scipy.stats import chi2  # type: ignore[import-untyped]
            return float(chi2.sf(x, df))
        except ImportError:
            pass
        # Rough gamma-based approximation for other df (not needed for McNemar)
        return 0.0

    # For df=1: P(X > x) = erfc(sqrt(x/2))
    return _erfc(math.sqrt(x / 2.0))


def _erfc(x: float) -> float:
    """Complementary error function approximation (Abramowitz & Stegun 7.1.26)."""
    t = 1.0 / (1.0 + 0.3275911 * abs(x))
    poly = t * (
        0.254829592
        + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429)))
    )
    result = poly * math.exp(-(x * x))
    if x < 0:
        return 2.0 - result
    return result


def _mcnemar_test(
    preds_a: list[int],
    preds_b: list[int],
    labels: list[int],
) -> dict[str, Any]:
    """McNemar's test comparing two classifiers on the same data."""
    # Contingency table
    both_correct = 0
    a_correct_b_wrong = 0
    a_wrong_b_correct = 0
    both_wrong = 0

    for pred_a, pred_b, label in zip(preds_a, preds_b, labels):
        a_ok = pred_a == label
        b_ok = pred_b == label
        if a_ok and b_ok:
            both_correct += 1
        elif a_ok and not b_ok:
            a_correct_b_wrong += 1
        elif not a_ok and b_ok:
            a_wrong_b_correct += 1
        else:
            both_wrong += 1

    b = a_correct_b_wrong
    c = a_wrong_b_correct

    if (b + c) == 0:
        return {
            "chi2": 0.0,
            "p_value": 1.0,
            "discordant_a_better": b,
            "discordant_b_better": c,
            "both_correct": both_correct,
            "both_wrong": both_wrong,
        }

    chi2 = ((b - c) ** 2) / (b + c)
    p_value = _chi2_sf(chi2, df=1)

    return {
        "chi2": round(chi2, 6),
        "p_value": round(p_value, 6),
        "discordant_a_better": b,
        "discordant_b_better": c,
        "both_correct": both_correct,
        "both_wrong": both_wrong,
    }


def _wilson_ci(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a proportion."""
    if total == 0:
        return 0.0, 0.0
    p_hat = successes / total
    denom = 1.0 + z * z / total
    center = (p_hat + z * z / (2 * total)) / denom
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * total)) / total) / denom
    return round(max(0.0, center - spread), 6), round(min(1.0, center + spread), 6)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A/B testing framework for comparing eGuard ML models"
    )
    parser.add_argument("--model-a", required=True, help="Path to model A JSON")
    parser.add_argument("--model-b", required=True, help="Path to model B JSON")
    parser.add_argument("--holdout", required=True, help="Holdout dataset NDJSON (features + labels)")
    parser.add_argument("--output", required=True, help="Output A/B test result JSON")
    parser.add_argument("--significance", type=float, default=0.05, help="Significance level (default 0.05)")
    return parser


def main() -> int:
    args = _parser().parse_args()

    model_a = _load_model(Path(args.model_a))
    model_b = _load_model(Path(args.model_b))
    holdout = _load_holdout(Path(args.holdout))

    if not holdout:
        raise SystemExit("holdout dataset is empty or has no labeled rows")

    labels = [int(row.get("label", 0)) for row in holdout]
    pos_count = sum(1 for l in labels if l == 1)
    neg_count = len(labels) - pos_count
    if pos_count == 0 or neg_count == 0:
        raise SystemExit("holdout must contain both positive and negative labels")

    # Score with model A
    scores_a = [
        _score_sample(
            row,
            model_a["features"],
            model_a["weights"],
            model_a["feature_scales"],
            _as_float(model_a["bias"], 0.0),
        )
        for row in holdout
    ]
    threshold_a = _as_float(model_a.get("threshold"), 0.5)
    preds_a = [1 if s >= threshold_a else 0 for s in scores_a]

    # Score with model B
    scores_b = [
        _score_sample(
            row,
            model_b["features"],
            model_b["weights"],
            model_b["feature_scales"],
            _as_float(model_b["bias"], 0.0),
        )
        for row in holdout
    ]
    threshold_b = _as_float(model_b.get("threshold"), 0.5)
    preds_b = [1 if s >= threshold_b else 0 for s in scores_b]

    # Compute metrics
    metrics_a = _compute_metrics(labels, scores_a, threshold_a)
    metrics_b = _compute_metrics(labels, scores_b, threshold_b)

    # McNemar's test
    mcnemar = _mcnemar_test(preds_a, preds_b, labels)

    # Accuracy confidence intervals (Wilson)
    correct_a = sum(1 for p, l in zip(preds_a, labels) if p == l)
    correct_b = sum(1 for p, l in zip(preds_b, labels) if p == l)
    ci_a = _wilson_ci(correct_a, len(labels))
    ci_b = _wilson_ci(correct_b, len(labels))

    # Recommendation
    significance = _clamp(_as_float(args.significance, 0.05), 0.001, 0.5)
    if mcnemar["p_value"] < significance:
        if metrics_a["f1"] > metrics_b["f1"]:
            recommendation = "model_a"
        elif metrics_b["f1"] > metrics_a["f1"]:
            recommendation = "model_b"
        else:
            recommendation = "no_significant_difference"
    else:
        recommendation = "no_significant_difference"

    result = {
        "suite": "signature_ml_ab_test",
        "holdout_samples": len(holdout),
        "positive_samples": pos_count,
        "negative_samples": neg_count,
        "model_a": {
            "path": str(args.model_a),
            "version": model_a.get("model_version", "unknown"),
            "threshold": threshold_a,
            "metrics": metrics_a,
            "accuracy_ci_95": list(ci_a),
        },
        "model_b": {
            "path": str(args.model_b),
            "version": model_b.get("model_version", "unknown"),
            "threshold": threshold_b,
            "metrics": metrics_b,
            "accuracy_ci_95": list(ci_b),
        },
        "mcnemar_chi2": mcnemar["chi2"],
        "mcnemar_p_value": mcnemar["p_value"],
        "mcnemar_details": {
            "discordant_a_better": mcnemar["discordant_a_better"],
            "discordant_b_better": mcnemar["discordant_b_better"],
            "both_correct": mcnemar["both_correct"],
            "both_wrong": mcnemar["both_wrong"],
        },
        "significance_level": significance,
        "recommendation": recommendation,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print("Signature ML A/B test results:")
    print(f"- holdout samples: {len(holdout)} (pos={pos_count}, neg={neg_count})")
    print(f"- model A ({model_a.get('model_version', '?')}): F1={metrics_a['f1']:.4f}, PR-AUC={metrics_a['pr_auc']:.4f}, ROC-AUC={metrics_a['roc_auc']:.4f}")
    print(f"- model B ({model_b.get('model_version', '?')}): F1={metrics_b['f1']:.4f}, PR-AUC={metrics_b['pr_auc']:.4f}, ROC-AUC={metrics_b['roc_auc']:.4f}")
    print(f"- McNemar chi2={mcnemar['chi2']:.4f}, p={mcnemar['p_value']:.4f}")
    print(f"- recommendation: {recommendation}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
