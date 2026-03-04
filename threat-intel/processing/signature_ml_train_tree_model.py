#!/usr/bin/env python3
"""Train deterministic tree-ensemble signature ML model (LightGBM-style stumps).

This trainer keeps zero heavy external dependencies while producing a
runtime-compatible JSON artifact for server-side GBDT inference. It also emits
linear fallback coefficients for legacy runtimes that only consume
(weights,bias,feature_scales).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso_utc(raw: datetime) -> str:
    return raw.isoformat().replace("+00:00", "Z")


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


def _sigmoid(raw: float) -> float:
    if raw >= 0:
        return 1.0 / (1.0 + math.exp(-raw))
    exp_val = math.exp(raw)
    return exp_val / (1.0 + exp_val)


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"missing feature dataset: {path}")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        payload = json.loads(raw)
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _load_feature_schema(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"missing feature schema: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    features = payload.get("features") if isinstance(payload, dict) else None
    if not isinstance(features, list) or not features:
        raise ValueError("feature schema missing features list")
    return [str(name) for name in features]


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _candidate_thresholds(values: list[float], bins: int) -> list[float]:
    if not values:
        return []
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    if n <= 2:
        return sorted(set(sorted_vals))
    thresholds: list[float] = []
    for q in range(1, max(bins, 2)):
        idx = int(round(q * (n - 1) / max(bins, 1)))
        idx = _as_int(_clamp(float(idx), 0, n - 1), 0)
        thresholds.append(sorted_vals[idx])
    return sorted(set(thresholds))


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
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        points.append((recall, precision))

    points.append((1.0, points[-1][1]))

    auc = 0.0
    prev_recall, prev_precision = points[0]
    for recall, precision in points[1:]:
        delta = recall - prev_recall
        auc += delta * ((precision + prev_precision) / 2.0)
        prev_recall, prev_precision = recall, precision
    return _clamp(auc, 0.0, 1.0)


def _log_loss(labels: list[int], scores: list[float]) -> float:
    if not labels:
        return 0.0
    eps = 1e-6
    total = 0.0
    for label, score in zip(labels, scores):
        p = _clamp(score, eps, 1.0 - eps)
        total += -(label * math.log(p) + (1 - label) * math.log(1.0 - p))
    return total / len(labels)


def _select_threshold(labels: list[int], scores: list[float], min_precision: float) -> tuple[float, dict[str, float]]:
    if not labels:
        return 0.5, {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    candidates = sorted(set([0.0, 1.0, *[round(v, 6) for v in scores]]))
    best = (0.5, {"precision": 0.0, "recall": 0.0, "f1": 0.0}, (0.0, 0.0, 0.0, -0.0))

    for threshold in candidates:
        tp = fp = tn = fn = 0
        for label, score in zip(labels, scores):
            pred = 1 if score >= threshold else 0
            if pred == 1 and label == 1:
                tp += 1
            elif pred == 1 and label == 0:
                fp += 1
            elif pred == 0 and label == 0:
                tn += 1
            else:
                fn += 1
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        key = (
            recall if precision >= min_precision else 0.0,
            f1 if precision >= min_precision else 0.0,
            precision,
            -abs(threshold - 0.5),
        )
        if key > best[2]:
            best = (threshold, {"precision": precision, "recall": recall, "f1": f1}, key)

    return float(best[0]), best[1]


def _prepare_training_rows(rows: list[dict[str, Any]], features: list[str]) -> tuple[list[list[float]], list[int], int]:
    matrix: list[list[float]] = []
    labels: list[int] = []
    unresolved = 0
    for row in rows:
        label = row.get("label")
        if label is None:
            unresolved += 1
            continue
        label_int = _as_int(label, -1)
        if label_int not in (0, 1):
            unresolved += 1
            continue
        matrix.append([_as_float(row.get(feature), 0.0) for feature in features])
        labels.append(label_int)
    return matrix, labels, unresolved


def _train_gbdt_stumps(
    matrix: list[list[float]],
    labels: list[int],
    features: list[str],
    trees: int,
    learning_rate: float,
    l2: float,
    bins: int,
    min_gain: float,
) -> tuple[float, list[dict[str, Any]], list[float], dict[str, Any]]:
    n = len(labels)
    if n == 0:
        raise ValueError("no labeled samples available")

    positive = sum(labels)
    negative = n - positive
    base_score = math.log((positive + 1.0) / (negative + 1.0))
    raw_scores = [base_score for _ in range(n)]

    feature_values = [[row[i] for row in matrix] for i in range(len(features))]
    threshold_map = {
        feature: _candidate_thresholds(feature_values[idx], bins)
        for idx, feature in enumerate(features)
    }

    forest: list[dict[str, Any]] = []
    surrogate_weights = {feature: 0.0 for feature in features}
    surrogate_bias = base_score

    for _ in range(max(trees, 1)):
        probs = [_sigmoid(raw) for raw in raw_scores]
        grad = [label - prob for label, prob in zip(labels, probs)]
        hess = [max(prob * (1.0 - prob), 1e-6) for prob in probs]

        total_g = sum(grad)
        total_h = sum(hess)
        parent_score = (total_g * total_g) / (total_h + l2)

        best_gain = -1e18
        best: dict[str, Any] | None = None

        for f_idx, feature in enumerate(features):
            values = feature_values[f_idx]
            for threshold in threshold_map.get(feature, []):
                left_idx = [i for i, value in enumerate(values) if value <= threshold]
                right_idx = [i for i, value in enumerate(values) if value > threshold]
                if not left_idx or not right_idx:
                    continue

                gl = sum(grad[i] for i in left_idx)
                hl = sum(hess[i] for i in left_idx)
                gr = sum(grad[i] for i in right_idx)
                hr = sum(hess[i] for i in right_idx)

                left_leaf = learning_rate * (gl / (hl + l2))
                right_leaf = learning_rate * (gr / (hr + l2))

                gain = 0.5 * ((gl * gl) / (hl + l2) + (gr * gr) / (hr + l2) - parent_score)
                if gain > best_gain:
                    best_gain = gain
                    best = {
                        "feature": feature,
                        "feature_idx": f_idx,
                        "threshold": threshold,
                        "left_leaf": left_leaf,
                        "right_leaf": right_leaf,
                    }

        if best is None or best_gain < min_gain:
            break

        feature = best["feature"]
        threshold = float(best["threshold"])
        left_leaf = float(best["left_leaf"])
        right_leaf = float(best["right_leaf"])
        f_idx = _as_int(best["feature_idx"], 0)

        for i in range(n):
            val = matrix[i][f_idx]
            raw_scores[i] += left_leaf if val <= threshold else right_leaf

        forest.append(
            {
                "weight": 1.0,
                "nodes": [
                    {"id": 0, "feature": feature, "threshold": threshold, "left": 1, "right": 2},
                    {"id": 1, "leaf": left_leaf},
                    {"id": 2, "leaf": right_leaf},
                ],
            }
        )

        surrogate_weights[feature] += (right_leaf - left_leaf) * 0.5
        surrogate_bias += (right_leaf + left_leaf) * 0.5

    predictions = [_sigmoid(raw) for raw in raw_scores]
    diagnostics = {
        "trained_trees": len(forest),
        "requested_trees": trees,
        "base_score": round(base_score, 6),
        "learning_rate": learning_rate,
        "l2": l2,
        "min_gain": min_gain,
        "threshold_bins": bins,
    }
    return base_score, forest, predictions, {
        "surrogate_weights": surrogate_weights,
        "surrogate_bias": surrogate_bias,
        "diagnostics": diagnostics,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train deterministic tree-ensemble signature ML model")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--feature-schema", required=True)
    parser.add_argument("--labels-report", required=True)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--model-out", required=True)
    parser.add_argument("--metadata-out", required=True)
    parser.add_argument("--min-precision", type=float, default=0.75)
    parser.add_argument("--trees", type=int, default=48)
    parser.add_argument("--learning-rate", type=float, default=0.15)
    parser.add_argument("--l2", type=float, default=1.0)
    parser.add_argument("--threshold-bins", type=int, default=12)
    parser.add_argument("--min-gain", type=float, default=1e-6)
    return parser


def main() -> int:
    args = _parser().parse_args()

    rows = _read_ndjson(Path(args.dataset))
    feature_schema = _load_feature_schema(Path(args.feature_schema))
    matrix, labels, unresolved = _prepare_training_rows(rows, feature_schema)

    base_score, forest, preds, aux = _train_gbdt_stumps(
        matrix=matrix,
        labels=labels,
        features=feature_schema,
        trees=max(args.trees, 1),
        learning_rate=max(_as_float(args.learning_rate, 0.1), 1e-4),
        l2=max(_as_float(args.l2, 1.0), 1e-6),
        bins=max(_as_int(args.threshold_bins, 12), 3),
        min_gain=max(_as_float(args.min_gain, 1e-6), 0.0),
    )

    threshold, threshold_metrics = _select_threshold(labels, preds, _clamp(args.min_precision, 0.0, 1.0))

    surrogate_weights = aux["surrogate_weights"]
    surrogate_bias = _as_float(aux["surrogate_bias"], 0.0)

    model = {
        "suite": "signature_ml_tree_ensemble_model",
        "model_type": "gbdt_tree_ensemble_v1",
        "model_version": args.model_version,
        "trained_at_utc": _iso_utc(_now_utc()),
        "features": feature_schema,
        "base_score": round(base_score, 6),
        "threshold": round(threshold, 6),
        "trees": forest,
        # Legacy compatibility payload for runtimes still expecting linear fields.
        "weights": {name: round(_as_float(surrogate_weights.get(name), 0.0), 6) for name in feature_schema},
        "feature_scales": {name: 1.0 for name in feature_schema},
        "bias": round(surrogate_bias, 6),
        "training_samples": len(labels),
        "positive_samples": sum(labels),
        "negative_samples": len(labels) - sum(labels),
        "training_metrics": {
            "precision": round(threshold_metrics["precision"], 6),
            "recall": round(threshold_metrics["recall"], 6),
            "f1": round(threshold_metrics["f1"], 6),
            "pr_auc": round(_pr_auc(labels, preds), 6),
            "roc_auc": round(_roc_auc(labels, preds), 6),
            "log_loss": round(_log_loss(labels, preds), 6),
        },
        "training_diagnostics": {
            **aux["diagnostics"],
            "unresolved_rows": unresolved,
            "dataset_rows": len(rows),
        },
    }

    model_path = Path(args.model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")

    metadata = {
        "suite": "signature_ml_model_metadata",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "model_version": args.model_version,
        "model_artifact": str(model_path),
        "model_sha256": _sha256_file(model_path),
        "dataset": str(args.dataset),
        "dataset_sha256": _sha256_file(Path(args.dataset)),
        "feature_schema": str(args.feature_schema),
        "feature_schema_sha256": _sha256_file(Path(args.feature_schema)),
        "labels_report": str(args.labels_report),
        "labels_report_sha256": _sha256_file(Path(args.labels_report)),
        "training_samples": len(labels),
        "positive_samples": sum(labels),
        "negative_samples": len(labels) - sum(labels),
        "threshold": round(threshold, 6),
        "optimizer": "deterministic_gbdt_stumps",
        "model_type": "gbdt_tree_ensemble_v1",
        "trained_trees": len(forest),
    }

    metadata_path = Path(args.metadata_out)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print("Signature ML tree model training snapshot:")
    print(f"- model version: {args.model_version}")
    print(f"- features: {len(feature_schema)}")
    print(f"- trained trees: {len(forest)}")
    print(f"- training samples: {len(labels)}")
    print(f"- threshold: {threshold:.6f}")
    print(f"- pr_auc: {model['training_metrics']['pr_auc']:.6f}")
    print(f"- roc_auc: {model['training_metrics']['roc_auc']:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
