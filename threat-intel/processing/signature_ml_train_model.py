#!/usr/bin/env python3
"""Train advanced deterministic signature-ML model.

Implements a deterministic, framework-free logistic regression trainer with:
- Robust scaling (percentile/MAD-aware)
- Class weighting for imbalance
- Newton/IRLS optimizer with damping + line search
- Regularization sweep with holdout metrics
- Temperature scaling calibration (log-loss optimized)

The output schema remains compatible with the agent runtime:
weights: {feature: float}, feature_scales: {feature: float}, bias, threshold.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RESERVED_FIELDS = {
    "sample_id",
    "observed_at_utc",
    "adjudicated_at_utc",
    "host_id",
    "rule_id",
    "label",
    "label_source",
    "event_class",
    "model_score",
}


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


def _safe_logit_prior(positive: int, negative: int) -> float:
    alpha = 1.0
    pos = positive + alpha
    neg = negative + alpha
    return math.log(pos / neg)


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _logit(prob: float) -> float:
    p = _clamp(prob, 1e-6, 1.0 - 1e-6)
    return math.log(p / (1.0 - p))


def _sigmoid(raw: float) -> float:
    if raw >= 0:
        return 1.0 / (1.0 + math.exp(-raw))
    exp_val = math.exp(raw)
    return exp_val / (1.0 + exp_val)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    pct = _clamp(pct, 0.0, 100.0)
    sorted_vals = sorted(values)
    idx = int(round((pct / 100.0) * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


def _median(values: list[float]) -> float:
    return _percentile(values, 50.0)


def _mad(values: list[float], med: float) -> float:
    if not values:
        return 0.0
    deviations = [abs(v - med) for v in values]
    return _median(deviations)


def _variance(values: list[float], mean: float) -> float:
    if not values:
        return 0.0
    return sum((v - mean) ** 2 for v in values) / len(values)


def _select_operating_threshold(
    labels: list[int],
    scores: list[float],
    min_precision: float,
) -> tuple[float, dict[str, float]]:
    if not scores:
        return 0.5, {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    unique = sorted(set(round(score, 6) for score in scores))
    candidates = [0.0, *unique, 1.0]

    best_threshold = 0.5
    best_metrics = {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    best_key = (0.0, 0.0, 0.0, -abs(best_threshold - 0.5))

    for threshold in candidates:
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

        key = (
            recall if precision >= min_precision else 0.0,
            f1 if precision >= min_precision else 0.0,
            precision,
            -abs(threshold - 0.5),
        )
        if key > best_key:
            best_key = key
            best_threshold = threshold
            best_metrics = {"precision": precision, "recall": recall, "f1": f1}

    return best_threshold, best_metrics


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


def _log_loss(labels: list[int], scores: list[float]) -> float:
    if not labels:
        return 1.0
    total = 0.0
    for label, score in zip(labels, scores):
        p = _clamp(score, 1e-8, 1.0 - 1e-8)
        total += -(label * math.log(p) + (1 - label) * math.log(1 - p))
    return total / len(labels)


def _confusion(labels: list[int], scores: list[float], threshold: float) -> dict[str, int]:
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
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _log_likelihood(
    weights: list[float],
    bias: float,
    X: list[list[float]],
    labels: list[int],
    sample_weights: list[float],
    l2: float,
) -> float:
    ll = 0.0
    for row, label, weight in zip(X, labels, sample_weights):
        z = bias + sum(w * x for w, x in zip(weights, row))
        p = _clamp(_sigmoid(z), 1e-10, 1.0 - 1e-10)
        ll += weight * (label * math.log(p) + (1 - label) * math.log(1 - p))
    ll -= 0.5 * l2 * sum(w**2 for w in weights)
    return ll


def _solve_linear_system(matrix: list[list[float]], vector: list[float]) -> list[float]:
    n = len(vector)
    mat = [row[:] for row in matrix]
    vec = vector[:]

    for i in range(n):
        pivot = i
        pivot_val = abs(mat[i][i])
        for j in range(i + 1, n):
            cand = abs(mat[j][i])
            if cand > pivot_val:
                pivot = j
                pivot_val = cand
        if pivot_val < 1e-12:
            mat[i][i] += 1e-6
            pivot_val = abs(mat[i][i])
        if pivot != i:
            mat[i], mat[pivot] = mat[pivot], mat[i]
            vec[i], vec[pivot] = vec[pivot], vec[i]

        divisor = mat[i][i]
        if abs(divisor) < 1e-12:
            divisor = 1e-12
        for j in range(i, n):
            mat[i][j] /= divisor
        vec[i] /= divisor

        for k in range(n):
            if k == i:
                continue
            factor = mat[k][i]
            if factor == 0.0:
                continue
            for j in range(i, n):
                mat[k][j] -= factor * mat[i][j]
            vec[k] -= factor * vec[i]

    return vec


def _invert_matrix(matrix: list[list[float]]) -> list[list[float]] | None:
    n = len(matrix)
    mat = [row[:] + [1.0 if i == j else 0.0 for j in range(n)] for i, row in enumerate(matrix)]

    for i in range(n):
        pivot = i
        pivot_val = abs(mat[i][i])
        for j in range(i + 1, n):
            cand = abs(mat[j][i])
            if cand > pivot_val:
                pivot = j
                pivot_val = cand
        if pivot_val < 1e-12:
            return None
        if pivot != i:
            mat[i], mat[pivot] = mat[pivot], mat[i]

        divisor = mat[i][i]
        if abs(divisor) < 1e-12:
            return None
        for j in range(2 * n):
            mat[i][j] /= divisor

        for k in range(n):
            if k == i:
                continue
            factor = mat[k][i]
            if factor == 0.0:
                continue
            for j in range(2 * n):
                mat[k][j] -= factor * mat[i][j]

    return [row[n:] for row in mat]


def _build_hessian(
    weights: list[float],
    bias: float,
    X: list[list[float]],
    labels: list[int],
    sample_weights: list[float],
    l2: float,
) -> list[list[float]]:
    d = len(weights)
    hessian = [[0.0 for _ in range(d + 1)] for _ in range(d + 1)]

    for row, label, weight in zip(X, labels, sample_weights):
        z = bias + sum(w * x for w, x in zip(weights, row))
        p = _sigmoid(z)
        wgt = weight * p * (1.0 - p)
        for j in range(d):
            for k in range(j, d):
                hessian[j][k] += wgt * row[j] * row[k]
            hessian[j][d] += wgt * row[j]
        hessian[d][d] += wgt

    for j in range(d):
        hessian[j][j] += l2

    for j in range(d):
        for k in range(j):
            hessian[j][k] = hessian[k][j]
    for j in range(d):
        hessian[d][j] = hessian[j][d]

    return hessian


def _irls_train(
    X: list[list[float]],
    labels: list[int],
    sample_weights: list[float],
    l2: float,
    max_iter: int,
    tol: float,
    damping: float,
    min_step: float,
) -> tuple[list[float], float, dict[str, Any]]:
    d = len(X[0]) if X else 0
    weights = [0.0 for _ in range(d)]
    bias = _safe_logit_prior(sum(labels), len(labels) - sum(labels))

    diagnostics = {
        "optimizer": "irls_newton",
        "iterations": 0,
        "converged": False,
        "final_log_likelihood": 0.0,
        "last_step": 0.0,
        "gradient_norm": 0.0,
    }

    damping = _clamp(damping, 0.05, 1.0)

    for iteration in range(max_iter):
        grad = [0.0 for _ in range(d + 1)]
        hessian = [[0.0 for _ in range(d + 1)] for _ in range(d + 1)]

        for row, label, weight in zip(X, labels, sample_weights):
            z = bias + sum(w * x for w, x in zip(weights, row))
            p = _sigmoid(z)
            diff = label - p
            for j in range(d):
                grad[j] += weight * diff * row[j]
            grad[d] += weight * diff
            wgt = weight * p * (1.0 - p)
            for j in range(d):
                for k in range(j, d):
                    hessian[j][k] += wgt * row[j] * row[k]
                hessian[j][d] += wgt * row[j]
            hessian[d][d] += wgt

        for j in range(d):
            grad[j] -= l2 * weights[j]
            hessian[j][j] += l2

        for j in range(d):
            for k in range(j):
                hessian[j][k] = hessian[k][j]
        for j in range(d):
            hessian[d][j] = hessian[j][d]

        delta = _solve_linear_system(hessian, grad)
        step = damping
        current_ll = _log_likelihood(weights, bias, X, labels, sample_weights, l2)
        updated = False
        while step >= min_step:
            cand_w = [w + step * delta_w for w, delta_w in zip(weights, delta[:d])]
            cand_b = bias + step * delta[d]
            cand_ll = _log_likelihood(cand_w, cand_b, X, labels, sample_weights, l2)
            if cand_ll >= current_ll:
                weights = cand_w
                bias = cand_b
                current_ll = cand_ll
                updated = True
                break
            step *= 0.5

        diagnostics["iterations"] = iteration + 1
        diagnostics["last_step"] = step

        grad_norm = max(abs(val) for val in delta) if delta else 0.0
        diagnostics["gradient_norm"] = grad_norm

        if not updated:
            break
        if grad_norm < tol:
            diagnostics["converged"] = True
            break

    diagnostics["final_log_likelihood"] = _log_likelihood(
        weights, bias, X, labels, sample_weights, l2
    )
    return weights, bias, diagnostics


def _temperature_scale(
    logits: list[float],
    labels: list[int],
    max_iter: int,
    tol: float,
) -> tuple[float, dict[str, Any]]:
    if not logits:
        return 1.0, {"temperature": 1.0, "iterations": 0, "converged": True}

    t = 0.0  # optimize log temperature
    diagnostics = {"temperature": 1.0, "iterations": 0, "converged": False}

    for iteration in range(max_iter):
        T = math.exp(t)
        grad = 0.0
        hess = 0.0
        for logit, label in zip(logits, labels):
            scaled = logit / T
            p = _sigmoid(scaled)
            diff = p - label
            grad += -(diff * logit / T)
            hess += (p * (1 - p) * (logit / T) ** 2) + diff * (logit / T)

        if abs(hess) < 1e-8:
            break
        step = grad / hess
        t_next = t - step
        if abs(step) < tol:
            t = t_next
            diagnostics["converged"] = True
            diagnostics["iterations"] = iteration + 1
            break
        t = t_next
        diagnostics["iterations"] = iteration + 1

    diagnostics["temperature"] = math.exp(t)
    return diagnostics["temperature"], diagnostics


def _deterministic_split(
    rows: list[dict[str, Any]],
    labels: list[int],
    holdout_ratio: float,
) -> tuple[list[int], list[int]]:
    train_idx: list[int] = []
    holdout_idx: list[int] = []
    for idx, row in enumerate(rows):
        seed = str(row.get("sample_id", idx))
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:2], "big") % 100
        if bucket < int((1.0 - holdout_ratio) * 100):
            train_idx.append(idx)
        else:
            holdout_idx.append(idx)

    def has_both(indices: list[int]) -> bool:
        if not indices:
            return False
        pos = sum(1 for idx in indices if labels[idx] == 1)
        neg = len(indices) - pos
        return pos > 0 and neg > 0

    if not has_both(holdout_idx):
        return list(range(len(rows))), []
    if not has_both(train_idx):
        return list(range(len(rows))), []
    return train_idx, holdout_idx


def _stratified_kfold(
    rows: list[dict[str, Any]],
    labels: list[int],
    n_folds: int,
) -> list[tuple[list[int], list[int]]]:
    """Generate stratified k-fold splits deterministically."""
    pos_indices = [i for i, l in enumerate(labels) if l == 1]
    neg_indices = [i for i, l in enumerate(labels) if l == 0]

    # Deterministic shuffle by hashing sample_id
    def sort_key(idx: int) -> str:
        seed = str(rows[idx].get("sample_id", idx))
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    pos_indices.sort(key=sort_key)
    neg_indices.sort(key=sort_key)

    folds: list[tuple[list[int], list[int]]] = []
    for fold in range(n_folds):
        val_idx: list[int] = []
        train_idx: list[int] = []

        for indices in [pos_indices, neg_indices]:
            fold_size = len(indices) // n_folds
            start = fold * fold_size
            end = start + fold_size if fold < n_folds - 1 else len(indices)
            for i, idx in enumerate(indices):
                if start <= i < end:
                    val_idx.append(idx)
                else:
                    train_idx.append(idx)

        if val_idx and train_idx:
            folds.append((train_idx, val_idx))

    return folds


def _parse_l2_grid(raw: str, base: float) -> list[float]:
    if raw:
        values = [
            _clamp(_as_float(part.strip(), base), 0.0, 10.0)
            for part in raw.split(",")
            if part.strip()
        ]
        unique = sorted(set(values))
        return unique if unique else [base]
    grid = [base / 4.0, base / 2.0, base, base * 2.0, base * 4.0]
    grid.append(0.0)
    return sorted({round(_clamp(value, 0.0, 10.0), 6) for value in grid})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train deterministic signature ML model with IRLS/Newton optimizer"
    )
    parser.add_argument("--dataset", required=True, help="Feature snapshot NDJSON")
    parser.add_argument("--feature-schema", required=True, help="Feature schema JSON")
    parser.add_argument("--labels-report", required=True, help="Label quality report JSON")
    parser.add_argument("--model-version", required=True, help="Model version string")
    parser.add_argument("--model-out", required=True, help="Output model JSON")
    parser.add_argument("--metadata-out", required=True, help="Output metadata JSON")
    parser.add_argument("--max-iter", type=int, default=60)
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.35,
        help="Legacy damping factor for Newton steps (0.05..1.0)",
    )
    parser.add_argument("--l2", type=float, default=0.12)
    parser.add_argument("--l2-grid", default="")
    parser.add_argument("--min-precision", type=float, default=0.20)
    parser.add_argument("--holdout-ratio", type=float, default=0.20)
    parser.add_argument("--min-step", type=float, default=1e-3)
    parser.add_argument("--tol", type=float, default=1e-4)
    parser.add_argument("--temperature-max-iter", type=int, default=30)
    parser.add_argument("--temperature-tol", type=float, default=1e-4)
    return parser


def main() -> int:
    args = _parser().parse_args()

    rows = _read_ndjson(Path(args.dataset))
    if not rows:
        raise SystemExit("feature dataset is empty")

    features = _load_feature_schema(Path(args.feature_schema))
    if not features:
        raise SystemExit("feature schema has no features")

    labels = [int(row.get("label", 0)) for row in rows]
    pos_rows = [row for row, label in zip(rows, labels) if label == 1]
    neg_rows = [row for row, label in zip(rows, labels) if label == 0]
    if not pos_rows or not neg_rows:
        raise SystemExit("dataset must contain both positive and negative labels")

    feature_stats: dict[str, dict[str, float]] = {}
    feature_scales: dict[str, float] = {}

    for feature in features:
        values = [_as_float(row.get(feature), 0.0) for row in rows]
        abs_vals = [abs(value) for value in values]
        mean = sum(values) / len(values)
        median = _median(values)
        mad = _mad(values, median)
        std = math.sqrt(_variance(values, mean))
        p95 = _percentile(abs_vals, 95.0)
        scale = max(p95, std * 2.0, mad * 1.4826, 1.0)
        feature_scales[feature] = round(scale, 6)

        pos_avg = sum(_as_float(row.get(feature), 0.0) for row in pos_rows) / len(pos_rows)
        neg_avg = sum(_as_float(row.get(feature), 0.0) for row in neg_rows) / len(neg_rows)
        delta = pos_avg - neg_avg
        feature_stats[feature] = {
            "positive_mean": round(pos_avg, 6),
            "negative_mean": round(neg_avg, 6),
            "delta": round(delta, 6),
            "scale": feature_scales[feature],
            "mean": round(mean, 6),
            "median": round(median, 6),
            "std": round(std, 6),
            "mad": round(mad, 6),
            "p95": round(p95, 6),
        }

    scaled = [
        [
            _as_float(row.get(feature), 0.0) / max(feature_scales.get(feature, 1.0), 1.0)
            for feature in features
        ]
        for row in rows
    ]

    pos_rate = len(pos_rows) / len(rows)
    neg_rate = len(neg_rows) / len(rows)
    fn_cost_multiplier = 3.0
    class_weights = {
        1: fn_cost_multiplier * 0.5 / max(pos_rate, 1e-6),
        0: 0.5 / max(neg_rate, 1e-6),
    }
    sample_weights = [class_weights[label] for label in labels]

    holdout_ratio = _clamp(args.holdout_ratio, 0.05, 0.5)
    train_idx, holdout_idx = _deterministic_split(rows, labels, holdout_ratio)

    l2_grid = _parse_l2_grid(args.l2_grid, args.l2)
    sweep_results: list[dict[str, Any]] = []
    best_key = (-1.0, -1.0, 1.0, 0.0)
    best_l2 = args.l2
    best_weights: list[float] = []
    best_bias = 0.0
    best_diag: dict[str, Any] = {}

    for l2 in l2_grid:
        train_X = [scaled[idx] for idx in train_idx]
        train_labels = [labels[idx] for idx in train_idx]
        train_weights = [sample_weights[idx] for idx in train_idx]
        weights, bias, diag = _irls_train(
            train_X,
            train_labels,
            train_weights,
            l2,
            max(args.max_iter, 1),
            args.tol,
            args.learning_rate,
            args.min_step,
        )

        eval_idx = holdout_idx if holdout_idx else train_idx
        eval_X = [scaled[idx] for idx in eval_idx]
        eval_labels = [labels[idx] for idx in eval_idx]

        scores = [
            _sigmoid(bias + sum(w * x for w, x in zip(weights, row)))
            for row in eval_X
        ]
        metrics = {
            "log_loss": _log_loss(eval_labels, scores),
            "pr_auc": _pr_auc(eval_labels, scores),
            "roc_auc": _roc_auc(eval_labels, scores),
            "brier": _brier_score(eval_labels, scores),
            "ece": _ece(eval_labels, scores),
        }

        sweep_results.append({"l2": l2, "metrics": metrics, "diagnostics": diag})
        key = (
            metrics["pr_auc"],
            metrics["roc_auc"],
            -metrics["log_loss"],
            -l2,
        )
        if key > best_key:
            best_key = key
            best_l2 = l2
            best_weights = weights
            best_bias = bias
            best_diag = diag

    # 5-fold stratified cross-validation for regularization sweep
    cv_folds = _stratified_kfold(rows, labels, 5)
    cv_sweep_results: list[dict[str, Any]] = []

    if cv_folds:
        for l2 in l2_grid:
            fold_metrics: list[dict[str, float]] = []
            for fold_train_idx, fold_val_idx in cv_folds:
                fold_train_X = [scaled[idx] for idx in fold_train_idx]
                fold_train_labels = [labels[idx] for idx in fold_train_idx]
                fold_train_weights = [sample_weights[idx] for idx in fold_train_idx]
                fold_weights, fold_bias, _ = _irls_train(
                    fold_train_X, fold_train_labels, fold_train_weights,
                    l2, max(args.max_iter, 1), args.tol, args.learning_rate, args.min_step,
                )
                fold_val_X = [scaled[idx] for idx in fold_val_idx]
                fold_val_labels = [labels[idx] for idx in fold_val_idx]
                fold_scores = [
                    _sigmoid(fold_bias + sum(w * x for w, x in zip(fold_weights, row)))
                    for row in fold_val_X
                ]
                fold_metrics.append({
                    "pr_auc": _pr_auc(fold_val_labels, fold_scores),
                    "roc_auc": _roc_auc(fold_val_labels, fold_scores),
                    "log_loss": _log_loss(fold_val_labels, fold_scores),
                })

            mean_pr_auc = sum(m["pr_auc"] for m in fold_metrics) / len(fold_metrics)
            mean_roc_auc = sum(m["roc_auc"] for m in fold_metrics) / len(fold_metrics)
            std_pr_auc = (sum((m["pr_auc"] - mean_pr_auc) ** 2 for m in fold_metrics) / len(fold_metrics)) ** 0.5

            cv_sweep_results.append({
                "l2": l2,
                "cv_mean_pr_auc": round(mean_pr_auc, 6),
                "cv_mean_roc_auc": round(mean_roc_auc, 6),
                "cv_std_pr_auc": round(std_pr_auc, 6),
                "fold_metrics": fold_metrics,
            })

    # Refit on full dataset using best L2.
    weights, bias, diag = _irls_train(
        scaled,
        labels,
        sample_weights,
        best_l2,
        max(args.max_iter, 1),
        args.tol,
        args.learning_rate,
        args.min_step,
    )
    diag["selected_l2"] = best_l2

    # Temperature scaling on holdout (or full set if no holdout).
    cal_idx = holdout_idx if holdout_idx else list(range(len(rows)))
    cal_logits = [
        bias + sum(w * x for w, x in zip(weights, scaled[idx])) for idx in cal_idx
    ]
    cal_labels = [labels[idx] for idx in cal_idx]
    temperature, temp_diag = _temperature_scale(
        cal_logits,
        cal_labels,
        args.temperature_max_iter,
        args.temperature_tol,
    )
    if temperature <= 0:
        temperature = 1.0
    scale = 1.0 / temperature
    weights = [w * scale for w in weights]
    bias = bias * scale

    # Final predictions (post-calibration).
    preds = [
        _sigmoid(bias + sum(w * x for w, x in zip(weights, row))) for row in scaled
    ]

    threshold, threshold_metrics = _select_operating_threshold(
        labels,
        preds,
        args.min_precision,
    )
    threshold = round(float(threshold), 6)

    weights_by_name = {feature: round(weight, 6) for feature, weight in zip(features, weights)}

    # Estimate parameter uncertainty via inverse Hessian.
    hessian = _build_hessian(weights, bias, scaled, labels, sample_weights, best_l2)
    cov = _invert_matrix(hessian)
    weight_se = {}
    if cov is not None:
        for idx, feature in enumerate(features):
            weight_se[feature] = round(math.sqrt(abs(cov[idx][idx])), 6)

    training_metrics = {
        "precision": round(threshold_metrics["precision"], 6),
        "recall": round(threshold_metrics["recall"], 6),
        "f1": round(threshold_metrics["f1"], 6),
        "pr_auc": round(_pr_auc(labels, preds), 6),
        "roc_auc": round(_roc_auc(labels, preds), 6),
        "log_loss": round(_log_loss(labels, preds), 6),
        "brier": round(_brier_score(labels, preds), 6),
        "ece": round(_ece(labels, preds), 6),
        "confusion": _confusion(labels, preds, threshold),
    }

    model = {
        "suite": "signature_ml_linear_logit_model",
        "model_type": "linear_logit_v3_irls",
        "model_version": args.model_version,
        "trained_at_utc": _iso_utc(_now_utc()),
        "features": features,
        "weights": weights_by_name,
        "feature_scales": feature_scales,
        "bias": round(bias, 6),
        "threshold": threshold,
        "training_samples": len(rows),
        "positive_samples": len(pos_rows),
        "negative_samples": len(neg_rows),
        "feature_stats": feature_stats,
        "weight_standard_errors": weight_se,
        "training_metrics": training_metrics,
        "training_diagnostics": {
            "optimizer": diag.get("optimizer"),
            "iterations": diag.get("iterations"),
            "converged": diag.get("converged"),
            "final_log_likelihood": round(_as_float(diag.get("final_log_likelihood"), 0.0), 6),
            "gradient_norm": round(_as_float(diag.get("gradient_norm"), 0.0), 6),
            "last_step": round(_as_float(diag.get("last_step"), 0.0), 6),
            "selected_l2": round(best_l2, 6),
            "l2_sweep": sweep_results,
            "cv_sweep": cv_sweep_results,
            "temperature": round(temperature, 6),
            "temperature_diagnostics": temp_diag,
        },
    }

    model_path = Path(args.model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")

    model_sha = _sha256_file(model_path)
    feature_schema_sha = _sha256_file(Path(args.feature_schema))
    labels_report_sha = _sha256_file(Path(args.labels_report))
    dataset_sha = _sha256_file(Path(args.dataset))

    metadata = {
        "suite": "signature_ml_model_metadata",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "model_version": args.model_version,
        "model_artifact": str(model_path),
        "model_sha256": model_sha,
        "dataset": str(args.dataset),
        "dataset_sha256": dataset_sha,
        "feature_schema": str(args.feature_schema),
        "feature_schema_sha256": feature_schema_sha,
        "labels_report": str(args.labels_report),
        "labels_report_sha256": labels_report_sha,
        "training_samples": len(rows),
        "positive_samples": len(pos_rows),
        "negative_samples": len(neg_rows),
        "threshold": threshold,
        "optimizer": "irls_newton",
        "temperature": round(temperature, 6),
    }

    metadata_path = Path(args.metadata_out)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print("Signature ML model training snapshot:")
    print(f"- model version: {args.model_version}")
    print(f"- features: {len(features)}")
    print(f"- training samples: {len(rows)}")
    print(f"- positive samples: {len(pos_rows)}")
    print(f"- negative samples: {len(neg_rows)}")
    print(f"- threshold: {threshold}")
    print(f"- l2: {best_l2}")
    print(f"- temperature: {temperature:.4f}")
    print(f"- model sha256: {model_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
