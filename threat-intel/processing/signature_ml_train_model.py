#!/usr/bin/env python3
"""Train deterministic linear-logit model for signature-ML readiness pipeline."""

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
    "host_id",
    "rule_id",
    "label",
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


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _extract_features(rows: list[dict[str, Any]]) -> list[str]:
    names: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key in RESERVED_FIELDS:
                continue
            if isinstance(row.get(key), (int, float)):
                names.add(str(key))
    return sorted(names)


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
    return 1.0 / (1.0 + math.exp(-raw))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train deterministic linear-logit signature ML model")
    parser.add_argument("--dataset", required=True, help="Feature snapshot NDJSON")
    parser.add_argument("--feature-schema", required=True, help="Feature schema JSON")
    parser.add_argument("--labels-report", required=True, help="Label quality report JSON")
    parser.add_argument("--model-version", required=True, help="Model version string")
    parser.add_argument("--model-out", required=True, help="Output model JSON")
    parser.add_argument("--metadata-out", required=True, help="Output metadata JSON")
    return parser


def main() -> int:
    args = _parser().parse_args()

    rows = _read_ndjson(Path(args.dataset))
    if not rows:
        raise SystemExit("feature dataset is empty")

    features = _extract_features(rows)
    if not features:
        raise SystemExit("no numeric feature columns found")

    pos_rows = [row for row in rows if int(row.get("label", -1)) == 1]
    neg_rows = [row for row in rows if int(row.get("label", -1)) == 0]
    if not pos_rows or not neg_rows:
        raise SystemExit("dataset must contain both positive and negative labels")

    feature_stats: dict[str, dict[str, float]] = {}
    raw_weights: dict[str, float] = {}
    feature_scales: dict[str, float] = {}

    for feature in features:
        values = [_as_float(row.get(feature), 0.0) for row in rows]
        max_abs = max(abs(value) for value in values) if values else 1.0
        feature_scales[feature] = round(max(max_abs, 1.0), 6)

        pos_avg = sum(_as_float(row.get(feature), 0.0) for row in pos_rows) / len(pos_rows)
        neg_avg = sum(_as_float(row.get(feature), 0.0) for row in neg_rows) / len(neg_rows)
        delta = pos_avg - neg_avg
        feature_stats[feature] = {
            "positive_mean": round(pos_avg, 6),
            "negative_mean": round(neg_avg, 6),
            "delta": round(delta, 6),
            "scale": feature_scales[feature],
        }
        raw_weights[feature] = delta / feature_scales[feature]

    total_abs = sum(abs(weight) for weight in raw_weights.values())
    if total_abs <= 0.0:
        normalized_weights = {feature: 0.0 for feature in features}
    else:
        normalized_weights = {
            feature: round(weight / total_abs, 6) for feature, weight in raw_weights.items()
        }

    positive_count = len(pos_rows)
    negative_count = len(neg_rows)
    bias = round(_safe_logit_prior(positive_count, negative_count), 6)

    target_positive_rate = positive_count / max(len(rows), 1)
    predicted = []
    for row in rows:
        linear = bias
        for feature, weight in normalized_weights.items():
            scale = max(feature_scales.get(feature, 1.0), 1.0)
            linear += weight * (_as_float(row.get(feature), 0.0) / scale)
        predicted.append(_sigmoid(linear))
    predicted_rate = sum(predicted) / max(len(predicted), 1)
    bias_adjustment = _logit(target_positive_rate) - _logit(predicted_rate)
    bias = round(bias + bias_adjustment, 6)

    model = {
        "suite": "signature_ml_linear_logit_model",
        "model_type": "linear_logit_v1",
        "model_version": args.model_version,
        "trained_at_utc": _iso_utc(_now_utc()),
        "features": features,
        "weights": normalized_weights,
        "feature_scales": feature_scales,
        "bias": bias,
        "training_samples": len(rows),
        "positive_samples": positive_count,
        "negative_samples": negative_count,
        "feature_stats": feature_stats,
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
        "positive_samples": positive_count,
        "negative_samples": negative_count,
    }

    metadata_path = Path(args.metadata_out)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print("Signature ML model training snapshot:")
    print(f"- model version: {args.model_version}")
    print(f"- features: {len(features)}")
    print(f"- training samples: {len(rows)}")
    print(f"- positive samples: {positive_count}")
    print(f"- negative samples: {negative_count}")
    print(f"- model sha256: {model_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
