#!/usr/bin/env python3
"""Build and validate signature-ML feature snapshot from adjudicated labels."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FEATURES = (
    "rule_severity",
    "signature_total",
    "database_total",
    "source_diversity_score",
    "attack_surface_score",
    "critical_resilience_score",
)


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"missing labels dataset: {path}")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        payload = json.loads(raw)
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _write_ndjson(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and validate feature snapshot for signature ML")
    parser.add_argument("--labels", required=True, help="Input adjudicated labels NDJSON")
    parser.add_argument("--output-features", required=True, help="Output features NDJSON")
    parser.add_argument("--output-schema", required=True, help="Output feature schema JSON")
    parser.add_argument("--output-report", required=True, help="Output quality report JSON")
    parser.add_argument("--min-rows", type=int, default=300)
    parser.add_argument("--min-unique-hosts", type=int, default=40)
    parser.add_argument("--min-unique-rules", type=int, default=60)
    parser.add_argument("--max-missing-feature-ratio", type=float, default=0.05)
    parser.add_argument("--min-temporal-span-days", type=float, default=14.0)
    parser.add_argument("--fail-on-threshold", default="0")
    return parser


def main() -> int:
    args = _parser().parse_args()
    fail_on_threshold = _parse_bool(args.fail_on_threshold)

    try:
        rows = _read_ndjson(Path(args.labels))
    except (FileNotFoundError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_feature_snapshot_gate",
            "recorded_at_utc": _iso_utc(_now_utc()),
            "status": "fail",
            "failures": [str(err)],
        }
        Path(args.output_report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(str(err))
        return 1

    processed: list[dict[str, Any]] = []
    unique_hosts: set[str] = set()
    unique_rules: set[str] = set()
    timestamps: list[datetime] = []
    missing_feature_count = 0

    for row in rows:
        label_raw = row.get("label")
        label_value: int | None = None
        if isinstance(label_raw, bool):
            label_value = int(label_raw)
        elif isinstance(label_raw, (int, float)):
            candidate = int(label_raw)
            if candidate in (0, 1):
                label_value = candidate

        if label_value is None:
            continue

        observed = _parse_ts(row.get("observed_at_utc"))
        if observed is None:
            continue
        timestamps.append(observed)

        host = str(row.get("host_id", "")).strip()
        rule = str(row.get("rule_id", "")).strip()
        if host:
            unique_hosts.add(host)
        if rule:
            unique_rules.add(rule)

        feature_values: dict[str, float] = {}
        for name in FEATURES:
            value_raw = row.get(name)
            if value_raw in (None, ""):
                missing_feature_count += 1
            feature_values[name] = _as_float(value_raw, 0.0)

        model_score = row.get("model_score")
        if model_score in (None, ""):
            synthetic_score = (
                0.20 * _clamp(feature_values["rule_severity"] / 5.0, 0.0, 1.0)
                + 0.15 * _clamp(feature_values["signature_total"] / 8000.0, 0.0, 1.0)
                + 0.15 * _clamp(feature_values["database_total"] / 30000.0, 0.0, 1.0)
                + 0.16 * _clamp(feature_values["source_diversity_score"] / 100.0, 0.0, 1.0)
                + 0.17 * _clamp(feature_values["attack_surface_score"] / 100.0, 0.0, 1.0)
                + 0.17 * _clamp(feature_values["critical_resilience_score"] / 100.0, 0.0, 1.0)
            )
            feature_values["model_score"] = round(_clamp(synthetic_score, 0.001, 0.999), 6)
        else:
            feature_values["model_score"] = round(_clamp(_as_float(model_score, 0.0), 0.001, 0.999), 6)

        processed.append(
            {
                "sample_id": str(row.get("sample_id", "")).strip() or f"anon-{len(processed)+1:06d}",
                "observed_at_utc": _iso_utc(observed),
                "host_id": host,
                "rule_id": rule,
                "label": label_value,
                **feature_values,
            }
        )

    row_count = len(processed)
    temporal_span_days = 0.0
    if len(timestamps) >= 2:
        temporal_span_days = (max(timestamps) - min(timestamps)).total_seconds() / 86400.0

    total_feature_cells = row_count * len(FEATURES)
    missing_feature_ratio = (
        missing_feature_count / total_feature_cells if total_feature_cells > 0 else 1.0
    )

    failures: list[str] = []
    if row_count < args.min_rows:
        failures.append(f"row_count below threshold: {row_count} < {args.min_rows}")
    if len(unique_hosts) < args.min_unique_hosts:
        failures.append(
            f"unique_hosts below threshold: {len(unique_hosts)} < {args.min_unique_hosts}"
        )
    if len(unique_rules) < args.min_unique_rules:
        failures.append(
            f"unique_rules below threshold: {len(unique_rules)} < {args.min_unique_rules}"
        )
    if missing_feature_ratio > args.max_missing_feature_ratio:
        failures.append(
            "missing_feature_ratio above threshold: "
            f"{missing_feature_ratio:.6f} > {args.max_missing_feature_ratio:.6f}"
        )
    if temporal_span_days < args.min_temporal_span_days:
        failures.append(
            f"temporal_span_days below threshold: {temporal_span_days:.4f} < {args.min_temporal_span_days:.4f}"
        )

    if failures and fail_on_threshold:
        status = "fail"
    elif failures:
        status = "shadow_alert"
    else:
        status = "pass"

    features_path = Path(args.output_features)
    _write_ndjson(features_path, processed)
    features_sha = _sha256_file(features_path)

    schema = {
        "suite": "signature_ml_feature_schema",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "version": 1,
        "row_count": row_count,
        "features": [*FEATURES],
        "label_field": "label",
        "score_field": "model_score",
        "dataset_sha256": features_sha,
    }
    schema_path = Path(args.output_schema)
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    schema_sha = _sha256_file(schema_path)

    report = {
        "suite": "signature_ml_feature_snapshot_gate",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "status": status,
        "mode": "enforced" if fail_on_threshold else "shadow",
        "thresholds": {
            "min_rows": args.min_rows,
            "min_unique_hosts": args.min_unique_hosts,
            "min_unique_rules": args.min_unique_rules,
            "max_missing_feature_ratio": args.max_missing_feature_ratio,
            "min_temporal_span_days": args.min_temporal_span_days,
            "fail_on_threshold": fail_on_threshold,
        },
        "measured": {
            "row_count": row_count,
            "unique_hosts": len(unique_hosts),
            "unique_rules": len(unique_rules),
            "missing_feature_ratio": round(missing_feature_ratio, 6),
            "temporal_span_days": round(temporal_span_days, 4),
        },
        "artifacts": {
            "features": str(features_path),
            "features_sha256": features_sha,
            "schema": str(schema_path),
            "schema_sha256": schema_sha,
        },
        "failures": failures,
    }
    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Signature ML feature snapshot:")
    print(f"- status: {status}")
    print(f"- rows: {row_count}")
    print(f"- unique hosts: {len(unique_hosts)}")
    print(f"- unique rules: {len(unique_rules)}")
    print(f"- temporal span days: {temporal_span_days:.4f}")
    if failures:
        print("\nSignature ML feature snapshot alerts:")
        for failure in failures:
            print(f"- {failure}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
