#!/usr/bin/env python3
"""Build and validate signature-ML feature snapshot from adjudicated labels.

The output feature schema must match the agent runtime Layer-5 features to
ensure CI-trained models are loadable without feature drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FEATURES = (
    "z1_ioc_hit",
    "z2_temporal_count",
    "z3_anomaly_high",
    "z3_anomaly_med",
    "z4_killchain_count",
    "yara_hit_count",
    "string_sig_count",
    "event_class_risk",
    "uid_is_root",
    "dst_port_risk",
    "has_command_line",
    "cmdline_length_norm",
    "prefilter_hit",
    "multi_layer_count",
    "cmdline_renyi_h2",
    "cmdline_compression",
    "cmdline_min_entropy",
    "cmdline_entropy_gap",
    "dns_entropy",
    "event_size_norm",
    "container_risk",
    "file_path_entropy",
    "file_path_depth",
    "behavioral_alarm_count",
    "z1_z2_interaction",
    "z1_z4_interaction",
    "anomaly_behavioral",
    "tree_depth_norm",       # 27: Process chain depth / 10
    "tree_breadth_norm",     # 28: Sibling count / 20
    "child_entropy",         # 29: Shannon entropy of child comm names
    "spawn_rate_norm",       # 30: Children spawned per minute / 10
    "rare_parent_child",     # 31: 1.0 if parent:child pair unseen in baseline
    "c2_beacon_mi",          # 32: Mutual information score for destination
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


def _synthetic_score(features: dict[str, float]) -> float:
    linear = (
        -2.6
        + 2.1 * features.get("z1_ioc_hit", 0.0)
        + 1.2 * features.get("z2_temporal_count", 0.0)
        + 1.4 * features.get("z4_killchain_count", 0.0)
        + 1.6 * features.get("yara_hit_count", 0.0)
        + 1.1 * features.get("string_sig_count", 0.0)
        + 0.6 * features.get("event_class_risk", 0.0)
        + 0.4 * features.get("dst_port_risk", 0.0)
        + 0.35 * features.get("cmdline_compression", 0.0)
        + 0.25 * features.get("dns_entropy", 0.0)
        + 0.2 * features.get("event_size_norm", 0.0)
        + 0.15 * features.get("multi_layer_count", 0.0)
        + 0.3 * features.get("container_risk", 0.0)
        + 0.2 * features.get("file_path_entropy", 0.0)
        + 0.15 * features.get("file_path_depth", 0.0)
        + 0.25 * features.get("behavioral_alarm_count", 0.0)
        + 0.5 * features.get("z1_z2_interaction", 0.0)
        + 0.4 * features.get("z1_z4_interaction", 0.0)
        + 0.3 * features.get("anomaly_behavioral", 0.0)
        + 0.3 * features.get("tree_depth_norm", 0.0)
        + 0.4 * features.get("tree_breadth_norm", 0.0)
        + 0.5 * features.get("child_entropy", 0.0)
        + 0.6 * features.get("spawn_rate_norm", 0.0)
        + 0.8 * features.get("rare_parent_child", 0.0)
        + 1.2 * features.get("c2_beacon_mi", 0.0)
    )
    return _clamp(1.0 / (1.0 + pow(2.718281828, -linear)), 0.001, 0.999)


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

    report: dict[str, Any] = {
        "suite": "signature_ml_feature_snapshot_gate",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "status": "pass",
        "measured": {
            "rows": len(rows),
            "unique_hosts": 0,
            "unique_rules": 0,
            "missing_feature_ratio": 1.0,
            "temporal_span_days": 0.0,
        },
        "alerts": [],
    }

    if not rows:
        report["status"] = "fail"
        report["alerts"].append("no rows in labels dataset")
        Path(args.output_report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("labels dataset empty")
        return 1

    missing_feature_count = 0
    processed = []
    unique_hosts = set()
    unique_rules = set()
    observed_at_values: list[datetime] = []

    for row in rows:
        host = str(row.get("host_id", "")).strip()
        rule = str(row.get("rule_id", "")).strip()
        if host:
            unique_hosts.add(host)
        if rule:
            unique_rules.add(rule)

        observed_at = _parse_ts(row.get("observed_at_utc"))
        if observed_at is not None:
            observed_at_values.append(observed_at)

        feature_values: dict[str, float] = {}
        for name in FEATURES:
            value_raw = row.get(name)
            if value_raw is None:
                missing_feature_count += 1
            feature_values[name] = _as_float(value_raw, 0.0)

        model_score = row.get("model_score")
        if model_score is None:
            feature_values["model_score"] = round(_synthetic_score(feature_values), 6)
        else:
            feature_values["model_score"] = round(_clamp(_as_float(model_score, 0.0), 0.001, 0.999), 6)

        processed.append(
            {
                **{
                    "sample_id": row.get("sample_id"),
                    "observed_at_utc": row.get("observed_at_utc"),
                    "adjudicated_at_utc": row.get("adjudicated_at_utc"),
                    "host_id": row.get("host_id"),
                    "rule_id": row.get("rule_id"),
                    "label": row.get("label"),
                    "label_source": row.get("label_source"),
                },
                **feature_values,
            }
        )

    row_count = len(processed)
    total_feature_cells = row_count * len(FEATURES)
    missing_feature_ratio = (
        missing_feature_count / total_feature_cells if total_feature_cells > 0 else 1.0
    )

    temporal_span_days = 0.0
    if observed_at_values:
        observed_at_values.sort()
        temporal_span_days = (
            observed_at_values[-1] - observed_at_values[0]
        ).total_seconds() / 86400.0

    report["measured"].update(
        {
            "rows": row_count,
            "unique_hosts": len(unique_hosts),
            "unique_rules": len(unique_rules),
            "missing_feature_ratio": round(missing_feature_ratio, 6),
            "temporal_span_days": round(temporal_span_days, 3),
        }
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
            "temporal_span_days below threshold: "
            f"{temporal_span_days:.3f} < {args.min_temporal_span_days:.3f}"
        )

    if failures and fail_on_threshold:
        report["status"] = "fail"
    elif failures:
        report["status"] = "shadow_alert"
    report["alerts"] = failures

    features_path = Path(args.output_features)
    _write_ndjson(features_path, processed)
    features_sha = _sha256_file(features_path)

    schema_path = Path(args.output_schema)
    schema = {
        "suite": "signature_ml_feature_schema",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "features": [*FEATURES],
        "dataset": str(features_path),
        "dataset_sha256": features_sha,
    }
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Signature ML feature snapshot:")
    print(f"- rows: {row_count}")
    print(f"- missing feature ratio: {missing_feature_ratio:.6f}")
    print(f"- temporal span days: {temporal_span_days:.3f}")
    if failures:
        print("\nSignature ML feature snapshot alerts:")
        for failure in failures:
            print(f"- {failure}")

    return 0 if (not failures or not fail_on_threshold) else 1


if __name__ == "__main__":
    raise SystemExit(main())
