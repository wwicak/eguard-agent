#!/usr/bin/env python3
"""Build deterministic signature-ML training corpus from bundle artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
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


def _load_json(path: Path, label: str, *, required: bool) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"missing {label}: {path}")
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _rand01(seed: str) -> float:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], "big")
    return value / float(2**64 - 1)


def _score_to_probability(linear: float) -> float:
    return 1.0 / (1.0 + math.exp(-linear))


def _base_component_score(readiness: dict[str, Any], component: str, fallback: float) -> float:
    components = readiness.get("components", {})
    if not isinstance(components, dict):
        return fallback
    payload = components.get(component, {})
    if not isinstance(payload, dict) or not payload.get("available"):
        return fallback
    return _clamp(_as_float(payload.get("score"), fallback), 0.0, 100.0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build deterministic synthetic signature-ML corpus from threat-intel bundle reports"
    )
    parser.add_argument("--manifest", required=True, help="bundle/manifest.json")
    parser.add_argument("--coverage", required=True, help="bundle/coverage-metrics.json")
    parser.add_argument("--readiness", default="", help="signature-ml-readiness.json")
    parser.add_argument("--attack-coverage", default="", help="bundle/attack-coverage.json")
    parser.add_argument("--critical-gate", default="", help="bundle/attack-critical-technique-gate.json")
    parser.add_argument("--output-signals", required=True, help="Output NDJSON path")
    parser.add_argument("--output-summary", default="", help="Optional output summary JSON path")
    parser.add_argument("--sample-count", type=int, default=720)
    parser.add_argument("--window-days", type=int, default=45)
    parser.add_argument("--host-pool", type=int, default=160)
    parser.add_argument("--rule-pool", type=int, default=220)
    parser.add_argument("--unresolved-ratio", type=float, default=0.08)
    parser.add_argument("--label-noise", type=float, default=0.03)
    return parser


def main() -> int:
    args = _parser().parse_args()

    manifest = _load_json(Path(args.manifest), "bundle manifest", required=True)
    coverage = _load_json(Path(args.coverage), "coverage report", required=True)
    readiness = (
        _load_json(Path(args.readiness), "signature ML readiness report", required=False)
        if args.readiness
        else {}
    )
    attack_coverage = (
        _load_json(Path(args.attack_coverage), "ATT&CK coverage report", required=False)
        if args.attack_coverage
        else {}
    )
    critical_gate = (
        _load_json(Path(args.critical_gate), "critical ATT&CK gate report", required=False)
        if args.critical_gate
        else {}
    )

    sample_count = max(args.sample_count, 50)
    window_days = max(args.window_days, 7)
    host_pool = max(args.host_pool, 8)
    rule_pool = max(args.rule_pool, 12)
    unresolved_ratio = _clamp(args.unresolved_ratio, 0.0, 0.80)
    label_noise = _clamp(args.label_noise, 0.0, 0.40)

    measured = coverage.get("measured", {})
    if not isinstance(measured, dict):
        measured = {}

    signature_total = max(_as_int(measured.get("signature_total"), 1), 1)
    database_total = max(_as_int(measured.get("database_total"), signature_total), signature_total)
    cve_count = max(_as_int(measured.get("cve_count"), 0), 0)

    attack_measured = attack_coverage.get("measured", {})
    if not isinstance(attack_measured, dict):
        attack_measured = {}
    attack_techniques = max(_as_int(attack_measured.get("total_techniques"), 0), 0)
    attack_tactics = max(_as_int(attack_measured.get("total_tactics"), 0), 0)

    critical_measured = critical_gate.get("measured", {})
    if not isinstance(critical_measured, dict):
        critical_measured = {}
    critical_ratio = _clamp(_as_float(critical_measured.get("covered_ratio"), 0.82), 0.0, 1.0)

    final_score = _clamp(
        _as_float((readiness.get("scores", {}) if isinstance(readiness.get("scores", {}), dict) else {}).get("final_score"), 82.0),
        0.0,
        100.0,
    )
    source_diversity_score = _base_component_score(readiness, "source_diversity", 78.0)
    attack_surface_score = _base_component_score(readiness, "attack_surface", 76.0)
    critical_resilience_score = _base_component_score(readiness, "critical_resilience", 79.0)

    version_seed = str(manifest.get("version", "unknown"))
    now = _now_utc()
    span = timedelta(days=window_days)
    start = now - span
    step_seconds = max(int(span.total_seconds() / max(sample_count - 1, 1)), 60)

    out_path = Path(args.output_signals)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []
    adjudicated_count = 0
    positive_count = 0
    negative_count = 0
    unresolved_count = 0
    readiness_norm = final_score / 100.0

    for idx in range(sample_count):
        seed_prefix = f"{version_seed}|{idx}"
        observed_at = start + timedelta(seconds=step_seconds * idx)

        host_idx = 1 + int(_rand01(seed_prefix + "|host") * host_pool)
        rule_idx = 1 + int(_rand01(seed_prefix + "|rule") * rule_pool)
        host_id = f"host-{host_idx:03d}"
        rule_id = f"sig-rule-{rule_idx:04d}"

        severity = 1 + int(_rand01(seed_prefix + "|severity") * 5)
        source_jitter = (_rand01(seed_prefix + "|source_jitter") - 0.5) * 16.0
        attack_jitter = (_rand01(seed_prefix + "|attack_jitter") - 0.5) * 18.0
        critical_jitter = (_rand01(seed_prefix + "|critical_jitter") - 0.5) * 14.0

        source_div_score = _clamp(source_diversity_score + source_jitter, 0.0, 100.0)
        attack_surface = _clamp(
            attack_surface_score + attack_jitter + (attack_techniques / 200.0) * 4.0 + attack_tactics,
            0.0,
            100.0,
        )
        critical_resilience = _clamp(
            critical_resilience_score + critical_jitter + critical_ratio * 4.0,
            0.0,
            100.0,
        )

        feature_signature_norm = _clamp(signature_total / 8000.0, 0.0, 1.0)
        feature_database_norm = _clamp(database_total / 30000.0, 0.0, 1.0)
        source_norm = source_div_score / 100.0
        attack_norm = attack_surface / 100.0
        critical_norm = critical_resilience / 100.0
        noise = (_rand01(seed_prefix + "|noise") - 0.5) * 0.8

        linear = (
            -3.30
            + 0.60 * (severity / 5.0)
            + 0.75 * source_norm
            + 0.95 * attack_norm
            + 0.90 * critical_norm
            + 0.55 * feature_signature_norm
            + 0.40 * feature_database_norm
            + 0.35 * readiness_norm
            + noise
        )
        model_score = _clamp(_score_to_probability(linear), 0.001, 0.999)

        raw_rows.append(
            {
                "sample_id": f"sample-{idx + 1:06d}",
                "observed_at": observed_at,
                "seed_prefix": seed_prefix,
                "host_id": host_id,
                "rule_id": rule_id,
                "rule_severity": severity,
                "signature_total": signature_total,
                "database_total": database_total,
                "source_diversity_score": round(source_div_score, 4),
                "attack_surface_score": round(attack_surface, 4),
                "critical_resilience_score": round(critical_resilience, 4),
                "cve_count": cve_count,
                "model_score": round(model_score, 6),
            }
        )

    target_positive_ratio = _clamp(0.23 + (0.80 - readiness_norm) * 0.18, 0.18, 0.34)
    sorted_scores = sorted(float(row.get("model_score", 0.0)) for row in raw_rows)
    cutoff_index = int((1.0 - target_positive_ratio) * max(len(sorted_scores) - 1, 0))
    cutoff_index = max(min(cutoff_index, max(len(sorted_scores) - 1, 0)), 0)
    score_cutoff = sorted_scores[cutoff_index] if sorted_scores else 0.5

    for row in raw_rows:
        seed_prefix = str(row.get("seed_prefix", ""))
        observed_at = row.get("observed_at", now)
        if not isinstance(observed_at, datetime):
            observed_at = now

        label = 1 if float(row.get("model_score", 0.0)) >= score_cutoff else 0
        if _rand01(seed_prefix + "|flip") < label_noise:
            label = 1 - label

        adjudicated = _rand01(seed_prefix + "|adjudicated") >= unresolved_ratio
        if adjudicated:
            delay_hours = int(_rand01(seed_prefix + "|delay") * 120)
            adjudicated_at = observed_at + timedelta(hours=delay_hours)
            adjudicated_count += 1
            if label == 1:
                positive_count += 1
            else:
                negative_count += 1
            encoded_label: int | None = label
            adjudicated_at_raw = _iso_utc(adjudicated_at)
        else:
            unresolved_count += 1
            encoded_label = None
            adjudicated_at_raw = ""

        rows.append(
            {
                "sample_id": row.get("sample_id"),
                "observed_at_utc": _iso_utc(observed_at),
                "adjudicated_at_utc": adjudicated_at_raw,
                "host_id": row.get("host_id"),
                "rule_id": row.get("rule_id"),
                "rule_severity": row.get("rule_severity"),
                "signature_total": row.get("signature_total"),
                "database_total": row.get("database_total"),
                "source_diversity_score": row.get("source_diversity_score"),
                "attack_surface_score": row.get("attack_surface_score"),
                "critical_resilience_score": row.get("critical_resilience_score"),
                "cve_count": row.get("cve_count"),
                "model_score": row.get("model_score"),
                "label": encoded_label,
                "label_source": "synthetic_ci",
            }
        )

    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "suite": "signature_ml_build_training_corpus",
        "status": "pass",
        "dataset_mode": "synthetic_ci",
        "recorded_at_utc": _iso_utc(now),
        "version_seed": version_seed,
        "measured": {
            "sample_count": sample_count,
            "adjudicated_count": adjudicated_count,
            "unresolved_count": unresolved_count,
            "positive_count": positive_count,
            "negative_count": negative_count,
            "adjudicated_ratio": round(adjudicated_count / sample_count, 4),
            "positive_ratio": round(
                positive_count / max(adjudicated_count, 1),
                4,
            ),
            "target_positive_ratio": round(target_positive_ratio, 4),
            "score_cutoff": round(score_cutoff, 6),
            "window_days": window_days,
            "host_pool": host_pool,
            "rule_pool": rule_pool,
        },
        "inputs": {
            "manifest": str(args.manifest),
            "coverage": str(args.coverage),
            "readiness": str(args.readiness) if args.readiness else None,
            "attack_coverage": str(args.attack_coverage) if args.attack_coverage else None,
            "critical_gate": str(args.critical_gate) if args.critical_gate else None,
        },
    }

    if args.output_summary:
        summary_path = Path(args.output_summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print("Signature ML training corpus snapshot:")
    print(f"- mode: {summary['dataset_mode']}")
    print(f"- sample count: {sample_count}")
    print(f"- adjudicated count: {adjudicated_count}")
    print(f"- unresolved count: {unresolved_count}")
    print(f"- positive count: {positive_count}")
    print(f"- negative count: {negative_count}")
    print(f"- output: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
