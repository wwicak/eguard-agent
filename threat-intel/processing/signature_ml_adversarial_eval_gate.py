#!/usr/bin/env python3
"""Adversarial robustness gate for signature-ML models.

Applies lightweight evasion-style feature perturbations to positive samples and
measures recall drop relative to baseline predictions.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from signature_ml_offline_eval_gate import _as_float, _as_int, _clamp, _extract_model, _score_row


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _iso_utc(raw: datetime) -> str:
    return raw.isoformat().replace("+00:00", "Z")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"missing dataset: {path}")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = line.strip()
        if not payload:
            continue
        decoded = json.loads(payload)
        if isinstance(decoded, dict):
            rows.append(decoded)
    return rows


def _binary_recall(labels: list[int], scores: list[float], threshold: float) -> float:
    tp = 0
    fn = 0
    for label, score in zip(labels, scores):
        if label != 1:
            continue
        if score >= threshold:
            tp += 1
        else:
            fn += 1
    total = tp + fn
    if total <= 0:
        return 0.0
    return tp / total


def _mutate_row(row: dict[str, Any], transform: str) -> dict[str, Any]:
    out = dict(row)

    def setf(key: str, value: float) -> None:
        out[key] = _clamp(value, 0.0, 1.0)

    if transform == "cmdline_obfuscation":
        setf("z1_ioc_hit", _as_float(out.get("z1_ioc_hit"), 0.0) * 0.65)
        setf("string_sig_count", _as_float(out.get("string_sig_count"), 0.0) * 0.70)
        setf("prefilter_hit", _as_float(out.get("prefilter_hit"), 0.0) * 0.70)
        setf("cmdline_renyi_h2", _as_float(out.get("cmdline_renyi_h2"), 0.0) * 0.85)
        setf("cmdline_entropy_gap", _as_float(out.get("cmdline_entropy_gap"), 0.0) * 0.80)
        return out

    if transform == "process_name_masquerade":
        setf("rare_parent_child_pair", _as_float(out.get("rare_parent_child_pair"), 0.0) * 0.65)
        setf("parent_cmdline_hash_risk", _as_float(out.get("parent_cmdline_hash_risk"), 0.0) * 0.70)
        setf("process_tree_depth_norm", _as_float(out.get("process_tree_depth_norm"), 0.0) * 0.85)
        setf("tree_network_interaction", _as_float(out.get("tree_network_interaction"), 0.0) * 0.75)
        return out

    if transform == "timestomp_file_churn":
        setf("sensitive_path_write_velocity", _as_float(out.get("sensitive_path_write_velocity"), 0.0) * 0.70)
        setf("rename_churn_norm", _as_float(out.get("rename_churn_norm"), 0.0) * 0.60)
        setf("file_behavior_interaction", _as_float(out.get("file_behavior_interaction"), 0.0) * 0.70)
        setf("behavioral_alarm_count", _as_float(out.get("behavioral_alarm_count"), 0.0) * 0.80)
        return out

    return out


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run adversarial robustness evaluation for signature ML")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=-1.0, help="Override threshold; default model threshold")
    parser.add_argument("--max-recall-drop", type=float, default=0.10)
    parser.add_argument("--max-pr-auc-drop", type=float, default=0.12)
    parser.add_argument("--min-positive-samples", type=int, default=120)
    parser.add_argument("--fail-on-threshold", default="1")
    return parser


def main() -> int:
    args = _parser().parse_args()
    fail_on_threshold = _parse_bool(args.fail_on_threshold)

    rows = _read_ndjson(Path(args.dataset))
    model_payload = json.loads(Path(args.model).read_text(encoding="utf-8"))
    model_runtime = _extract_model(model_payload if isinstance(model_payload, dict) else None)

    threshold = _as_float(args.threshold, -1.0)
    if threshold < 0.0:
        threshold = _as_float(model_payload.get("threshold"), 0.5) if isinstance(model_payload, dict) else 0.5
    threshold = _clamp(threshold, 0.0, 1.0)

    valid = [row for row in rows if _as_int(row.get("label"), -1) in (0, 1)]
    positives = [row for row in valid if _as_int(row.get("label"), 0) == 1]

    failures: list[str] = []
    if len(positives) < max(args.min_positive_samples, 1):
        failures.append(
            f"insufficient positive samples for adversarial eval: {len(positives)} < {max(args.min_positive_samples, 1)}"
        )

    labels = [_as_int(row.get("label"), 0) for row in valid]
    baseline_scores = [_score_row(row, model_runtime) for row in valid]
    baseline_recall = _binary_recall(labels, baseline_scores, threshold)

    transforms = [
        "cmdline_obfuscation",
        "process_name_masquerade",
        "timestomp_file_churn",
    ]

    scenarios: list[dict[str, Any]] = []
    worst_recall_drop = 0.0

    for name in transforms:
        transformed_rows = [_mutate_row(row, name) if _as_int(row.get("label"), 0) == 1 else dict(row) for row in valid]
        transformed_scores = [_score_row(row, model_runtime) for row in transformed_rows]
        transformed_recall = _binary_recall(labels, transformed_scores, threshold)
        recall_drop = _clamp(baseline_recall - transformed_recall, 0.0, 1.0)
        worst_recall_drop = max(worst_recall_drop, recall_drop)

        scenarios.append(
            {
                "name": name,
                "baseline_recall": round(baseline_recall, 6),
                "transformed_recall": round(transformed_recall, 6),
                "recall_drop": round(recall_drop, 6),
            }
        )

    if worst_recall_drop > max(args.max_recall_drop, 0.0):
        failures.append(
            f"adversarial recall drop exceeded threshold: {worst_recall_drop:.6f} > {max(args.max_recall_drop, 0.0):.6f}"
        )

    # Placeholder parity metric for PR-AUC drop budget (kept deterministic for gate contract).
    pr_auc_drop = round(min(worst_recall_drop * 0.8, 1.0), 6)
    if pr_auc_drop > max(args.max_pr_auc_drop, 0.0):
        failures.append(
            f"adversarial pr_auc_drop exceeded threshold: {pr_auc_drop:.6f} > {max(args.max_pr_auc_drop, 0.0):.6f}"
        )

    status = "pass"
    if failures and fail_on_threshold:
        status = "fail"
    elif failures:
        status = "shadow_alert"

    report = {
        "suite": "signature_ml_adversarial_eval_gate",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "status": status,
        "mode": "enforced" if fail_on_threshold else "shadow",
        "thresholds": {
            "max_recall_drop": max(args.max_recall_drop, 0.0),
            "max_pr_auc_drop": max(args.max_pr_auc_drop, 0.0),
            "min_positive_samples": max(args.min_positive_samples, 1),
        },
        "dataset": {
            "rows": len(valid),
            "positive_rows": len(positives),
        },
        "model_family": model_runtime.get("family"),
        "operating_threshold": round(threshold, 6),
        "worst_recall_drop": round(worst_recall_drop, 6),
        "pr_auc_drop_proxy": pr_auc_drop,
        "scenarios": scenarios,
        "failures": failures,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Signature ML adversarial eval snapshot:")
    print(f"- status: {status}")
    print(f"- model_family: {report['model_family']}")
    print(f"- worst_recall_drop: {worst_recall_drop:.6f}")
    print(f"- pr_auc_drop_proxy: {pr_auc_drop:.6f}")
    if failures:
        print("\nAdversarial eval alerts:")
        for failure in failures:
            print(f"- {failure}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
