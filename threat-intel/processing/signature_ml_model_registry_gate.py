#!/usr/bin/env python3
"""Validate signature-ML model registry entry and provenance contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso_utc(raw: datetime) -> str:
    return raw.isoformat().replace("+00:00", "Z")


def _load_json_required(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"missing {label}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _verify_signature(model: Path, signature: Path, public_key: Path) -> tuple[bool, str]:
    verify_script = Path(__file__).with_name("ed25519_verify.py")
    cmd = [
        sys.executable,
        str(verify_script),
        "--input",
        str(model),
        "--signature",
        str(signature),
        "--public-key-file",
        str(public_key),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, "ok"
    detail = (result.stderr.strip() or result.stdout.strip() or "verification failed").strip()
    return False, detail


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate signature ML model artifact provenance and registry constraints"
    )
    parser.add_argument("--model-artifact", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--offline-eval", required=True)
    parser.add_argument("--offline-eval-trend-report", default="")
    parser.add_argument("--feature-schema", required=True)
    parser.add_argument("--labels-report", required=True)
    parser.add_argument("--signature-file", default="")
    parser.add_argument("--public-key-file", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-pr-auc", type=float, default=0.82)
    parser.add_argument("--min-roc-auc", type=float, default=0.82)
    parser.add_argument("--require-signed-model", default="1")
    parser.add_argument("--verify-signature", default="1")
    parser.add_argument("--require-offline-eval-trend-pass", default="0")
    parser.add_argument("--fail-on-threshold", default="1")
    return parser


def main() -> int:
    args = _parser().parse_args()
    require_signed_model = _parse_bool(args.require_signed_model)
    verify_signature = _parse_bool(args.verify_signature)
    require_offline_eval_trend_pass = _parse_bool(args.require_offline_eval_trend_pass)
    fail_on_threshold = _parse_bool(args.fail_on_threshold)

    model_path = Path(args.model_artifact)
    metadata_path = Path(args.metadata)
    offline_eval_path = Path(args.offline_eval)
    offline_eval_trend_report_path = (
        Path(args.offline_eval_trend_report) if args.offline_eval_trend_report else None
    )
    feature_schema_path = Path(args.feature_schema)
    labels_report_path = Path(args.labels_report)
    signature_path = Path(args.signature_file) if args.signature_file else None
    public_key_path = Path(args.public_key_file) if args.public_key_file else None

    try:
        metadata = _load_json_required(metadata_path, "model metadata")
        offline_eval = _load_json_required(offline_eval_path, "offline eval report")
        feature_schema = _load_json_required(feature_schema_path, "feature schema")
        labels_report = _load_json_required(labels_report_path, "labels report")
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_model_registry_gate",
            "recorded_at_utc": _iso_utc(_now_utc()),
            "status": "fail",
            "failures": [str(err)],
        }
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(str(err))
        return 1

    failures: list[str] = []

    if not model_path.is_file():
        failures.append(f"missing model artifact: {model_path}")
    else:
        model_sha = _sha256_file(model_path)
        metadata_model_sha = str(metadata.get("model_sha256", "")).strip().lower()
        if metadata_model_sha and metadata_model_sha != model_sha:
            failures.append(
                f"metadata model_sha256 mismatch: metadata={metadata_model_sha} actual={model_sha}"
            )

    if not str(metadata.get("model_version", "")).strip():
        failures.append("metadata missing model_version")

    offline_metrics = offline_eval.get("metrics", {})
    if not isinstance(offline_metrics, dict):
        offline_metrics = {}
    pr_auc = _as_float(offline_metrics.get("pr_auc"), 0.0)
    roc_auc = _as_float(offline_metrics.get("roc_auc"), 0.0)
    if pr_auc < args.min_pr_auc:
        failures.append(f"offline eval pr_auc below threshold: {pr_auc:.6f} < {args.min_pr_auc:.6f}")
    if roc_auc < args.min_roc_auc:
        failures.append(f"offline eval roc_auc below threshold: {roc_auc:.6f} < {args.min_roc_auc:.6f}")

    labels_status = str(labels_report.get("status", "")).strip().lower()
    if labels_status not in {"pass", "pass_no_baseline"}:
        failures.append(f"labels report not healthy: status={labels_status or 'unknown'}")

    schema_sha = _sha256_file(feature_schema_path)
    if str(metadata.get("feature_schema_sha256", "")).strip().lower() not in {"", schema_sha}:
        failures.append("metadata feature_schema_sha256 mismatch")

    labels_sha = _sha256_file(labels_report_path)
    if str(metadata.get("labels_report_sha256", "")).strip().lower() not in {"", labels_sha}:
        failures.append("metadata labels_report_sha256 mismatch")

    offline_eval_trend_report = None
    if offline_eval_trend_report_path is not None:
        try:
            offline_eval_trend_report = _load_json_required(
                offline_eval_trend_report_path,
                "offline eval trend report",
            )
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as err:
            failures.append(str(err))
    elif require_offline_eval_trend_pass:
        failures.append("offline eval trend report required but not provided")

    if offline_eval_trend_report is not None and require_offline_eval_trend_pass:
        trend_status = str(offline_eval_trend_report.get("status", "")).strip().lower()
        if trend_status not in {"pass", "pass_no_baseline"}:
            failures.append(
                f"offline eval trend report not healthy: status={trend_status or 'unknown'}"
            )

    signature_verified = None
    signature_detail = "not_checked"
    if require_signed_model:
        if signature_path is None or not signature_path.is_file():
            failures.append("signed model required but signature file missing")
        elif signature_path.stat().st_size <= 0:
            failures.append("signed model required but signature file is empty")

    if verify_signature and signature_path is not None and public_key_path is not None:
        if not public_key_path.is_file():
            failures.append(f"public key file missing for signature verification: {public_key_path}")
        elif model_path.is_file() and signature_path.is_file():
            signature_verified, signature_detail = _verify_signature(
                model_path,
                signature_path,
                public_key_path,
            )
            if not signature_verified:
                failures.append(f"model signature verification failed: {signature_detail}")

    if failures and fail_on_threshold:
        status = "fail"
    elif failures:
        status = "shadow_alert"
    else:
        status = "pass"

    report = {
        "suite": "signature_ml_model_registry_gate",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "status": status,
        "mode": "enforced" if fail_on_threshold else "shadow",
        "thresholds": {
            "min_pr_auc": args.min_pr_auc,
            "min_roc_auc": args.min_roc_auc,
            "require_signed_model": require_signed_model,
            "verify_signature": verify_signature,
            "require_offline_eval_trend_pass": require_offline_eval_trend_pass,
            "fail_on_threshold": fail_on_threshold,
        },
        "provenance": {
            "model_artifact": str(model_path),
            "metadata": str(metadata_path),
            "offline_eval": str(offline_eval_path),
            "offline_eval_trend_report": str(offline_eval_trend_report_path)
            if offline_eval_trend_report_path is not None
            else None,
            "feature_schema": str(feature_schema_path),
            "labels_report": str(labels_report_path),
            "signature_file": str(signature_path) if signature_path is not None else None,
            "public_key_file": str(public_key_path) if public_key_path is not None else None,
            "signature_verified": signature_verified,
            "signature_detail": signature_detail,
        },
        "offline_metrics": {
            "pr_auc": round(pr_auc, 6),
            "roc_auc": round(roc_auc, 6),
        },
        "model_version": str(metadata.get("model_version", "")).strip(),
        "failures": failures,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Signature ML model registry snapshot:")
    print(f"- status: {status}")
    print(f"- model version: {report['model_version'] or 'unknown'}")
    print(f"- pr_auc: {pr_auc:.6f}")
    print(f"- roc_auc: {roc_auc:.6f}")
    print(f"- signature verified: {signature_verified}")
    if failures:
        print("\nSignature ML model registry alerts:")
        for failure in failures:
            print(f"- {failure}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
