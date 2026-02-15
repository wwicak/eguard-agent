#!/usr/bin/env python3
"""Validate signature-ML offline-eval trend history and regression streaks."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALERT_STATUSES = {"shadow_alert", "fail"}
PASS_STATUSES = {"pass", "pass_no_baseline"}


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def _load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"missing offline eval trend NDJSON: {path}")

    entries: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _metric(entry: dict[str, Any], key: str) -> float | None:
    if key not in entry:
        return None
    return _as_float(entry.get(key), 0.0)


def _consecutive_alerts(entries: list[dict[str, Any]]) -> int:
    streak = 0
    for entry in reversed(entries):
        status = str(entry.get("status", "")).strip().lower()
        if status in ALERT_STATUSES:
            streak += 1
            continue
        break
    return streak


def _window_pass_rate(entries: list[dict[str, Any]], window_size: int) -> float | None:
    if not entries:
        return None
    window = entries[-max(window_size, 1) :]
    if not window:
        return None
    pass_count = sum(1 for entry in window if str(entry.get("status", "")).strip().lower() in PASS_STATUSES)
    return pass_count / len(window)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate signature ML offline eval trend regressions")
    parser.add_argument("--trend", required=True, help="signature-ml-offline-eval-trend.ndjson")
    parser.add_argument("--output", required=True, help="output report JSON")
    parser.add_argument("--max-pr-auc-drop", type=float, default=0.15)
    parser.add_argument("--max-roc-auc-drop", type=float, default=0.15)
    parser.add_argument("--max-brier-increase", type=float, default=0.08)
    parser.add_argument("--max-ece-increase", type=float, default=0.10)
    parser.add_argument("--max-threshold-drift", type=float, default=0.25)
    parser.add_argument("--max-consecutive-alerts", type=int, default=3)
    parser.add_argument("--window-size", type=int, default=8)
    parser.add_argument("--min-window-pass-rate", type=float, default=0.60)
    parser.add_argument("--fail-on-regression", default="0")
    return parser


def main() -> int:
    args = _parser().parse_args()
    fail_on_regression = _parse_bool(args.fail_on_regression)

    try:
        entries = _load_ndjson(Path(args.trend))
    except (FileNotFoundError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_offline_eval_trend_gate",
            "recorded_at_utc": _now_utc(),
            "status": "fail",
            "failures": [str(err)],
        }
        _write_json(Path(args.output), report)
        print(str(err))
        return 1

    if not entries:
        report = {
            "suite": "signature_ml_offline_eval_trend_gate",
            "recorded_at_utc": _now_utc(),
            "status": "fail",
            "failures": ["offline eval trend dataset is empty"],
        }
        _write_json(Path(args.output), report)
        print("offline eval trend dataset is empty")
        return 1

    current = entries[-1]
    previous = entries[-2] if len(entries) >= 2 else None
    current_status = str(current.get("status", "")).strip().lower() or "unknown"
    previous_status = str(previous.get("status", "")).strip().lower() if previous else None

    regressions: list[str] = []
    if current_status in ALERT_STATUSES:
        regressions.append(f"current offline eval status is alert: {current_status}")

    deltas: dict[str, float | None] = {
        "pr_auc_drop": None,
        "roc_auc_drop": None,
        "brier_increase": None,
        "ece_increase": None,
        "threshold_drift": None,
    }
    if previous is not None:
        current_pr_auc = _metric(current, "pr_auc")
        previous_pr_auc = _metric(previous, "pr_auc")
        current_roc_auc = _metric(current, "roc_auc")
        previous_roc_auc = _metric(previous, "roc_auc")
        current_brier = _metric(current, "brier_score")
        previous_brier = _metric(previous, "brier_score")
        current_ece = _metric(current, "ece")
        previous_ece = _metric(previous, "ece")
        current_threshold = _metric(current, "operating_threshold")
        previous_threshold = _metric(previous, "operating_threshold")

        if current_pr_auc is not None and previous_pr_auc is not None:
            pr_auc_drop = round(previous_pr_auc - current_pr_auc, 6)
            deltas["pr_auc_drop"] = pr_auc_drop
            if pr_auc_drop > args.max_pr_auc_drop:
                regressions.append(
                    f"pr_auc drop too high: {pr_auc_drop:.6f} > {args.max_pr_auc_drop:.6f}"
                )

        if current_roc_auc is not None and previous_roc_auc is not None:
            roc_auc_drop = round(previous_roc_auc - current_roc_auc, 6)
            deltas["roc_auc_drop"] = roc_auc_drop
            if roc_auc_drop > args.max_roc_auc_drop:
                regressions.append(
                    f"roc_auc drop too high: {roc_auc_drop:.6f} > {args.max_roc_auc_drop:.6f}"
                )

        if current_brier is not None and previous_brier is not None:
            brier_increase = round(current_brier - previous_brier, 6)
            deltas["brier_increase"] = brier_increase
            if brier_increase > args.max_brier_increase:
                regressions.append(
                    "brier_score increase too high: "
                    f"{brier_increase:.6f} > {args.max_brier_increase:.6f}"
                )

        if current_ece is not None and previous_ece is not None:
            ece_increase = round(current_ece - previous_ece, 6)
            deltas["ece_increase"] = ece_increase
            if ece_increase > args.max_ece_increase:
                regressions.append(
                    f"ece increase too high: {ece_increase:.6f} > {args.max_ece_increase:.6f}"
                )

        if current_threshold is not None and previous_threshold is not None:
            threshold_drift = round(abs(current_threshold - previous_threshold), 6)
            deltas["threshold_drift"] = threshold_drift
            if threshold_drift > args.max_threshold_drift:
                regressions.append(
                    "operating threshold drift too high: "
                    f"{threshold_drift:.6f} > {args.max_threshold_drift:.6f}"
                )

    consecutive_alerts = _consecutive_alerts(entries)
    if consecutive_alerts > args.max_consecutive_alerts:
        regressions.append(
            "consecutive offline-eval alerts exceeded max: "
            f"{consecutive_alerts} > {args.max_consecutive_alerts}"
        )

    pass_rate = _window_pass_rate(entries, args.window_size)
    if pass_rate is not None and len(entries) >= max(args.window_size, 1):
        if pass_rate < args.min_window_pass_rate:
            regressions.append(
                f"window pass rate below threshold: {pass_rate:.6f} < {args.min_window_pass_rate:.6f}"
            )

    if len(entries) == 1:
        history_status = "no_baseline"
        if regressions and fail_on_regression:
            status = "fail"
        elif regressions:
            status = "shadow_alert"
        else:
            status = "pass_no_baseline"
    elif regressions and fail_on_regression:
        history_status = "baseline_available"
        status = "fail"
    elif regressions:
        history_status = "baseline_available"
        status = "shadow_alert"
    else:
        history_status = "baseline_available"
        status = "pass"

    report = {
        "suite": "signature_ml_offline_eval_trend_gate",
        "recorded_at_utc": _now_utc(),
        "status": status,
        "history_status": history_status,
        "thresholds": {
            "max_pr_auc_drop": args.max_pr_auc_drop,
            "max_roc_auc_drop": args.max_roc_auc_drop,
            "max_brier_increase": args.max_brier_increase,
            "max_ece_increase": args.max_ece_increase,
            "max_threshold_drift": args.max_threshold_drift,
            "max_consecutive_alerts": args.max_consecutive_alerts,
            "window_size": args.window_size,
            "min_window_pass_rate": args.min_window_pass_rate,
            "fail_on_regression": fail_on_regression,
        },
        "current": {
            "status": current_status,
            "precision": _metric(current, "precision"),
            "recall": _metric(current, "recall"),
            "pr_auc": _metric(current, "pr_auc"),
            "roc_auc": _metric(current, "roc_auc"),
            "brier_score": _metric(current, "brier_score"),
            "ece": _metric(current, "ece"),
            "operating_threshold": _metric(current, "operating_threshold"),
            "operating_threshold_strategy": str(current.get("operating_threshold_strategy", "")).strip()
            or "unknown",
        },
        "previous": {
            "status": previous_status,
            "precision": _metric(previous, "precision") if previous else None,
            "recall": _metric(previous, "recall") if previous else None,
            "pr_auc": _metric(previous, "pr_auc") if previous else None,
            "roc_auc": _metric(previous, "roc_auc") if previous else None,
            "brier_score": _metric(previous, "brier_score") if previous else None,
            "ece": _metric(previous, "ece") if previous else None,
            "operating_threshold": _metric(previous, "operating_threshold") if previous else None,
        },
        "deltas": deltas,
        "alerts": {
            "entry_count": len(entries),
            "consecutive_alerts": consecutive_alerts,
            "window_pass_rate": round(pass_rate, 6) if pass_rate is not None else None,
            "regression_count": len(regressions),
        },
        "regressions": regressions,
    }

    _write_json(Path(args.output), report)

    print("Signature ML offline eval trend snapshot:")
    print(f"- status: {status}")
    print(f"- history status: {history_status}")
    print(f"- trend entries: {len(entries)}")
    print(f"- consecutive alerts: {consecutive_alerts}")
    print(f"- window pass rate: {round(pass_rate, 6) if pass_rate is not None else 'n/a'}")

    if regressions:
        print("\nSignature ML offline eval trend alerts:")
        for regression in regressions:
            print(f"- {regression}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
