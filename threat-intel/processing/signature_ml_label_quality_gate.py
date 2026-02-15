#!/usr/bin/env python3
"""Validate signature-ML label quality and adjudication readiness."""

from __future__ import annotations

import argparse
import json
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


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
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
        raise FileNotFoundError(f"missing signals dataset: {path}")

    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        payload = json.loads(raw)
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    idx = max(min(int(round((len(values) - 1) * pct)), len(values) - 1), 0)
    return sorted(values)[idx]


def _write_ndjson(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate signature ML adjudication/label quality")
    parser.add_argument("--signals", required=True, help="Input signal dataset NDJSON")
    parser.add_argument("--output-report", required=True, help="Output JSON report")
    parser.add_argument("--output-labels", default="", help="Optional adjudicated labels NDJSON")
    parser.add_argument("--min-adjudicated", type=int, default=320)
    parser.add_argument("--min-positive", type=int, default=50)
    parser.add_argument("--min-negative", type=int, default=120)
    parser.add_argument("--min-unique-hosts", type=int, default=40)
    parser.add_argument("--min-unique-rules", type=int, default=60)
    parser.add_argument("--max-unresolved-ratio", type=float, default=0.15)
    parser.add_argument("--max-p95-label-latency-days", type=float, default=5.0)
    parser.add_argument("--fail-on-threshold", default="0")
    return parser


def main() -> int:
    args = _parser().parse_args()
    fail_on_threshold = _parse_bool(args.fail_on_threshold)

    try:
        rows = _read_ndjson(Path(args.signals))
    except (FileNotFoundError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_label_quality_gate",
            "recorded_at_utc": _iso_utc(_now_utc()),
            "status": "fail",
            "failures": [str(err)],
        }
        Path(args.output_report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(str(err))
        return 1

    total = len(rows)
    adjudicated: list[dict[str, Any]] = []
    unresolved = 0
    positive_count = 0
    negative_count = 0
    unique_hosts: set[str] = set()
    unique_rules: set[str] = set()
    label_latencies_days: list[float] = []

    for row in rows:
        label_raw = row.get("label")
        label: int | None = None
        if isinstance(label_raw, bool):
            label = int(label_raw)
        elif isinstance(label_raw, (int, float)) and int(label_raw) in (0, 1):
            label = int(label_raw)

        if label is None:
            unresolved += 1
            continue

        observed = _parse_ts(row.get("observed_at_utc"))
        adjudicated_at = _parse_ts(row.get("adjudicated_at_utc"))
        if observed and adjudicated_at and adjudicated_at >= observed:
            label_latencies_days.append((adjudicated_at - observed).total_seconds() / 86400.0)

        host = str(row.get("host_id", "")).strip()
        rule = str(row.get("rule_id", "")).strip()
        if host:
            unique_hosts.add(host)
        if rule:
            unique_rules.add(rule)

        if label == 1:
            positive_count += 1
        else:
            negative_count += 1

        normalized = dict(row)
        normalized["label"] = label
        adjudicated.append(normalized)

    adjudicated_count = len(adjudicated)
    unresolved_ratio = (unresolved / total) if total > 0 else 1.0
    p95_latency_days = _percentile(label_latencies_days, 0.95)

    failures: list[str] = []
    if adjudicated_count < args.min_adjudicated:
        failures.append(
            f"adjudicated_count below threshold: {adjudicated_count} < {args.min_adjudicated}"
        )
    if positive_count < args.min_positive:
        failures.append(f"positive_count below threshold: {positive_count} < {args.min_positive}")
    if negative_count < args.min_negative:
        failures.append(f"negative_count below threshold: {negative_count} < {args.min_negative}")
    if len(unique_hosts) < args.min_unique_hosts:
        failures.append(
            f"unique_hosts below threshold: {len(unique_hosts)} < {args.min_unique_hosts}"
        )
    if len(unique_rules) < args.min_unique_rules:
        failures.append(
            f"unique_rules below threshold: {len(unique_rules)} < {args.min_unique_rules}"
        )
    if unresolved_ratio > args.max_unresolved_ratio:
        failures.append(
            f"unresolved_ratio above threshold: {unresolved_ratio:.4f} > {args.max_unresolved_ratio:.4f}"
        )
    if p95_latency_days > args.max_p95_label_latency_days:
        failures.append(
            "p95_label_latency_days above threshold: "
            f"{p95_latency_days:.4f} > {args.max_p95_label_latency_days:.4f}"
        )

    if failures and fail_on_threshold:
        status = "fail"
    elif failures:
        status = "shadow_alert"
    else:
        status = "pass"

    report = {
        "suite": "signature_ml_label_quality_gate",
        "recorded_at_utc": _iso_utc(_now_utc()),
        "status": status,
        "mode": "enforced" if fail_on_threshold else "shadow",
        "thresholds": {
            "min_adjudicated": args.min_adjudicated,
            "min_positive": args.min_positive,
            "min_negative": args.min_negative,
            "min_unique_hosts": args.min_unique_hosts,
            "min_unique_rules": args.min_unique_rules,
            "max_unresolved_ratio": args.max_unresolved_ratio,
            "max_p95_label_latency_days": args.max_p95_label_latency_days,
            "fail_on_threshold": fail_on_threshold,
        },
        "measured": {
            "total_count": total,
            "adjudicated_count": adjudicated_count,
            "unresolved_count": unresolved,
            "positive_count": positive_count,
            "negative_count": negative_count,
            "unresolved_ratio": round(unresolved_ratio, 4),
            "unique_hosts": len(unique_hosts),
            "unique_rules": len(unique_rules),
            "p95_label_latency_days": round(p95_latency_days, 4),
        },
        "failures": failures,
    }

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.output_labels:
        _write_ndjson(Path(args.output_labels), adjudicated)

    print("Signature ML label quality snapshot:")
    print(f"- status: {status}")
    print(f"- adjudicated: {adjudicated_count}")
    print(f"- unresolved ratio: {unresolved_ratio:.4f}")
    print(f"- p95 label latency days: {p95_latency_days:.4f}")
    if failures:
        print("\nSignature ML label quality alerts:")
        for failure in failures:
            print(f"- {failure}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
