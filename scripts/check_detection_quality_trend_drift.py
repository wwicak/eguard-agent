#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys
from typing import Any, Dict, Optional


def parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_ndjson(path: pathlib.Path) -> list[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"missing trend artifact: {path}")

    entries: list[Dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid JSON in trend artifact {path} line {line_no}: {err}") from err
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def extract_metrics(entry: Dict[str, Any], label: str) -> Optional[Dict[str, float]]:
    if label == "focus":
        precision = entry.get("precision")
        recall = entry.get("recall")
        far = entry.get("false_alarm_upper_bound")
    else:
        bucket = entry.get("by_confidence_threshold", {})
        if not isinstance(bucket, dict):
            return None
        class_metrics = bucket.get(label)
        if not isinstance(class_metrics, dict):
            return None
        precision = class_metrics.get("precision")
        recall = class_metrics.get("recall")
        far = class_metrics.get("false_alarm_upper_bound")

    try:
        return {
            "precision": float(precision),
            "recall": float(recall),
            "false_alarm_upper_bound": float(far),
        }
    except (TypeError, ValueError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check detection-quality trend drift bounds from per-confidence NDJSON artifacts."
    )
    parser.add_argument("--trend-path", required=True)
    parser.add_argument("--report-path", required=True)
    parser.add_argument("--precision-drop-max", type=float, default=0.01)
    parser.add_argument("--recall-drop-max", type=float, default=0.01)
    parser.add_argument("--far-increase-max", type=float, default=0.02)
    parser.add_argument(
        "--labels",
        default="focus,definite,very_high,high",
        help="comma-separated metric labels to compare; 'focus' uses top-level measured metrics",
    )
    parser.add_argument("--fail-on-regression", default="1")

    args = parser.parse_args()

    trend_path = pathlib.Path(args.trend_path)
    report_path = pathlib.Path(args.report_path)
    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    fail_on_regression = parse_bool(args.fail_on_regression)

    report: Dict[str, Any] = {
        "suite": "detection_quality_trend_drift",
        "trend_path": str(trend_path),
        "labels": labels,
        "bounds": {
            "precision_drop_max": args.precision_drop_max,
            "recall_drop_max": args.recall_drop_max,
            "far_increase_max": args.far_increase_max,
        },
        "comparisons": {},
        "regressions": [],
        "status": "insufficient_history",
    }

    try:
        entries = parse_ndjson(trend_path)
    except Exception as err:
        report["status"] = "invalid_trend"
        report["error"] = str(err)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(str(err), file=sys.stderr)
        return 1

    report["entry_count"] = len(entries)

    if len(entries) < 2:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(
            f"detection-quality trend drift check skipped: insufficient history ({len(entries)} entry)",
            file=sys.stderr,
        )
        return 0

    def corpus_signature(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        corpus = entry.get("corpus", {})
        if not isinstance(corpus, dict) or not corpus:
            return None
        return {
            "name": corpus.get("name"),
            "scenario_count": corpus.get("scenario_count"),
            "total_events": corpus.get("total_events"),
            "malicious_events": corpus.get("malicious_events"),
        }

    current = entries[-1]
    current_sig = corpus_signature(current)
    previous = None
    previous_sig = None
    for candidate in reversed(entries[:-1]):
        candidate_sig = corpus_signature(candidate)
        if candidate_sig and current_sig and candidate_sig == current_sig:
            previous = candidate
            previous_sig = candidate_sig
            break

    report["current_recorded_at_utc"] = current.get("recorded_at_utc")
    report["current_corpus"] = current_sig

    if previous is None:
        report["status"] = "baseline_reset"
        report["baseline_reset"] = True
        report["reason"] = "corpus_changed_or_missing"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(
            "detection-quality trend drift check skipped: corpus changed or no matching baseline",
            file=sys.stderr,
        )
        return 0

    report["previous_recorded_at_utc"] = previous.get("recorded_at_utc")
    report["previous_corpus"] = previous_sig

    regressions: list[str] = []

    for label in labels:
        prev_metrics = extract_metrics(previous, label)
        curr_metrics = extract_metrics(current, label)
        if prev_metrics is None or curr_metrics is None:
            report["comparisons"][label] = {"status": "missing_metrics"}
            continue

        precision_drop = prev_metrics["precision"] - curr_metrics["precision"]
        recall_drop = prev_metrics["recall"] - curr_metrics["recall"]
        far_increase = curr_metrics["false_alarm_upper_bound"] - prev_metrics["false_alarm_upper_bound"]

        report["comparisons"][label] = {
            "previous": prev_metrics,
            "current": curr_metrics,
            "deltas": {
                "precision_drop": precision_drop,
                "recall_drop": recall_drop,
                "false_alarm_upper_increase": far_increase,
            },
        }

        if precision_drop > args.precision_drop_max:
            regressions.append(
                f"{label}: precision drop {precision_drop:.6f} exceeds max {args.precision_drop_max:.6f}"
            )
        if recall_drop > args.recall_drop_max:
            regressions.append(
                f"{label}: recall drop {recall_drop:.6f} exceeds max {args.recall_drop_max:.6f}"
            )
        if far_increase > args.far_increase_max:
            regressions.append(
                f"{label}: false-alarm upper increase {far_increase:.6f} exceeds max {args.far_increase_max:.6f}"
            )

    report["regressions"] = regressions
    report["status"] = "regressed" if regressions else "ok"

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if regressions and fail_on_regression:
        print("detection-quality trend drift regressions detected:", file=sys.stderr)
        for regression in regressions:
            print(f"- {regression}", file=sys.stderr)
        return 1

    if regressions:
        print("detection-quality trend drift regressions detected (non-blocking mode):", file=sys.stderr)
        for regression in regressions:
            print(f"- {regression}", file=sys.stderr)
    else:
        print("detection-quality trend drift check passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
