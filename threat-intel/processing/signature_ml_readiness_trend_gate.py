#!/usr/bin/env python3
"""Track and gate signature ML readiness trend regressions."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALERT_STATUSES = {"shadow_alert", "fail"}
TIER_ORDER = {
    "at_risk": 0,
    "developing": 1,
    "competitive": 2,
    "strong": 3,
    "elite": 4,
}


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


def _load_json_required(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"missing {label}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _load_ndjson(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []

    entries: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def _component_scores(report: dict[str, Any]) -> dict[str, float]:
    components = report.get("components", {})
    if not isinstance(components, dict) or not components:
        fallback = report.get("component_scores", {})
        if not isinstance(fallback, dict):
            return {}
        out: dict[str, float] = {}
        for name, score in fallback.items():
            out[str(name)] = round(_as_float(score, 0.0), 2)
        return out

    out: dict[str, float] = {}
    for name, payload in components.items():
        if not isinstance(payload, dict):
            continue
        if not payload.get("available"):
            continue
        if "score" not in payload:
            continue
        out[str(name)] = round(_as_float(payload.get("score"), 0.0), 2)
    return out


def _final_score(entry: dict[str, Any]) -> float | None:
    scores = entry.get("scores", {})
    if isinstance(scores, dict) and "final_score" in scores:
        return round(_as_float(scores.get("final_score"), 0.0), 2)
    if "final_score" in entry:
        return round(_as_float(entry.get("final_score"), 0.0), 2)
    return None


def _tier(entry: dict[str, Any]) -> str:
    tier = str(entry.get("readiness_tier", "")).strip().lower()
    if tier in TIER_ORDER:
        return tier
    return "at_risk"


def _consecutive_alerts(entries: list[dict[str, Any]]) -> int:
    streak = 0
    for entry in reversed(entries):
        status = str(entry.get("status", "")).strip().lower()
        if status in ALERT_STATUSES:
            streak += 1
            continue
        break
    return streak


def _entry_for_trend(
    report: dict[str, Any],
    *,
    status: str,
    score_delta: float | None,
    score_drop: float | None,
    projected_alert_streak: int,
) -> dict[str, Any]:
    scores = report.get("scores", {})
    if not isinstance(scores, dict):
        scores = {}

    entry = {
        "recorded_at_utc": report.get("recorded_at_utc") or _now_utc(),
        "suite": "signature_ml_readiness_trend",
        "status": status,
        "mode": report.get("mode", "shadow"),
        "readiness_tier": _tier(report),
        "final_score": _final_score(report),
        "score_delta": score_delta,
        "score_drop": score_drop,
        "projected_alert_streak": projected_alert_streak,
        "component_scores": _component_scores(report),
        "warning_count": len(report.get("warnings", [])) if isinstance(report.get("warnings", []), list) else 0,
        "failure_count": len(report.get("failures", [])) if isinstance(report.get("failures", []), list) else 0,
        "source_status": str(report.get("status", "")).strip().lower() or "unknown",
        "source_final_score": scores.get("final_score"),
    }
    return entry


def _write_ndjson(path: Path, entries: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate signature ML readiness trend regressions")
    parser.add_argument("--current", required=True, help="Current signature ML readiness JSON")
    parser.add_argument("--previous-trend", default="", help="Previous readiness trend NDJSON")
    parser.add_argument("--output-trend", required=True, help="Output readiness trend NDJSON")
    parser.add_argument("--output-report", required=True, help="Output readiness trend report JSON")
    parser.add_argument("--max-score-drop", type=float, default=2.5)
    parser.add_argument("--max-component-drop", type=float, default=8.0)
    parser.add_argument("--max-tier-drop", type=int, default=1)
    parser.add_argument("--max-consecutive-alerts", type=int, default=3)
    parser.add_argument("--fail-on-regression", default="0")
    return parser


def main() -> int:
    args = _parser().parse_args()

    current_path = Path(args.current)
    previous_trend_path = Path(args.previous_trend) if args.previous_trend else None
    output_trend_path = Path(args.output_trend)
    output_report_path = Path(args.output_report)
    fail_on_regression = _parse_bool(args.fail_on_regression)

    try:
        current_report = _load_json_required(current_path, "current readiness report")
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_readiness_trend_gate",
            "recorded_at_utc": _now_utc(),
            "status": "fail",
            "failures": [str(err)],
        }
        _write_json(output_report_path, report)
        print(str(err))
        return 1

    previous_entries = _load_ndjson(previous_trend_path)
    previous_entry = previous_entries[-1] if previous_entries else None

    current_final_score = _final_score(current_report)
    previous_final_score = _final_score(previous_entry) if previous_entry else None
    score_delta = (
        round(current_final_score - previous_final_score, 2)
        if current_final_score is not None and previous_final_score is not None
        else None
    )
    score_drop = (
        round(previous_final_score - current_final_score, 2)
        if current_final_score is not None and previous_final_score is not None
        else None
    )

    current_components = _component_scores(current_report)
    previous_components = _component_scores(previous_entry) if previous_entry else {}

    component_deltas: dict[str, float] = {}
    component_drops: dict[str, float] = {}
    for key in sorted(set(current_components.keys()) | set(previous_components.keys())):
        current = current_components.get(key)
        previous = previous_components.get(key)
        if current is None or previous is None:
            continue
        delta = round(current - previous, 2)
        component_deltas[key] = delta
        if delta < 0:
            component_drops[key] = round(-delta, 2)

    current_tier = _tier(current_report)
    previous_tier = _tier(previous_entry) if previous_entry else None
    tier_delta = (
        TIER_ORDER.get(current_tier, 0) - TIER_ORDER.get(previous_tier, 0)
        if previous_tier is not None
        else None
    )
    tier_drop = -tier_delta if tier_delta is not None and tier_delta < 0 else 0

    previous_alert_streak = _consecutive_alerts(previous_entries)
    projected_alert_streak = previous_alert_streak

    regressions: list[str] = []
    if current_final_score is None:
        regressions.append("current report missing final_score")
    if score_drop is not None and score_drop > args.max_score_drop:
        regressions.append(
            f"final_score drop too high: {score_drop:.2f} > {args.max_score_drop:.2f}"
        )
    for name, drop in component_drops.items():
        if drop > args.max_component_drop:
            regressions.append(
                f"component score drop too high ({name}): {drop:.2f} > {args.max_component_drop:.2f}"
            )
    if tier_drop > args.max_tier_drop:
        regressions.append(
            f"readiness tier dropped too far: {tier_drop} > {args.max_tier_drop}"
        )

    if regressions:
        projected_alert_streak += 1
        if projected_alert_streak > args.max_consecutive_alerts:
            regressions.append(
                "consecutive trend alerts exceeded max: "
                f"{projected_alert_streak} > {args.max_consecutive_alerts}"
            )
    else:
        projected_alert_streak = 0

    if not previous_entries:
        history_status = "no_baseline"
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

    trend_entry = _entry_for_trend(
        current_report,
        status=status,
        score_delta=score_delta,
        score_drop=score_drop,
        projected_alert_streak=projected_alert_streak,
    )
    all_entries = [*previous_entries, trend_entry]
    _write_ndjson(output_trend_path, all_entries)

    report = {
        "suite": "signature_ml_readiness_trend_gate",
        "recorded_at_utc": _now_utc(),
        "status": status,
        "history_status": history_status,
        "thresholds": {
            "max_score_drop": args.max_score_drop,
            "max_component_drop": args.max_component_drop,
            "max_tier_drop": args.max_tier_drop,
            "max_consecutive_alerts": args.max_consecutive_alerts,
            "fail_on_regression": fail_on_regression,
        },
        "scores": {
            "current_final_score": current_final_score,
            "previous_final_score": previous_final_score,
            "score_delta": score_delta,
            "score_drop": score_drop,
        },
        "tiers": {
            "current": current_tier,
            "previous": previous_tier,
            "delta": tier_delta,
            "drop": tier_drop,
        },
        "components": {
            "current": current_components,
            "previous": previous_components,
            "deltas": component_deltas,
            "drops": component_drops,
        },
        "alerts": {
            "previous_consecutive_alerts": previous_alert_streak,
            "projected_consecutive_alerts": projected_alert_streak,
            "regression_count": len(regressions),
        },
        "regressions": regressions,
    }
    _write_json(output_report_path, report)

    print("Signature ML readiness trend snapshot:")
    print(f"- status: {status}")
    print(f"- history status: {history_status}")
    print(f"- current final score: {current_final_score if current_final_score is not None else 'n/a'}")
    print(f"- previous final score: {previous_final_score if previous_final_score is not None else 'n/a'}")
    print(f"- score drop: {score_drop if score_drop is not None else 'n/a'}")
    print(f"- projected consecutive alerts: {projected_alert_streak}")

    if regressions:
        print("\nSignature ML readiness trend alerts:")
        for regression in regressions:
            print(f"- {regression}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
