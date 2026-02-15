#!/usr/bin/env python3
"""Score signature-database pipeline ML readiness (shadow by default)."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _safe_ratio(actual: float, target: float, headroom: float) -> float:
    actual = max(actual, 0.0)
    if target <= 0.0:
        return 1.0 if actual > 0.0 else 0.0
    return _clamp(actual / target, 0.0, headroom) / headroom


def _load_json_required(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"missing {label}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _load_json_optional(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _source_balance(rule_counts: dict[str, Any]) -> float:
    cleaned = [max(_as_int(count, 0), 0) for count in rule_counts.values()]
    total = sum(cleaned)
    if total <= 0:
        return 0.5
    if len(cleaned) == 1:
        return 0.3

    max_share = max(cleaned) / float(total)
    if max_share <= 0.45:
        return 1.0
    if max_share >= 0.85:
        return 0.0
    return 1.0 - ((max_share - 0.45) / 0.40)


def _score_signature_scale(
    measured: dict[str, Any],
    thresholds: dict[str, Any],
) -> dict[str, Any]:
    signature_total = _as_float(measured.get("signature_total"), 0.0)
    database_total = _as_float(measured.get("database_total"), 0.0)
    min_signature_total = max(_as_float(thresholds.get("min_signature_total"), 1.0), 1.0)
    min_database_total = max(_as_float(thresholds.get("min_database_total"), 1.0), 1.0)

    signature_ratio = _safe_ratio(signature_total, min_signature_total, 1.50)
    database_ratio = _safe_ratio(database_total, min_database_total, 1.50)
    score = 100.0 * (0.60 * signature_ratio + 0.40 * database_ratio)

    return {
        "available": True,
        "score": round(score, 2),
        "details": {
            "signature_total": int(signature_total),
            "database_total": int(database_total),
            "min_signature_total": int(min_signature_total),
            "min_database_total": int(min_database_total),
            "signature_ratio": round(signature_ratio, 4),
            "database_ratio": round(database_ratio, 4),
        },
    }


def _score_source_diversity(
    measured: dict[str, Any],
    thresholds: dict[str, Any],
    observed_source_rule_counts: dict[str, Any],
) -> dict[str, Any]:
    yara_source_count = _as_float(measured.get("yara_source_count"), 0.0)
    sigma_source_count = _as_float(measured.get("sigma_source_count"), 0.0)
    min_yara_sources = max(_as_float(thresholds.get("min_yara_sources"), 1.0), 1.0)
    min_sigma_sources = max(_as_float(thresholds.get("min_sigma_sources"), 1.0), 1.0)

    yara_ratio = _safe_ratio(yara_source_count, min_yara_sources, 1.75)
    sigma_ratio = _safe_ratio(sigma_source_count, min_sigma_sources, 1.75)

    yara_balance = _source_balance(
        observed_source_rule_counts.get("yara", {})
        if isinstance(observed_source_rule_counts.get("yara", {}), dict)
        else {}
    )
    sigma_balance = _source_balance(
        observed_source_rule_counts.get("sigma", {})
        if isinstance(observed_source_rule_counts.get("sigma", {}), dict)
        else {}
    )
    balance = (yara_balance + sigma_balance) / 2.0
    score = 100.0 * (0.40 * yara_ratio + 0.40 * sigma_ratio + 0.20 * balance)

    return {
        "available": True,
        "score": round(score, 2),
        "details": {
            "yara_source_count": int(yara_source_count),
            "sigma_source_count": int(sigma_source_count),
            "min_yara_sources": int(min_yara_sources),
            "min_sigma_sources": int(min_sigma_sources),
            "yara_ratio": round(yara_ratio, 4),
            "sigma_ratio": round(sigma_ratio, 4),
            "yara_balance": round(yara_balance, 4),
            "sigma_balance": round(sigma_balance, 4),
            "balance": round(balance, 4),
        },
    }


def _score_exploit_intel(
    measured: dict[str, Any],
    thresholds: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    cve_count = _as_float(measured.get("cve_count"), 0.0)
    cve_kev_count = _as_float(measured.get("cve_kev_count"), 0.0)
    cve_epss_count = _as_float(manifest.get("cve_epss_count"), 0.0)

    min_cve = max(_as_float(thresholds.get("min_cve"), 1.0), 1.0)
    min_cve_kev = max(_as_float(thresholds.get("min_cve_kev"), 1.0), 1.0)

    cve_ratio = _safe_ratio(cve_count, min_cve, 1.50)
    kev_ratio = _safe_ratio(cve_kev_count, min_cve_kev, 1.50)
    epss_coverage_ratio = cve_epss_count / cve_count if cve_count > 0.0 else 0.0
    epss_ratio = _safe_ratio(epss_coverage_ratio, 0.25, 1.50)

    score = 100.0 * (0.35 * cve_ratio + 0.35 * kev_ratio + 0.30 * epss_ratio)

    return {
        "available": True,
        "score": round(score, 2),
        "details": {
            "cve_count": int(cve_count),
            "cve_kev_count": int(cve_kev_count),
            "cve_epss_count": int(cve_epss_count),
            "min_cve": int(min_cve),
            "min_cve_kev": int(min_cve_kev),
            "cve_ratio": round(cve_ratio, 4),
            "kev_ratio": round(kev_ratio, 4),
            "epss_coverage_ratio": round(epss_coverage_ratio, 4),
            "epss_ratio": round(epss_ratio, 4),
        },
    }


def _score_attack_surface(attack_coverage: dict[str, Any] | None) -> dict[str, Any]:
    if not attack_coverage:
        return {
            "available": False,
            "score": None,
            "reason": "attack coverage report not provided",
        }

    measured = attack_coverage.get("measured", {})
    thresholds = attack_coverage.get("thresholds", {})
    if not isinstance(measured, dict) or not measured:
        return {
            "available": False,
            "score": None,
            "reason": "attack coverage report missing measured section",
        }

    total_techniques = _as_float(measured.get("total_techniques"), 0.0)
    total_tactics = _as_float(measured.get("total_tactics"), 0.0)
    sigma_rules_with_attack = _as_float(measured.get("sigma_rules_with_attack"), 0.0)
    elastic_rules_with_attack = _as_float(measured.get("elastic_rules_with_attack"), 0.0)

    min_techniques = max(_as_float(thresholds.get("min_techniques"), 1.0), 1.0)
    min_tactics = max(_as_float(thresholds.get("min_tactics"), 1.0), 1.0)
    min_sigma_rules = max(_as_float(thresholds.get("min_sigma_rules_with_attack"), 1.0), 1.0)
    min_elastic_rules = max(_as_float(thresholds.get("min_elastic_rules_with_attack"), 1.0), 1.0)

    techniques_ratio = _safe_ratio(total_techniques, min_techniques, 1.40)
    tactics_ratio = _safe_ratio(total_tactics, min_tactics, 1.40)
    sigma_ratio = _safe_ratio(sigma_rules_with_attack, min_sigma_rules, 1.40)
    elastic_ratio = _safe_ratio(elastic_rules_with_attack, min_elastic_rules, 1.40)

    score = 100.0 * (
        0.35 * techniques_ratio
        + 0.25 * tactics_ratio
        + 0.20 * sigma_ratio
        + 0.20 * elastic_ratio
    )

    return {
        "available": True,
        "score": round(score, 2),
        "details": {
            "total_techniques": int(total_techniques),
            "total_tactics": int(total_tactics),
            "sigma_rules_with_attack": int(sigma_rules_with_attack),
            "elastic_rules_with_attack": int(elastic_rules_with_attack),
            "min_techniques": int(min_techniques),
            "min_tactics": int(min_tactics),
            "min_sigma_rules_with_attack": int(min_sigma_rules),
            "min_elastic_rules_with_attack": int(min_elastic_rules),
            "techniques_ratio": round(techniques_ratio, 4),
            "tactics_ratio": round(tactics_ratio, 4),
            "sigma_ratio": round(sigma_ratio, 4),
            "elastic_ratio": round(elastic_ratio, 4),
        },
    }


def _score_critical_resilience(
    critical_gate: dict[str, Any] | None,
    critical_regression: dict[str, Any] | None,
    critical_owner_streak: dict[str, Any] | None,
    burndown_scoreboard: dict[str, Any] | None,
) -> dict[str, Any]:
    if not critical_gate:
        return {
            "available": False,
            "score": None,
            "reason": "critical ATT&CK gate report not provided",
        }

    measured = critical_gate.get("measured", {})
    if not isinstance(measured, dict):
        measured = {}
    critical_total = max(_as_int(measured.get("critical_total"), 0), 0)
    covered_ratio = _clamp(_as_float(measured.get("covered_ratio"), 0.0), 0.0, 1.0)
    missing_count = max(_as_int(measured.get("missing_count"), critical_total), 0)
    backlog_ratio = (
        _clamp((critical_total - missing_count) / float(critical_total), 0.0, 1.0)
        if critical_total > 0
        else 0.0
    )

    coverage_component = _safe_ratio(covered_ratio, 0.85, 1.20)
    backlog_component = _safe_ratio(backlog_ratio, 0.85, 1.20)
    base_score = 100.0 * (0.70 * coverage_component + 0.30 * backlog_component)

    penalties: list[dict[str, Any]] = []
    regression_status = str((critical_regression or {}).get("status", "")).strip().lower()
    if regression_status == "fail":
        penalties.append({"source": "critical_regression", "points": 20.0})
    elif regression_status == "skipped_no_baseline":
        penalties.append({"source": "critical_regression_no_baseline", "points": 4.0})

    owner_streak_status = str((critical_owner_streak or {}).get("status", "")).strip().lower()
    if owner_streak_status == "fail":
        penalties.append({"source": "owner_streak_regression", "points": 15.0})

    trend = (burndown_scoreboard or {}).get("trend", {}) if burndown_scoreboard else {}
    if not isinstance(trend, dict):
        trend = {}
    delta_uncovered = _as_int(trend.get("delta_uncovered"), 0)
    if delta_uncovered > 0:
        penalties.append(
            {
                "source": "critical_uncovered_growth",
                "points": float(min(12, delta_uncovered * 3)),
                "delta_uncovered": delta_uncovered,
            }
        )

    penalty_points = sum(_as_float(item.get("points"), 0.0) for item in penalties)
    score = max(base_score - penalty_points, 0.0)

    return {
        "available": True,
        "score": round(score, 2),
        "details": {
            "critical_total": critical_total,
            "covered_ratio": round(covered_ratio, 4),
            "missing_count": missing_count,
            "base_score": round(base_score, 2),
            "penalty_points": round(penalty_points, 2),
            "penalties": penalties,
            "regression_status": regression_status or "unknown",
            "owner_streak_status": owner_streak_status or "unknown",
            "delta_uncovered": delta_uncovered,
        },
    }


def _weighted_final_score(components: dict[str, dict[str, Any]], weights: dict[str, float]) -> float:
    weighted_sum = 0.0
    total_weight = 0.0
    for name, component in components.items():
        if not component.get("available"):
            continue
        weight = _as_float(weights.get(name), 0.0)
        if weight <= 0.0:
            continue
        weighted_sum += _as_float(component.get("score"), 0.0) * weight
        total_weight += weight
    if total_weight <= 0.0:
        return 0.0
    return weighted_sum / total_weight


def _readiness_tier(score: float) -> str:
    if score >= 94.0:
        return "elite"
    if score >= 88.0:
        return "strong"
    if score >= 80.0:
        return "competitive"
    if score >= 70.0:
        return "developing"
    return "at_risk"


def _previous_final_score(previous_report: dict[str, Any] | None) -> float | None:
    if not previous_report:
        return None
    scores = previous_report.get("scores", {})
    if isinstance(scores, dict) and "final_score" in scores:
        return _as_float(scores.get("final_score"), 0.0)
    if "final_score" in previous_report:
        return _as_float(previous_report.get("final_score"), 0.0)
    return None


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate signature-database ML readiness score from bundle pipeline artifacts"
    )
    parser.add_argument("--manifest", required=True, help="Bundle manifest.json path")
    parser.add_argument("--coverage", required=True, help="bundle_coverage_gate output JSON path")
    parser.add_argument("--attack-coverage", default="", help="Optional attack_coverage_gate output JSON")
    parser.add_argument("--critical-gate", default="", help="Optional attack_critical_technique_gate output JSON")
    parser.add_argument(
        "--critical-regression",
        default="",
        help="Optional attack_critical_regression_gate output JSON",
    )
    parser.add_argument(
        "--critical-owner-streak",
        default="",
        help="Optional attack_critical_owner_streak_gate output JSON",
    )
    parser.add_argument(
        "--burndown-scoreboard",
        default="",
        help="Optional attack_burndown_scoreboard output JSON",
    )
    parser.add_argument("--previous", default="", help="Optional previous readiness report JSON")
    parser.add_argument("--output", required=True, help="Output readiness report JSON")
    parser.add_argument("--min-final-score", type=float, default=88.0)
    parser.add_argument("--max-score-drop", type=float, default=3.0)
    parser.add_argument("--fail-on-threshold", default="0")
    parser.add_argument("--fail-on-score-drop", default="0")
    return parser


def main() -> int:
    args = _parser().parse_args()

    manifest_path = Path(args.manifest)
    coverage_path = Path(args.coverage)
    output_path = Path(args.output)

    fail_on_threshold = _parse_bool(args.fail_on_threshold)
    fail_on_score_drop = _parse_bool(args.fail_on_score_drop)
    mode = "enforced" if (fail_on_threshold or fail_on_score_drop) else "shadow"

    try:
        manifest = _load_json_required(manifest_path, "bundle manifest")
        coverage = _load_json_required(coverage_path, "coverage report")
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as err:
        report = {
            "suite": "signature_ml_readiness_gate",
            "recorded_at_utc": _now_utc(),
            "status": "fail",
            "mode": mode,
            "failures": [str(err)],
        }
        _write_report(output_path, report)
        print(str(err))
        return 1

    measured = coverage.get("measured", {})
    thresholds = coverage.get("thresholds", {})
    observed_source_rule_counts = coverage.get("observed_source_rule_counts", {})
    if not isinstance(measured, dict):
        measured = {}
    if not isinstance(thresholds, dict):
        thresholds = {}
    if not isinstance(observed_source_rule_counts, dict):
        observed_source_rule_counts = {}

    attack_coverage = _load_json_optional(Path(args.attack_coverage)) if args.attack_coverage else None
    critical_gate = _load_json_optional(Path(args.critical_gate)) if args.critical_gate else None
    critical_regression = (
        _load_json_optional(Path(args.critical_regression)) if args.critical_regression else None
    )
    critical_owner_streak = (
        _load_json_optional(Path(args.critical_owner_streak)) if args.critical_owner_streak else None
    )
    burndown_scoreboard = (
        _load_json_optional(Path(args.burndown_scoreboard)) if args.burndown_scoreboard else None
    )
    previous_report = _load_json_optional(Path(args.previous)) if args.previous else None

    components = {
        "signature_scale": _score_signature_scale(measured, thresholds),
        "source_diversity": _score_source_diversity(measured, thresholds, observed_source_rule_counts),
        "exploit_intel": _score_exploit_intel(measured, thresholds, manifest),
        "attack_surface": _score_attack_surface(attack_coverage),
        "critical_resilience": _score_critical_resilience(
            critical_gate,
            critical_regression,
            critical_owner_streak,
            burndown_scoreboard,
        ),
    }
    component_weights = {
        "signature_scale": 0.30,
        "source_diversity": 0.20,
        "exploit_intel": 0.15,
        "attack_surface": 0.20,
        "critical_resilience": 0.15,
    }

    final_score = round(_weighted_final_score(components, component_weights), 2)
    previous_final_score = _previous_final_score(previous_report)
    score_delta = round(final_score - previous_final_score, 2) if previous_final_score is not None else None
    score_drop = round(previous_final_score - final_score, 2) if previous_final_score is not None else None
    readiness_tier = _readiness_tier(final_score)

    warnings: list[str] = []
    if components["source_diversity"].get("available") and _as_float(
        components["source_diversity"].get("score"), 0.0
    ) < 75.0:
        warnings.append("source diversity score below 75.0")
    if components["critical_resilience"].get("available") and _as_float(
        components["critical_resilience"].get("score"), 0.0
    ) < 80.0:
        warnings.append("critical resilience score below 80.0")

    for name, component in components.items():
        if not component.get("available"):
            reason = str(component.get("reason", "missing optional input")).strip()
            warnings.append(f"{name} unavailable: {reason}")

    failures: list[str] = []
    enforced_failures: list[str] = []
    if final_score < args.min_final_score:
        failure = f"final_score below threshold: {final_score:.2f} < {args.min_final_score:.2f}"
        failures.append(failure)
        if fail_on_threshold:
            enforced_failures.append(failure)

    if previous_final_score is not None and score_drop is not None and score_drop > args.max_score_drop:
        failure = (
            "score_drop beyond threshold: "
            f"{score_drop:.2f} > {args.max_score_drop:.2f} "
            f"(previous={previous_final_score:.2f}, current={final_score:.2f})"
        )
        failures.append(failure)
        if fail_on_score_drop:
            enforced_failures.append(failure)

    if enforced_failures:
        status = "fail"
    elif failures:
        status = "shadow_alert"
    else:
        status = "pass"

    report = {
        "suite": "signature_ml_readiness_gate",
        "recorded_at_utc": _now_utc(),
        "status": status,
        "mode": mode,
        "readiness_tier": readiness_tier,
        "thresholds": {
            "min_final_score": args.min_final_score,
            "max_score_drop": args.max_score_drop,
            "fail_on_threshold": fail_on_threshold,
            "fail_on_score_drop": fail_on_score_drop,
        },
        "scores": {
            "final_score": final_score,
            "previous_final_score": round(previous_final_score, 2)
            if previous_final_score is not None
            else None,
            "score_delta": score_delta,
            "score_drop": score_drop,
        },
        "components": components,
        "component_weights": component_weights,
        "inputs": {
            "manifest": str(manifest_path),
            "coverage": str(coverage_path),
            "attack_coverage": str(args.attack_coverage) if args.attack_coverage else None,
            "critical_gate": str(args.critical_gate) if args.critical_gate else None,
            "critical_regression": str(args.critical_regression) if args.critical_regression else None,
            "critical_owner_streak": str(args.critical_owner_streak)
            if args.critical_owner_streak
            else None,
            "burndown_scoreboard": str(args.burndown_scoreboard) if args.burndown_scoreboard else None,
            "previous": str(args.previous) if args.previous else None,
        },
        "warnings": warnings,
        "failures": failures,
        "enforced_failures": enforced_failures,
    }
    _write_report(output_path, report)

    print("Signature ML readiness snapshot:")
    print(f"- mode: {mode}")
    print(f"- status: {status}")
    print(f"- readiness tier: {readiness_tier}")
    print(f"- final score: {final_score:.2f}")
    if previous_final_score is not None and score_drop is not None and score_delta is not None:
        print(f"- previous final score: {previous_final_score:.2f}")
        print(f"- score delta: {score_delta:.2f}")
        print(f"- score drop: {score_drop:.2f}")
    else:
        print("- previous final score: n/a")

    for name, component in components.items():
        if component.get("available"):
            print(f"- {name}: {float(component.get('score', 0.0)):.2f}")
        else:
            print(f"- {name}: unavailable ({component.get('reason', 'missing optional input')})")

    if failures:
        print("\nSignature ML readiness alerts:")
        for failure in failures:
            print(f"- {failure}")

    if warnings:
        print("\nSignature ML readiness warnings:")
        for warning in warnings:
            print(f"- {warning}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
