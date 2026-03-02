#!/usr/bin/env python3
"""Performance gate evaluator for phase-3 benchmark summaries."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

THRESHOLDS: Dict[str, Dict[str, Dict[str, float]]] = {
    "provisional": {
        "linux": {
            "overhead_median_pct": 12.0,
            "overhead_p95_pct": 30.0,
            "agent_cpu_avg_s": 1.0,
        },
        "windows": {
            "overhead_median_pct": 6.0,
            "overhead_p95_pct": 12.0,
            "agent_cpu_avg_s": 1.0,
        },
    },
    "hard": {
        "linux": {
            "overhead_median_pct": 8.0,
            "overhead_p95_pct": 20.0,
            "agent_cpu_avg_s": 1.0,
        },
        "windows": {
            "overhead_median_pct": 5.0,
            "overhead_p95_pct": 8.0,
            "agent_cpu_avg_s": 1.0,
        },
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate summary.json against phase-3 gate thresholds")
    parser.add_argument("--summary", required=True, help="Path to summary.json")
    parser.add_argument(
        "--profile",
        default="provisional",
        choices=sorted(THRESHOLDS.keys()),
        help="Gate profile to enforce",
    )
    parser.add_argument(
        "--scenario",
        default="headline",
        help="Scenario name to evaluate (default: headline scenario per platform)",
    )
    parser.add_argument(
        "--json-output",
        default="",
        help="Optional output path for machine-readable gate results",
    )
    parser.add_argument(
        "--min-runs-per-mode",
        type=int,
        default=6,
        help="Minimum measured ON and OFF runs required per platform/scenario (default: %(default)s)",
    )
    parser.add_argument(
        "--fail-on-quality-flags",
        default="low_sample_count,missing_overhead_median,missing_overhead_p95",
        help=(
            "Comma-separated scenario quality flags that should fail the gate "
            "(empty to disable quality-flag failures)"
        ),
    )
    return parser.parse_args()


def get_metric_value(payload: Dict[str, Any], key: str) -> Optional[float]:
    value = payload.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def parse_csv_flags(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def evaluate_platform(
    platform: str,
    pdata: Dict[str, Any],
    threshold: Dict[str, float],
    requested_scenario: str,
    min_runs_per_mode: int,
    fail_on_quality_flags: List[str],
) -> Tuple[List[str], Dict[str, Any]]:
    failures: List[str] = []

    if requested_scenario == "headline":
        scenario_name = str(pdata.get("headline_scenario") or "")
        metrics = pdata.get("headline") if isinstance(pdata.get("headline"), dict) else {}
    else:
        scenario_name = requested_scenario
        scenarios = pdata.get("scenarios") if isinstance(pdata.get("scenarios"), dict) else {}
        metrics = scenarios.get(requested_scenario) if isinstance(scenarios.get(requested_scenario), dict) else {}

    if not scenario_name:
        failures.append(f"{platform}: unable to resolve scenario")
        return failures, {"scenario": scenario_name, "status": "fail", "checks": []}

    checks: List[Dict[str, Any]] = []

    runs_on = metrics.get("runs_on") if isinstance(metrics.get("runs_on"), int) else None
    runs_off = metrics.get("runs_off") if isinstance(metrics.get("runs_off"), int) else None

    run_count_pass = (
        runs_on is not None
        and runs_off is not None
        and runs_on >= min_runs_per_mode
        and runs_off >= min_runs_per_mode
    )
    checks.append(
        {
            "metric": "min_runs_per_mode",
            "actual": {
                "runs_on": runs_on,
                "runs_off": runs_off,
            },
            "threshold_min": min_runs_per_mode,
            "pass": run_count_pass,
        }
    )
    if not run_count_pass:
        failures.append(
            f"{platform}/{scenario_name}: insufficient measured runs (runs_on={runs_on}, runs_off={runs_off}, min={min_runs_per_mode})"
        )

    quality_flags = metrics.get("quality_flags") if isinstance(metrics.get("quality_flags"), list) else []
    quality_flags = [str(flag) for flag in quality_flags]
    quality_fail_flags = [flag for flag in quality_flags if flag in fail_on_quality_flags]
    quality_pass = len(quality_fail_flags) == 0
    checks.append(
        {
            "metric": "quality_flags",
            "actual": quality_flags,
            "fail_on": fail_on_quality_flags,
            "fail_flags": quality_fail_flags,
            "pass": quality_pass,
        }
    )
    if not quality_pass:
        failures.append(
            f"{platform}/{scenario_name}: quality flags triggered failure: {', '.join(quality_fail_flags)}"
        )

    for metric_name, threshold_value in threshold.items():
        actual = get_metric_value(metrics, metric_name)
        passed = actual is not None and actual <= threshold_value
        checks.append(
            {
                "metric": metric_name,
                "actual": actual,
                "threshold_max": threshold_value,
                "pass": passed,
            }
        )
        if not passed:
            failures.append(
                f"{platform}/{scenario_name}: {metric_name}={actual if actual is not None else 'n/a'} > {threshold_value}"
            )

    status = "pass" if not failures else "fail"
    return failures, {"scenario": scenario_name, "status": status, "checks": checks}


def main() -> int:
    args = parse_args()
    summary_path = pathlib.Path(args.summary)
    if not summary_path.exists():
        print(f"summary not found: {summary_path}", file=sys.stderr)
        return 2

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    platforms = summary.get("platforms") if isinstance(summary, dict) else None
    if not isinstance(platforms, dict) or not platforms:
        print("summary has no platform data", file=sys.stderr)
        return 2

    profile_threshold = THRESHOLDS[args.profile]
    fail_on_quality_flags = parse_csv_flags(args.fail_on_quality_flags)

    all_failures: List[str] = []
    result: Dict[str, Any] = {
        "profile": args.profile,
        "scenario": args.scenario,
        "summary": str(summary_path),
        "min_runs_per_mode": args.min_runs_per_mode,
        "fail_on_quality_flags": fail_on_quality_flags,
        "platforms": {},
    }

    for platform, threshold in profile_threshold.items():
        pdata = platforms.get(platform)
        if not isinstance(pdata, dict):
            all_failures.append(f"missing platform data: {platform}")
            result["platforms"][platform] = {
                "status": "fail",
                "scenario": args.scenario,
                "checks": [],
                "error": "platform data missing",
            }
            continue

        failures, platform_result = evaluate_platform(
            platform,
            pdata,
            threshold,
            args.scenario,
            max(1, int(args.min_runs_per_mode)),
            fail_on_quality_flags,
        )
        all_failures.extend(failures)
        result["platforms"][platform] = platform_result

    result["status"] = "pass" if not all_failures else "fail"
    result["failures"] = all_failures

    if args.json_output:
        out_path = pathlib.Path(args.json_output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if all_failures:
        print("PERFORMANCE GATE: FAIL")
        for line in all_failures:
            print(f"- {line}")
        return 1

    print("PERFORMANCE GATE: PASS")
    for platform, pdata in result["platforms"].items():
        print(f"- {platform}/{pdata.get('scenario')}")
        for check in pdata.get("checks", []):
            metric = check.get("metric")
            if check.get("threshold_max") is not None:
                print(
                    "  - {metric}: actual={actual} threshold<={thr}".format(
                        metric=metric,
                        actual=check.get("actual"),
                        thr=check.get("threshold_max"),
                    )
                )
            elif check.get("threshold_min") is not None:
                print(
                    "  - {metric}: actual={actual} threshold>={thr}".format(
                        metric=metric,
                        actual=check.get("actual"),
                        thr=check.get("threshold_min"),
                    )
                )
            elif metric == "quality_flags":
                print(
                    "  - quality_flags: actual={actual} fail_on={fail_on} fail_flags={fail_flags}".format(
                        actual=check.get("actual"),
                        fail_on=check.get("fail_on"),
                        fail_flags=check.get("fail_flags"),
                    )
                )
            else:
                print(f"  - {metric}: {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
