#!/usr/bin/env python3
"""Compare multiple phase-3 summary runs and highlight regressions."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_THRESHOLDS: Dict[str, float] = {
    "overhead_median_pct": 5.0,
    "overhead_p95_pct": 8.0,
    "agent_cpu_avg_s": 0.20,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare multiple perf summary runs and flag regressions")
    parser.add_argument(
        "--input",
        dest="inputs",
        action="append",
        default=[],
        help="Run directory (containing summary.json) or summary.json path; repeatable",
    )
    parser.add_argument(
        "--artifact-root",
        default="",
        help="Optional root containing run directories (used when --input is omitted)",
    )
    parser.add_argument(
        "--scenario",
        default="headline",
        help="Scenario to compare (default: headline per platform)",
    )
    parser.add_argument(
        "--baseline-run",
        default="",
        help="Optional run tag to use as baseline (default: oldest discovered run)",
    )
    parser.add_argument(
        "--required-platforms",
        default="linux,windows",
        help="Comma-separated platforms required in all runs (default: %(default)s)",
    )
    parser.add_argument(
        "--max-regression-overhead-median-pct",
        type=float,
        default=DEFAULT_THRESHOLDS["overhead_median_pct"],
        help="Max allowed increase vs baseline for overhead_median_pct",
    )
    parser.add_argument(
        "--max-regression-overhead-p95-pct",
        type=float,
        default=DEFAULT_THRESHOLDS["overhead_p95_pct"],
        help="Max allowed increase vs baseline for overhead_p95_pct",
    )
    parser.add_argument(
        "--max-regression-agent-cpu-avg-s",
        type=float,
        default=DEFAULT_THRESHOLDS["agent_cpu_avg_s"],
        help="Max allowed increase vs baseline for agent_cpu_avg_s",
    )
    parser.add_argument(
        "--json-output",
        default="",
        help="Optional output path for trend JSON",
    )
    parser.add_argument(
        "--report-output",
        default="",
        help="Optional output path for Markdown report",
    )
    parser.add_argument(
        "--fail-on-new-quality-flags",
        action="store_true",
        help="Treat quality flags newly introduced vs baseline as regressions",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Return non-zero exit code when any regression is detected",
    )
    return parser.parse_args()


def sort_key_for_summary(path: pathlib.Path) -> Tuple[str, str]:
    run_name = path.parent.name
    match = re.search(r"(\d{8}T\d{6}Z)", run_name)
    ts = match.group(1) if match else ""
    return (ts, run_name)


def resolve_summary_paths(args: argparse.Namespace) -> List[pathlib.Path]:
    candidates: List[pathlib.Path] = []

    if args.inputs:
        for raw in args.inputs:
            path = pathlib.Path(raw).resolve()
            if path.is_file() and path.name == "summary.json":
                candidates.append(path)
            elif path.is_dir():
                summary_path = path / "summary.json"
                if summary_path.exists():
                    candidates.append(summary_path)
            else:
                raise SystemExit(f"input not found or unsupported: {path}")
    elif args.artifact_root:
        root = pathlib.Path(args.artifact_root).resolve()
        if not root.exists() or not root.is_dir():
            raise SystemExit(f"artifact root not found: {root}")
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            summary_path = child / "summary.json"
            if summary_path.exists():
                candidates.append(summary_path)
    else:
        raise SystemExit("provide at least one --input or --artifact-root")

    if not candidates:
        raise SystemExit("no summary.json files found")

    return sorted(candidates, key=sort_key_for_summary)


def metric_value(metrics: Dict[str, Any], key: str) -> Optional[float]:
    value = metrics.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def parse_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def load_run(summary_path: pathlib.Path, requested_scenario: str) -> Dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
    platforms = summary.get("platforms") if isinstance(summary, dict) else None
    if not isinstance(platforms, dict) or not platforms:
        raise ValueError(f"{summary_path}: invalid summary payload (no platforms)")

    run_name = summary_path.parent.name
    run_payload: Dict[str, Any] = {
        "run": run_name,
        "summary_path": str(summary_path),
        "platforms": {},
    }

    for platform, pdata in platforms.items():
        if not isinstance(pdata, dict):
            continue

        if requested_scenario == "headline":
            scenario = str(pdata.get("headline_scenario") or "")
            metrics = pdata.get("headline") if isinstance(pdata.get("headline"), dict) else {}
        else:
            scenario = requested_scenario
            scenarios = pdata.get("scenarios") if isinstance(pdata.get("scenarios"), dict) else {}
            metrics = scenarios.get(requested_scenario) if isinstance(scenarios.get(requested_scenario), dict) else {}

        run_payload["platforms"][platform] = {
            "scenario": scenario,
            "overhead_median_pct": metric_value(metrics, "overhead_median_pct"),
            "overhead_p95_pct": metric_value(metrics, "overhead_p95_pct"),
            "agent_cpu_avg_s": metric_value(metrics, "agent_cpu_avg_s"),
            "quality_flags": metrics.get("quality_flags") if isinstance(metrics.get("quality_flags"), list) else [],
        }

    return run_payload


def fmt(value: Optional[float], digits: int = 2) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}"


def delta(current: Optional[float], baseline: Optional[float]) -> Optional[float]:
    if current is None or baseline is None:
        return None
    return current - baseline


def evaluate_regressions(
    runs: List[Dict[str, Any]],
    thresholds: Dict[str, float],
    baseline_run: str,
    fail_on_new_quality_flags: bool,
    required_platforms: List[str],
) -> Tuple[Dict[str, Any], List[str]]:
    result: Dict[str, Any] = {"platforms": {}}
    failures: List[str] = []

    if not runs:
        return result, failures

    baseline = next((run for run in runs if str(run.get("run")) == baseline_run), None)
    if baseline is None:
        raise ValueError(f"baseline run not found: {baseline_run}")

    result["baseline_run"] = baseline.get("run")
    required = set(required_platforms)

    all_platforms = sorted(
        {
            platform
            for run in runs
            for platform in run.get("platforms", {}).keys()
        }
        | required
    )

    for platform in all_platforms:
        rows: List[Dict[str, Any]] = []
        baseline_metrics = baseline.get("platforms", {}).get(platform, {})
        baseline_present = isinstance(baseline_metrics, dict) and bool(baseline_metrics)
        if not baseline_present:
            failures.append(f"{platform}/{baseline.get('run')}: missing platform data in baseline")
            baseline_metrics = {}

        baseline_missing_metrics = {
            metric_key
            for metric_key in thresholds.keys()
            if baseline_metrics.get(metric_key) is None
        }
        for metric_key in sorted(baseline_missing_metrics):
            failures.append(
                f"{platform}/{baseline.get('run')}: baseline missing metric {metric_key}"
            )

        baseline_quality_flags = {
            str(flag)
            for flag in (
                baseline_metrics.get("quality_flags")
                if isinstance(baseline_metrics.get("quality_flags"), list)
                else []
            )
        }

        for run in runs:
            current = run.get("platforms", {}).get(platform, {})
            current_present = isinstance(current, dict) and bool(current)
            if not current_present:
                current = {}

            current_quality_flags = [str(flag) for flag in current.get("quality_flags", [])]
            row: Dict[str, Any] = {
                "run": run.get("run"),
                "scenario": current.get("scenario"),
                "metrics": {
                    "overhead_median_pct": current.get("overhead_median_pct"),
                    "overhead_p95_pct": current.get("overhead_p95_pct"),
                    "agent_cpu_avg_s": current.get("agent_cpu_avg_s"),
                },
                "quality_flags": current_quality_flags,
                "new_quality_flags_vs_baseline": [],
                "regressions": [],
                "status": "pass",
            }

            run_name = str(run.get("run"))
            is_baseline = run_name == str(baseline.get("run"))

            if not current_present and platform in required:
                row["regressions"].append(
                    {
                        "metric": "platform_presence",
                        "error": "platform data missing",
                    }
                )
                failures.append(f"{platform}/{run_name}: missing required platform data")
                row["status"] = "fail"
                rows.append(row)
                continue

            for metric_key, threshold in thresholds.items():
                current_value = current.get(metric_key)
                baseline_value = baseline_metrics.get(metric_key)

                if metric_key in baseline_missing_metrics:
                    row["regressions"].append(
                        {
                            "metric": metric_key,
                            "error": "baseline metric missing",
                        }
                    )
                    continue

                if current_value is None:
                    row["regressions"].append(
                        {
                            "metric": metric_key,
                            "error": "metric missing",
                        }
                    )
                    failures.append(f"{platform}/{run_name}: missing metric {metric_key}")
                    continue

                if is_baseline:
                    continue

                d = delta(current_value, baseline_value)
                if d is not None and d > threshold:
                    row["regressions"].append(
                        {
                            "metric": metric_key,
                            "delta_vs_baseline": d,
                            "max_allowed": threshold,
                        }
                    )
                    failures.append(
                        f"{platform}/{run_name}: {metric_key} delta {d:.4f} > {threshold:.4f} vs baseline {baseline.get('run')}"
                    )

            if not is_baseline:
                new_flags = sorted(set(current_quality_flags) - baseline_quality_flags)
                row["new_quality_flags_vs_baseline"] = new_flags
                if fail_on_new_quality_flags and new_flags:
                    row["regressions"].append(
                        {
                            "metric": "quality_flags",
                            "new_flags": new_flags,
                        }
                    )
                    failures.append(
                        f"{platform}/{run_name}: new quality flags vs baseline {baseline.get('run')}: {', '.join(new_flags)}"
                    )

            if row["regressions"]:
                row["status"] = "fail"

            rows.append(row)

        result["platforms"][platform] = rows

    return result, failures


def build_report(result: Dict[str, Any], runs: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# eGuard Agent Performance Trend Comparison")
    lines.append("")
    baseline_run = str(result.get("baseline_run", "n/a"))
    lines.append(f"Baseline run: `{baseline_run}`")
    lines.append("")

    for platform, rows in sorted(result.get("platforms", {}).items()):
        lines.append(f"## {platform.capitalize()}")
        lines.append("")
        lines.append(
            "| Run | Scenario | Median overhead % | Δ median vs baseline | p95 overhead % | Δ p95 vs baseline | Agent CPU avg (s) | Δ CPU vs baseline | Quality flags | New flags vs baseline | Status |"
        )
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|---|---|---|")

        baseline_row = next((row for row in rows if str(row.get("run")) == baseline_run), {})
        baseline_metrics = baseline_row.get("metrics", {}) if isinstance(baseline_row, dict) else {}

        for row in rows:
            metrics = row.get("metrics", {})
            d_med = delta(metrics.get("overhead_median_pct"), baseline_metrics.get("overhead_median_pct"))
            d_p95 = delta(metrics.get("overhead_p95_pct"), baseline_metrics.get("overhead_p95_pct"))
            d_cpu = delta(metrics.get("agent_cpu_avg_s"), baseline_metrics.get("agent_cpu_avg_s"))

            lines.append(
                "| {run} | {scenario} | {median} | {d_median} | {p95} | {d_p95} | {cpu} | {d_cpu} | {quality_flags} | {new_flags} | {status} |".format(
                    run=row.get("run"),
                    scenario=row.get("scenario") or "n/a",
                    median=fmt(metrics.get("overhead_median_pct"), 2),
                    d_median=fmt(d_med, 2),
                    p95=fmt(metrics.get("overhead_p95_pct"), 2),
                    d_p95=fmt(d_p95, 2),
                    cpu=fmt(metrics.get("agent_cpu_avg_s"), 3),
                    d_cpu=fmt(d_cpu, 3),
                    quality_flags=", ".join(row.get("quality_flags", [])) or "-",
                    new_flags=", ".join(row.get("new_quality_flags_vs_baseline", [])) or "-",
                    status=row.get("status", "n/a"),
                )
            )

        lines.append("")

    lines.append("## Runs included")
    lines.append("")
    for run in runs:
        lines.append(f"- `{run.get('run')}` → `{run.get('summary_path')}`")

    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    summary_paths = resolve_summary_paths(args)

    runs: List[Dict[str, Any]] = []
    for summary_path in summary_paths:
        runs.append(load_run(summary_path, args.scenario))

    thresholds = {
        "overhead_median_pct": float(args.max_regression_overhead_median_pct),
        "overhead_p95_pct": float(args.max_regression_overhead_p95_pct),
        "agent_cpu_avg_s": float(args.max_regression_agent_cpu_avg_s),
    }

    baseline_run = args.baseline_run.strip() if isinstance(args.baseline_run, str) else ""
    if not baseline_run:
        baseline_run = str(runs[0].get("run"))

    required_platforms = parse_csv(args.required_platforms)

    try:
        result, failures = evaluate_regressions(
            runs,
            thresholds,
            baseline_run,
            bool(args.fail_on_new_quality_flags),
            required_platforms,
        )
    except ValueError as exc:
        raise SystemExit(str(exc))
    result_payload = {
        "scenario": args.scenario,
        "thresholds": thresholds,
        "runs": [run.get("run") for run in runs],
        "required_platforms": required_platforms,
        "fail_on_new_quality_flags": bool(args.fail_on_new_quality_flags),
        "result": result,
        "failures": failures,
        "status": "pass" if not failures else "fail",
    }

    report = build_report(result, runs)

    if args.json_output:
        out_json = pathlib.Path(args.json_output)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(result_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.report_output:
        out_report = pathlib.Path(args.report_output)
        out_report.parent.mkdir(parents=True, exist_ok=True)
        out_report.write_text(report, encoding="utf-8")

    if failures:
        print("TREND CHECK: FAIL")
        for failure in failures:
            print(f"- {failure}")
        if args.fail_on_regression:
            return 1
    else:
        print("TREND CHECK: PASS")

    print(f"runs analyzed: {', '.join(run.get('run') for run in runs)}")
    print(f"baseline: {result.get('baseline_run')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
