#!/usr/bin/env python3
"""Aggregate phase-3 benchmark raw artifacts into summary JSON + Markdown report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import pathlib
import statistics
from typing import Any, Dict, Iterable, List, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize perf artifacts from scripts/perf/linux_phase3.sh and windows_phase3.ps1")
    parser.add_argument(
        "--input-root",
        required=True,
        help="Artifact root for one run date (e.g. artifacts/perf/20260302T150000Z)",
    )
    parser.add_argument(
        "--output-summary",
        default="",
        help="Path to write summary JSON (default: <input-root>/summary.json)",
    )
    parser.add_argument(
        "--output-report",
        default="",
        help="Path to write Markdown report (default: <input-root>/report.md)",
    )
    parser.add_argument(
        "--headline-scenario",
        default="ransomware",
        help="Scenario used for headline metrics and gate defaults (default: %(default)s)",
    )
    return parser.parse_args()


def percentile(values: List[float], p: float) -> Optional[float]:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    values = sorted(values)
    rank = (len(values) - 1) * p
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return values[low]
    frac = rank - low
    return values[low] + (values[high] - values[low]) * frac


def avg(values: Iterable[Optional[float]]) -> Optional[float]:
    valid = [float(v) for v in values if isinstance(v, (int, float))]
    if not valid:
        return None
    return sum(valid) / len(valid)


def overhead_pct(on_value: Optional[float], off_value: Optional[float]) -> Optional[float]:
    if on_value is None or off_value is None:
        return None
    if off_value <= 0:
        return None
    return ((on_value - off_value) / off_value) * 100.0


def load_rows(raw_file: pathlib.Path) -> List[Dict[str, Any]]:
    payload = json.loads(raw_file.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, list):
        raise ValueError(f"{raw_file} must contain a JSON array")
    rows: List[Dict[str, Any]] = []
    for row in payload:
        if isinstance(row, dict):
            rows.append(row)
    return rows


def scenario_quality_flags(payload: Dict[str, Any]) -> List[str]:
    flags: List[str] = []

    runs_on = payload.get("runs_on")
    runs_off = payload.get("runs_off")
    if isinstance(runs_on, int) and isinstance(runs_off, int):
        if runs_on < 6 or runs_off < 6:
            flags.append("low_sample_count")

    if payload.get("overhead_median_pct") is None:
        flags.append("missing_overhead_median")
    if payload.get("overhead_p95_pct") is None:
        flags.append("missing_overhead_p95")

    median_overhead = payload.get("overhead_median_pct")
    if isinstance(median_overhead, (int, float)) and median_overhead < -20.0:
        flags.append("high_negative_median_overhead_check_for_noise")

    p95_overhead = payload.get("overhead_p95_pct")
    if isinstance(p95_overhead, (int, float)) and p95_overhead < -25.0:
        flags.append("high_negative_p95_overhead_check_for_noise")

    return flags


def scenario_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    measured = [r for r in rows if not bool(r.get("warmup", False))]
    on_rows = [r for r in measured if str(r.get("mode", "")).upper() == "ON"]
    off_rows = [r for r in measured if str(r.get("mode", "")).upper() == "OFF"]

    on_elapsed = [float(r["elapsed_s"]) for r in on_rows if isinstance(r.get("elapsed_s"), (int, float))]
    off_elapsed = [float(r["elapsed_s"]) for r in off_rows if isinstance(r.get("elapsed_s"), (int, float))]

    median_on = statistics.median(on_elapsed) if on_elapsed else None
    median_off = statistics.median(off_elapsed) if off_elapsed else None
    p95_on = percentile(on_elapsed, 0.95)
    p95_off = percentile(off_elapsed, 0.95)
    p99_on = percentile(on_elapsed, 0.99)
    p99_off = percentile(off_elapsed, 0.99)

    payload = {
        "sample_count_total": len(rows),
        "sample_count_measured": len(measured),
        "runs_on": len(on_elapsed),
        "runs_off": len(off_elapsed),
        "median_on_s": median_on,
        "median_off_s": median_off,
        "p95_on_s": p95_on,
        "p95_off_s": p95_off,
        "p99_on_s": p99_on,
        "p99_off_s": p99_off,
        "overhead_median_pct": overhead_pct(median_on, median_off),
        "overhead_p95_pct": overhead_pct(p95_on, p95_off),
        "overhead_p99_pct": overhead_pct(p99_on, p99_off),
        "agent_cpu_avg_s": avg(r.get("agent_cpu_s") for r in on_rows),
        "agent_rss_avg_kb": avg(r.get("agent_rss_kb") for r in on_rows),
        "cpu_iowait_avg_pct": avg(r.get("cpu_iowait_pct") for r in measured),
        "disk_await_avg_ms": avg(r.get("disk_await_ms") for r in measured),
        "disk_read_avg_bytes": avg(
            r.get("disk_read_bytes", r.get("disk_read_bytes_per_sec")) for r in measured
        ),
        "disk_write_avg_bytes": avg(
            r.get("disk_write_bytes", r.get("disk_write_bytes_per_sec")) for r in measured
        ),
    }
    payload["quality_flags"] = scenario_quality_flags(payload)
    return payload


def format_float(value: Optional[float], digits: int = 3) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}"


def make_report(summary: Dict[str, Any], headline_scenario: str) -> str:
    lines: List[str] = []
    lines.append("# eGuard Agent Performance Benchmark — Phase 3 Summary")
    lines.append("")
    lines.append(f"Generated: `{summary['generated_at_utc']}`")
    lines.append("")
    lines.append(f"Headline scenario: `{headline_scenario}`")
    lines.append("")

    for platform, pdata in summary.get("platforms", {}).items():
        lines.append(f"## {platform.capitalize()}")
        lines.append("")
        lines.append("| Scenario | ON runs | OFF runs | Median ON (s) | Median OFF (s) | Median overhead % | p95 ON (s) | p95 OFF (s) | p95 overhead % | Agent CPU avg (s) | Quality flags |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        for scenario, sdata in sorted(pdata.get("scenarios", {}).items()):
            lines.append(
                "| {scenario} | {runs_on} | {runs_off} | {median_on} | {median_off} | {over_median} | {p95_on} | {p95_off} | {over_p95} | {cpu_avg} | {quality_flags} |".format(
                    scenario=scenario,
                    runs_on=sdata.get("runs_on", 0),
                    runs_off=sdata.get("runs_off", 0),
                    median_on=format_float(sdata.get("median_on_s")),
                    median_off=format_float(sdata.get("median_off_s")),
                    over_median=format_float(sdata.get("overhead_median_pct"), 2),
                    p95_on=format_float(sdata.get("p95_on_s")),
                    p95_off=format_float(sdata.get("p95_off_s")),
                    over_p95=format_float(sdata.get("overhead_p95_pct"), 2),
                    cpu_avg=format_float(sdata.get("agent_cpu_avg_s"), 3),
                    quality_flags=", ".join(sdata.get("quality_flags", [])) or "-",
                )
            )
        lines.append("")

        headline = pdata.get("headline", {})
        lines.append("**Headline metrics**")
        lines.append("")
        lines.append(
            "- scenario: `{}`\n- median overhead: `{}`%\n- p95 overhead: `{}`%\n- agent cpu avg: `{}` s\n- quality flags: `{}`".format(
                pdata.get("headline_scenario"),
                format_float(headline.get("overhead_median_pct"), 2),
                format_float(headline.get("overhead_p95_pct"), 2),
                format_float(headline.get("agent_cpu_avg_s"), 3),
                ", ".join(headline.get("quality_flags", [])) or "-",
            )
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    input_root = pathlib.Path(args.input_root).resolve()
    if not input_root.exists() or not input_root.is_dir():
        raise SystemExit(f"input root not found: {input_root}")

    output_summary = pathlib.Path(args.output_summary).resolve() if args.output_summary else input_root / "summary.json"
    output_report = pathlib.Path(args.output_report).resolve() if args.output_report else input_root / "report.md"

    summary: Dict[str, Any] = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "input_root": str(input_root),
        "headline_scenario": args.headline_scenario,
        "platforms": {},
    }

    platform_dirs = [p for p in sorted(input_root.iterdir()) if p.is_dir()]
    for platform_dir in platform_dirs:
        platform = platform_dir.name
        scenarios: Dict[str, Any] = {}

        for scenario_dir in sorted([p for p in platform_dir.iterdir() if p.is_dir()]):
            raw_file = scenario_dir / "raw.json"
            if not raw_file.exists():
                continue
            rows = load_rows(raw_file)
            scenarios[scenario_dir.name] = scenario_summary(rows)

        if not scenarios:
            continue

        headline_scenario = args.headline_scenario if args.headline_scenario in scenarios else sorted(scenarios.keys())[0]
        summary["platforms"][platform] = {
            "headline_scenario": headline_scenario,
            "headline": scenarios[headline_scenario],
            "scenarios": scenarios,
        }

    output_summary.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_report.write_text(make_report(summary, args.headline_scenario), encoding="utf-8")

    print(f"wrote summary: {output_summary}")
    print(f"wrote report:  {output_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
