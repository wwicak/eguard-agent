#!/usr/bin/env python3
"""Generate ATT&CK critical-technique burn-down scoreboard artifacts."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_technique(raw: str) -> str:
    return str(raw).strip().upper()


def _priority_rank(raw: str) -> tuple[int, str]:
    priority = str(raw).strip().upper()
    if priority.startswith("P") and priority[1:].isdigit():
        return int(priority[1:]), priority
    return 99, (priority or "P99")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_critical_rows(path: Path) -> list[dict[str, str]]:
    payload = _load_json(path)
    if not isinstance(payload, list):
        raise ValueError(f"critical technique file must be a JSON list: {path}")

    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for idx, entry in enumerate(payload):
        if isinstance(entry, str):
            technique = _normalize_technique(entry)
            row = {
                "technique": technique,
                "name": "",
                "owner": "unassigned",
                "eta": "unspecified",
                "priority": "P1",
            }
        elif isinstance(entry, dict):
            technique = _normalize_technique(entry.get("technique", ""))
            row = {
                "technique": technique,
                "name": str(entry.get("name", "")).strip(),
                "owner": str(entry.get("owner", "unassigned")).strip() or "unassigned",
                "eta": str(entry.get("eta", "unspecified")).strip() or "unspecified",
                "priority": str(entry.get("priority", "P1")).strip().upper() or "P1",
            }
        else:
            raise ValueError(f"invalid critical technique row at index {idx}")

        if not TECHNIQUE_RE.match(row["technique"]):
            raise ValueError(f"invalid ATT&CK technique id at index {idx}: {row['technique']}")
        if row["technique"] in seen:
            continue
        seen.add(row["technique"])
        rows.append(row)

    if not rows:
        raise ValueError("no critical ATT&CK techniques configured")
    return rows


def _observed_techniques(coverage_report: dict[str, Any]) -> set[str]:
    observed = coverage_report.get("observed_techniques", [])
    if not isinstance(observed, list):
        return set()
    out: set[str] = set()
    for item in observed:
        technique = _normalize_technique(item)
        if TECHNIQUE_RE.match(technique):
            out.add(technique)
    return out


def _previous_uncovered(previous_path: Path | None) -> set[str]:
    if previous_path is None or not previous_path.is_file():
        return set()
    payload = _load_json(previous_path)
    if not isinstance(payload, dict):
        return set()
    uncovered = payload.get("uncovered_critical_techniques", [])
    if not isinstance(uncovered, list):
        return set()
    return {
        _normalize_technique(item)
        for item in uncovered
        if TECHNIQUE_RE.match(_normalize_technique(item))
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate ATT&CK critical-technique burn-down scoreboard")
    parser.add_argument("--attack-coverage", required=True, help="Current attack coverage report JSON")
    parser.add_argument("--critical-techniques", required=True, help="Critical ATT&CK techniques JSON")
    parser.add_argument("--attack-gap", default="", help="Optional ATT&CK gap burn-down report JSON")
    parser.add_argument(
        "--previous-scoreboard",
        default="",
        help="Optional previous scoreboard JSON for trend comparison",
    )
    parser.add_argument("--output-json", required=True, help="Output scoreboard JSON")
    parser.add_argument("--output-md", required=True, help="Output scoreboard Markdown")
    return parser


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_markdown(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = _parser().parse_args()

    coverage_path = Path(args.attack_coverage)
    critical_path = Path(args.critical_techniques)
    gap_path = Path(args.attack_gap) if args.attack_gap else None
    previous_path = Path(args.previous_scoreboard) if args.previous_scoreboard else None
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)

    if not coverage_path.is_file():
        raise SystemExit(f"missing attack coverage report: {coverage_path}")
    if not critical_path.is_file():
        raise SystemExit(f"missing critical technique file: {critical_path}")

    coverage_report = _load_json(coverage_path)
    if not isinstance(coverage_report, dict):
        raise SystemExit("attack coverage report must be a JSON object")

    critical_rows = _load_critical_rows(critical_path)
    observed = _observed_techniques(coverage_report)

    previous_uncovered = _previous_uncovered(previous_path)

    gap_payload: dict[str, Any] = {}
    if gap_path is not None and gap_path.is_file():
        loaded_gap = _load_json(gap_path)
        if isinstance(loaded_gap, dict):
            gap_payload = loaded_gap

    records: list[dict[str, Any]] = []
    uncovered: list[str] = []
    for row in critical_rows:
        covered = row["technique"] in observed
        if not covered:
            uncovered.append(row["technique"])
        records.append(
            {
                "technique": row["technique"],
                "name": row["name"],
                "owner": row["owner"],
                "eta": row["eta"],
                "priority": row["priority"],
                "covered": covered,
            }
        )

    uncovered_records = [record for record in records if not record["covered"]]
    uncovered_records.sort(
        key=lambda record: (
            _priority_rank(record["priority"])[0],
            str(record["owner"]),
            str(record["technique"]),
        )
    )
    top_uncovered = uncovered_records[:10]

    uncovered_set = set(uncovered)
    newly_uncovered = sorted(uncovered_set - previous_uncovered)
    newly_covered = sorted(previous_uncovered - uncovered_set)

    covered_count = len(records) - len(uncovered)
    coverage_pct = 0.0 if not records else (covered_count * 100.0) / len(records)

    owner_backlog: dict[str, int] = {}
    for record in records:
        if record["covered"]:
            continue
        owner = str(record["owner"])
        owner_backlog[owner] = owner_backlog.get(owner, 0) + 1

    uncovered_by_priority_counts: dict[str, int] = {}
    for record in uncovered_records:
        priority = str(record["priority"])
        uncovered_by_priority_counts[priority] = uncovered_by_priority_counts.get(priority, 0) + 1
    uncovered_by_priority = {
        priority: count
        for priority, count in sorted(
            uncovered_by_priority_counts.items(),
            key=lambda item: (_priority_rank(item[0])[0], item[0]),
        )
    }

    scoreboard = {
        "suite": "attack_burndown_scoreboard",
        "recorded_at_utc": _now_utc(),
        "critical_total": len(records),
        "critical_covered_count": covered_count,
        "critical_uncovered_count": len(uncovered),
        "critical_coverage_pct": round(coverage_pct, 2),
        "critical_techniques": records,
        "uncovered_critical_techniques": sorted(uncovered),
        "uncovered_by_priority": uncovered_by_priority,
        "top_uncovered_critical_techniques": top_uncovered,
        "trend": {
            "newly_uncovered": newly_uncovered,
            "newly_covered": newly_covered,
            "delta_uncovered": (len(uncovered_set) - len(previous_uncovered))
            if previous_path is not None and previous_path.is_file()
            else None,
        },
        "owner_backlog": owner_backlog,
        "attack_gap_context": {
            "status": gap_payload.get("status") if gap_payload else None,
            "technique_gap": (gap_payload.get("current", {}) or {}).get("technique_gap")
            if gap_payload
            else None,
            "tactic_gap": (gap_payload.get("current", {}) or {}).get("tactic_gap")
            if gap_payload
            else None,
            "technique_gap_reduced_by": (gap_payload.get("burn_down", {}) or {}).get(
                "technique_gap_reduced_by"
            )
            if gap_payload
            else None,
            "tactic_gap_reduced_by": (gap_payload.get("burn_down", {}) or {}).get(
                "tactic_gap_reduced_by"
            )
            if gap_payload
            else None,
        },
    }

    _write_json(output_json, scoreboard)

    md_lines: list[str] = []
    md_lines.append("# ATT&CK Critical Technique Burn-down Scoreboard")
    md_lines.append("")
    md_lines.append(f"- Recorded at UTC: **{scoreboard['recorded_at_utc']}**")
    md_lines.append(f"- Critical techniques total: **{scoreboard['critical_total']}**")
    md_lines.append(f"- Covered: **{scoreboard['critical_covered_count']}**")
    md_lines.append(f"- Uncovered: **{scoreboard['critical_uncovered_count']}**")
    md_lines.append(f"- Coverage: **{scoreboard['critical_coverage_pct']}%**")
    md_lines.append("")

    trend = scoreboard["trend"]
    md_lines.append("## Trend vs Previous")
    md_lines.append("")
    if trend["delta_uncovered"] is None:
        md_lines.append("- Previous scoreboard baseline not available")
    else:
        md_lines.append(f"- Delta uncovered techniques: **{trend['delta_uncovered']}**")
        md_lines.append(f"- Newly covered: **{len(trend['newly_covered'])}**")
        md_lines.append(f"- Newly uncovered: **{len(trend['newly_uncovered'])}**")
    md_lines.append("")

    md_lines.append("## Owner Backlog")
    md_lines.append("")
    if owner_backlog:
        md_lines.append("| Owner | Uncovered Critical Techniques |")
        md_lines.append("| --- | ---: |")
        for owner, count in sorted(owner_backlog.items(), key=lambda item: (-item[1], item[0])):
            md_lines.append(f"| {owner} | {count} |")
    else:
        md_lines.append("- No uncovered critical techniques")
    md_lines.append("")

    md_lines.append("## Top Uncovered Critical Techniques")
    md_lines.append("")
    if top_uncovered:
        md_lines.append("| Technique | Priority | Owner | ETA | Name |")
        md_lines.append("| --- | --- | --- | --- | --- |")
        for record in top_uncovered:
            md_lines.append(
                "| {technique} | {priority} | {owner} | {eta} | {name} |".format(
                    technique=record["technique"],
                    priority=record["priority"],
                    owner=record["owner"],
                    eta=record["eta"],
                    name=record["name"] or "-",
                )
            )
    else:
        md_lines.append("- No uncovered critical techniques")
    md_lines.append("")

    md_lines.append("## Critical Techniques")
    md_lines.append("")
    md_lines.append("| Technique | Name | Priority | Owner | ETA | Covered |")
    md_lines.append("| --- | --- | --- | --- | --- | --- |")
    for record in records:
        covered = "yes" if record["covered"] else "no"
        md_lines.append(
            "| {technique} | {name} | {priority} | {owner} | {eta} | {covered} |".format(
                technique=record["technique"],
                name=record["name"] or "-",
                priority=record["priority"],
                owner=record["owner"],
                eta=record["eta"],
                covered=covered,
            )
        )

    _write_markdown(output_md, md_lines)

    print(f"wrote ATT&CK burn-down scoreboard JSON to {output_json}")
    print(f"wrote ATT&CK burn-down scoreboard Markdown to {output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
