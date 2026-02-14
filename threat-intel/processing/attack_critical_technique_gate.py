#!/usr/bin/env python3
"""Enforce critical ATT&CK technique floor coverage."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _normalize_technique(raw: str) -> str:
    return str(raw).strip().upper()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_critical_techniques(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"critical techniques file must be a JSON list: {path}")

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
            raise ValueError(f"invalid critical technique entry at index {idx}")

        if not TECHNIQUE_ID_RE.match(row["technique"]):
            raise ValueError(f"invalid ATT&CK technique id at index {idx}: {row['technique']}")
        if row["technique"] in seen:
            continue
        seen.add(row["technique"])
        rows.append(row)

    if not rows:
        raise ValueError("critical technique set is empty")
    return rows


def _observed_techniques(coverage_report: dict[str, Any]) -> set[str]:
    observed = coverage_report.get("observed_techniques", [])
    if not isinstance(observed, list):
        return set()

    out: set[str] = set()
    for item in observed:
        technique = _normalize_technique(item)
        if TECHNIQUE_ID_RE.match(technique):
            out.add(technique)
    return out


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate coverage for critical ATT&CK techniques")
    parser.add_argument("--attack-coverage", required=True, help="ATT&CK coverage report JSON")
    parser.add_argument(
        "--critical-techniques",
        required=True,
        help="JSON file containing critical ATT&CK techniques",
    )
    parser.add_argument("--output", required=True, help="Gate report output JSON")
    parser.add_argument("--min-covered-count", type=int, default=20)
    parser.add_argument("--min-covered-ratio", type=float, default=0.0)
    parser.add_argument("--max-missing-count", type=int, default=0)
    parser.add_argument(
        "--require-technique",
        action="append",
        default=[],
        help="Explicitly required ATT&CK technique id (repeatable)",
    )
    return parser


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = _parser().parse_args()

    coverage_path = Path(args.attack_coverage)
    critical_path = Path(args.critical_techniques)
    output_path = Path(args.output)

    if not coverage_path.is_file():
        report = {
            "suite": "attack_critical_technique_gate",
            "status": "fail",
            "failures": [f"missing attack coverage report: {coverage_path}"],
        }
        _write_report(output_path, report)
        print(report["failures"][0])
        return 1

    if not critical_path.is_file():
        report = {
            "suite": "attack_critical_technique_gate",
            "status": "fail",
            "failures": [f"missing critical technique file: {critical_path}"],
        }
        _write_report(output_path, report)
        print(report["failures"][0])
        return 1

    if args.min_covered_ratio < 0.0 or args.min_covered_ratio > 1.0:
        report = {
            "suite": "attack_critical_technique_gate",
            "status": "fail",
            "failures": [
                f"invalid min-covered-ratio: {args.min_covered_ratio} (expected 0.0..1.0)"
            ],
        }
        _write_report(output_path, report)
        print(report["failures"][0])
        return 1

    try:
        coverage_report = _load_json(coverage_path)
        critical_rows = _load_critical_techniques(critical_path)
    except Exception as err:
        report = {
            "suite": "attack_critical_technique_gate",
            "status": "fail",
            "failures": [str(err)],
        }
        _write_report(output_path, report)
        print(str(err))
        return 1

    observed = _observed_techniques(coverage_report)
    critical_required = {_normalize_technique(item) for item in args.require_technique if item}

    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for row in critical_rows:
        covered = row["technique"] in observed
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
        if not covered:
            missing.append(row["technique"])

    missing_required = sorted([technique for technique in critical_required if technique not in observed])
    covered_count = len(records) - len(missing)
    covered_ratio = 0.0 if not records else covered_count / len(records)

    failures: list[str] = []
    if covered_count < args.min_covered_count:
        failures.append(
            f"critical technique coverage too low: covered={covered_count} < min={args.min_covered_count}"
        )
    if covered_ratio < args.min_covered_ratio:
        failures.append(
            "critical technique coverage ratio too low: "
            f"covered_ratio={covered_ratio:.4f} < min={args.min_covered_ratio:.4f}"
        )
    if len(missing) > args.max_missing_count:
        failures.append(
            f"critical missing techniques too high: missing={len(missing)} > max={args.max_missing_count}"
        )
    if missing_required:
        failures.append(
            "required critical ATT&CK techniques missing: " + ", ".join(missing_required)
        )

    report = {
        "suite": "attack_critical_technique_gate",
        "status": "fail" if failures else "pass",
        "thresholds": {
            "min_covered_count": args.min_covered_count,
            "min_covered_ratio": args.min_covered_ratio,
            "max_missing_count": args.max_missing_count,
            "required_techniques": sorted(critical_required),
        },
        "measured": {
            "critical_total": len(records),
            "covered_count": covered_count,
            "covered_ratio": round(covered_ratio, 4),
            "missing_count": len(missing),
        },
        "missing_techniques": sorted(missing),
        "missing_required_techniques": missing_required,
        "critical_techniques": records,
    }

    _write_report(output_path, report)

    print("Critical ATT&CK technique coverage snapshot:")
    print(f"- critical total: {len(records)}")
    print(f"- covered count: {covered_count}")
    print(f"- covered ratio: {covered_ratio:.4f}")
    print(f"- missing count: {len(missing)}")

    if failures:
        print("\nCritical ATT&CK technique gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nCritical ATT&CK technique gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
