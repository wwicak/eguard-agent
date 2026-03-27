#!/usr/bin/env python3
"""Quality gate for IOC behavior JSON payloads.

Checks three dimensions:
1) load time (JSON decode latency)
2) accuracy (schema-valid rule ratio)
3) coverability (tactic/technique/matcher coverage)
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
ALLOWED_PLATFORM = {"", "linux", "windows", "macos"}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def load_rules(path: Path) -> tuple[list[dict[str, Any]], float]:
    start = time.perf_counter()
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError("empty file")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # NDJSON fallback
        rules: list[dict[str, Any]] = []
        for idx, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"ndjson line {idx} is not object")
            rules.append(item)
        elapsed = (time.perf_counter() - start) * 1000.0
        return rules, elapsed

    if isinstance(parsed, dict):
        if isinstance(parsed.get("rules"), list):
            rules = [r for r in parsed["rules"] if isinstance(r, dict)]
        else:
            rules = [parsed]
    elif isinstance(parsed, list):
        rules = [r for r in parsed if isinstance(r, dict)]
    else:
        raise ValueError("json payload must be object/list/ndjson")

    elapsed = (time.perf_counter() - start) * 1000.0
    return rules, elapsed


def validate_rule(rule: dict[str, Any]) -> tuple[bool, list[str], set[str]]:
    errors: list[str] = []

    name = str(rule.get("name", "")).strip()
    if not name:
        errors.append("missing_name")

    sev = str(rule.get("severity", "medium")).strip().lower()
    if sev not in ALLOWED_SEVERITY:
        errors.append("invalid_severity")

    platform = str(rule.get("platform", "")).strip().lower()
    if platform not in ALLOWED_PLATFORM:
        errors.append("invalid_platform")

    matchers = {
        "cmdline_contains": _as_list(rule.get("cmdline_contains")),
        "cmdline_all_contains": _as_list(rule.get("cmdline_all_contains")),
        "process_names": _as_list(rule.get("process_names")),
        "file_path_suffix": _as_list(rule.get("file_path_suffix")),
    }
    used_matchers = {k for k, v in matchers.items() if v}
    if not used_matchers:
        errors.append("empty_match_criteria")

    return len(errors) == 0, errors, used_matchers


def main() -> int:
    p = argparse.ArgumentParser(description="Validate IOC behavior JSON quality")
    p.add_argument("--input", required=True, help="Path to ioc_behavior_rules.json")
    p.add_argument("--output", default="", help="Optional JSON metrics output path")
    p.add_argument("--max-load-ms", type=float, default=1000.0)
    p.add_argument("--min-rules", type=int, default=20)
    p.add_argument("--min-tactics", type=int, default=6)
    p.add_argument("--min-techniques", type=int, default=12)
    p.add_argument("--min-matcher-types", type=int, default=3)
    args = p.parse_args()

    src = Path(args.input)
    if not src.is_file():
        raise SystemExit(f"input file not found: {src}")

    rules, load_ms = load_rules(src)

    valid = 0
    invalid = 0
    invalid_reasons: dict[str, int] = {}
    tactics: set[str] = set()
    techniques: set[str] = set()
    platforms: set[str] = set()
    matcher_types: set[str] = set()

    for rule in rules:
        ok, errs, used_matchers = validate_rule(rule)
        if ok:
            valid += 1
        else:
            invalid += 1
            for e in errs:
                invalid_reasons[e] = invalid_reasons.get(e, 0) + 1

        tactic = str(rule.get("mitre_tactic", "")).strip().lower()
        if tactic:
            tactics.add(tactic)

        technique = str(rule.get("mitre_technique", "")).strip().upper()
        if technique:
            techniques.add(technique)

        platform = str(rule.get("platform", "")).strip().lower()
        if platform:
            platforms.add(platform)

        matcher_types.update(used_matchers)

    total = len(rules)
    accuracy_pct = (valid * 100.0 / total) if total else 0.0

    metrics = {
        "input": str(src),
        "total_rules": total,
        "valid_rules": valid,
        "invalid_rules": invalid,
        "accuracy_pct": round(accuracy_pct, 2),
        "load_time_ms": round(load_ms, 3),
        "tactic_coverage_count": len(tactics),
        "technique_coverage_count": len(techniques),
        "platform_coverage": sorted(platforms),
        "matcher_type_coverage": sorted(matcher_types),
        "invalid_reasons": invalid_reasons,
    }

    failed_checks: list[str] = []
    if total < args.min_rules:
        failed_checks.append(f"rule_count {total} < min_rules {args.min_rules}")
    if load_ms > args.max_load_ms:
        failed_checks.append(f"load_time_ms {load_ms:.3f} > max_load_ms {args.max_load_ms:.3f}")
    if accuracy_pct < 100.0:
        failed_checks.append(f"accuracy_pct {accuracy_pct:.2f} < 100.00")
    if len(tactics) < args.min_tactics:
        failed_checks.append(f"tactic_coverage {len(tactics)} < min_tactics {args.min_tactics}")
    if len(techniques) < args.min_techniques:
        failed_checks.append(f"technique_coverage {len(techniques)} < min_techniques {args.min_techniques}")
    if len(matcher_types) < args.min_matcher_types:
        failed_checks.append(
            f"matcher_type_coverage {len(matcher_types)} < min_matcher_types {args.min_matcher_types}"
        )

    metrics["status"] = "pass" if not failed_checks else "fail"
    metrics["failed_checks"] = failed_checks

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    print("=== IOC behavior quality gate ===")
    print(json.dumps(metrics, indent=2))

    if failed_checks:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
