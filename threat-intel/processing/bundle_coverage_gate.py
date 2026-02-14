#!/usr/bin/env python3
"""Enforce minimum threat-intel signature database coverage from a bundle manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _to_int(manifest: dict, field: str) -> int:
    value = manifest.get(field, 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_sources(manifest: dict, field: str) -> int:
    sources = manifest.get("sources", {}).get(field, [])
    if isinstance(sources, list):
        return sum(1 for src in sources if str(src).strip())
    if isinstance(sources, str):
        return 1 if sources.strip() else 0
    return 0


def _source_set(manifest: dict, field: str) -> set[str]:
    sources = manifest.get("sources", {}).get(field, [])
    if isinstance(sources, str):
        candidate = sources.strip()
        return {candidate} if candidate else set()
    if not isinstance(sources, list):
        return set()
    return {str(source).strip() for source in sources if str(source).strip()}


def _source_rule_counts(manifest: dict, field: str) -> dict[str, int]:
    raw = manifest.get("source_rule_counts", {}).get(field, {})
    if not isinstance(raw, dict):
        return {}

    counts: dict[str, int] = {}
    for name, value in raw.items():
        source_name = str(name).strip()
        if not source_name:
            continue
        try:
            counts[source_name] = int(value)
        except (TypeError, ValueError):
            counts[source_name] = 0
    return counts


def _parse_named_minimums(raw_values: list[str], label: str) -> tuple[dict[str, int], list[str]]:
    parsed: dict[str, int] = {}
    errors: list[str] = []

    for raw in raw_values:
        value = str(raw).strip()
        if not value:
            continue

        if "=" in value:
            name, min_value = value.split("=", 1)
        elif ":" in value:
            name, min_value = value.split(":", 1)
        else:
            errors.append(f"invalid {label} minimum format '{value}', expected name=count")
            continue

        source_name = name.strip()
        if not source_name:
            errors.append(f"invalid {label} minimum '{value}', missing source name")
            continue

        try:
            minimum = int(min_value.strip())
        except ValueError:
            errors.append(f"invalid {label} minimum '{value}', count is not an integer")
            continue

        if minimum < 0:
            errors.append(f"invalid {label} minimum '{value}', count must be >= 0")
            continue

        parsed[source_name] = minimum

    return parsed, errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate bundle signature/intel coverage against minimum thresholds"
    )
    parser.add_argument("--manifest", required=True, help="Path to bundle manifest.json")
    parser.add_argument("--output", default="", help="Optional JSON output report path")

    parser.add_argument("--min-sigma", type=int, default=150)
    parser.add_argument("--min-yara", type=int, default=600)
    parser.add_argument("--min-ioc-hash", type=int, default=1000)
    parser.add_argument("--min-ioc-domain", type=int, default=300)
    parser.add_argument("--min-ioc-ip", type=int, default=1500)
    parser.add_argument("--min-cve", type=int, default=1000)
    parser.add_argument("--min-cve-kev", type=int, default=50)
    parser.add_argument("--min-signature-total", type=int, default=900)
    parser.add_argument("--min-database-total", type=int, default=5000)
    parser.add_argument("--min-yara-sources", type=int, default=3)
    parser.add_argument("--min-sigma-sources", type=int, default=2)

    parser.add_argument("--min-suricata", type=int, default=1000)
    parser.add_argument("--min-elastic", type=int, default=100)
    parser.add_argument(
        "--require-suricata",
        action="store_true",
        help="Fail gate if Suricata coverage is below minimum",
    )
    parser.add_argument(
        "--require-elastic",
        action="store_true",
        help="Fail gate if Elastic coverage is below minimum",
    )
    parser.add_argument(
        "--require-yara-source",
        action="append",
        default=[],
        help="Require specific YARA source name (repeatable)",
    )
    parser.add_argument(
        "--require-sigma-source",
        action="append",
        default=[],
        help="Require specific SIGMA source name (repeatable)",
    )
    parser.add_argument(
        "--min-yara-source-rules",
        action="append",
        default=[],
        help="Per-source minimum YARA rule count (name=count), repeatable",
    )
    parser.add_argument(
        "--min-sigma-source-rules",
        action="append",
        default=[],
        help="Per-source minimum SIGMA rule count (name=count), repeatable",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    manifest_path = Path(args.manifest)

    if not manifest_path.is_file():
        print(f"coverage gate failed: manifest not found: {manifest_path}")
        return 1

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"coverage gate failed: invalid manifest JSON: {exc}")
        return 1

    measured = {
        "sigma_count": _to_int(manifest, "sigma_count"),
        "yara_count": _to_int(manifest, "yara_count"),
        "ioc_hash_count": _to_int(manifest, "ioc_hash_count"),
        "ioc_domain_count": _to_int(manifest, "ioc_domain_count"),
        "ioc_ip_count": _to_int(manifest, "ioc_ip_count"),
        "cve_count": _to_int(manifest, "cve_count"),
        "cve_kev_count": _to_int(manifest, "cve_kev_count"),
        "suricata_count": _to_int(manifest, "suricata_count"),
        "elastic_count": _to_int(manifest, "elastic_count"),
        "yara_source_count": _parse_sources(manifest, "yara"),
        "sigma_source_count": _parse_sources(manifest, "sigma"),
    }
    yara_sources = _source_set(manifest, "yara")
    sigma_sources = _source_set(manifest, "sigma")
    yara_source_rule_counts = _source_rule_counts(manifest, "yara")
    sigma_source_rule_counts = _source_rule_counts(manifest, "sigma")
    measured["ioc_total"] = (
        measured["ioc_hash_count"] + measured["ioc_domain_count"] + measured["ioc_ip_count"]
    )
    measured["signature_total"] = (
        measured["sigma_count"]
        + measured["yara_count"]
        + measured["suricata_count"]
        + measured["elastic_count"]
    )
    measured["database_total"] = (
        measured["signature_total"] + measured["ioc_total"] + measured["cve_count"]
    )

    thresholds = {
        "min_sigma": args.min_sigma,
        "min_yara": args.min_yara,
        "min_ioc_hash": args.min_ioc_hash,
        "min_ioc_domain": args.min_ioc_domain,
        "min_ioc_ip": args.min_ioc_ip,
        "min_cve": args.min_cve,
        "min_cve_kev": args.min_cve_kev,
        "min_signature_total": args.min_signature_total,
        "min_database_total": args.min_database_total,
        "min_yara_sources": args.min_yara_sources,
        "min_sigma_sources": args.min_sigma_sources,
        "min_suricata": args.min_suricata,
        "min_elastic": args.min_elastic,
        "require_suricata": args.require_suricata,
        "require_elastic": args.require_elastic,
        "required_yara_sources": args.require_yara_source,
        "required_sigma_sources": args.require_sigma_source,
        "min_yara_source_rules": args.min_yara_source_rules,
        "min_sigma_source_rules": args.min_sigma_source_rules,
    }

    min_yara_source_rules, yara_source_rule_errors = _parse_named_minimums(
        args.min_yara_source_rules,
        "yara",
    )
    min_sigma_source_rules, sigma_source_rule_errors = _parse_named_minimums(
        args.min_sigma_source_rules,
        "sigma",
    )
    thresholds["min_yara_source_rules"] = min_yara_source_rules
    thresholds["min_sigma_source_rules"] = min_sigma_source_rules

    checks = [
        ("sigma_count", measured["sigma_count"], args.min_sigma),
        ("yara_count", measured["yara_count"], args.min_yara),
        ("ioc_hash_count", measured["ioc_hash_count"], args.min_ioc_hash),
        ("ioc_domain_count", measured["ioc_domain_count"], args.min_ioc_domain),
        ("ioc_ip_count", measured["ioc_ip_count"], args.min_ioc_ip),
        ("cve_count", measured["cve_count"], args.min_cve),
        ("cve_kev_count", measured["cve_kev_count"], args.min_cve_kev),
        ("signature_total", measured["signature_total"], args.min_signature_total),
        ("database_total", measured["database_total"], args.min_database_total),
        ("yara_source_count", measured["yara_source_count"], args.min_yara_sources),
        ("sigma_source_count", measured["sigma_source_count"], args.min_sigma_sources),
    ]
    if args.require_suricata:
        checks.append(("suricata_count", measured["suricata_count"], args.min_suricata))
    if args.require_elastic:
        checks.append(("elastic_count", measured["elastic_count"], args.min_elastic))

    failures: list[str] = []
    failures.extend(yara_source_rule_errors)
    failures.extend(sigma_source_rule_errors)
    for label, actual, minimum in checks:
        if actual < minimum:
            failures.append(f"{label} coverage too low: {actual} < {minimum}")

    missing_yara_sources = sorted(
        required for required in args.require_yara_source if required and required not in yara_sources
    )
    missing_sigma_sources = sorted(
        required for required in args.require_sigma_source if required and required not in sigma_sources
    )
    if missing_yara_sources:
        failures.append(
            "missing required YARA sources: " + ", ".join(missing_yara_sources)
        )
    if missing_sigma_sources:
        failures.append(
            "missing required SIGMA sources: " + ", ".join(missing_sigma_sources)
        )

    for source_name, minimum in sorted(min_yara_source_rules.items()):
        actual = yara_source_rule_counts.get(source_name, 0)
        if actual < minimum:
            failures.append(
                f"yara source {source_name} rule coverage too low: {actual} < {minimum}"
            )

    for source_name, minimum in sorted(min_sigma_source_rules.items()):
        actual = sigma_source_rule_counts.get(source_name, 0)
        if actual < minimum:
            failures.append(
                f"sigma source {source_name} rule coverage too low: {actual} < {minimum}"
            )

    report = {
        "suite": "bundle_signature_coverage_gate",
        "version": manifest.get("version", ""),
        "thresholds": thresholds,
        "measured": measured,
        "status": "fail" if failures else "pass",
        "failures": failures,
        "observed_sources": {
            "yara": sorted(yara_sources),
            "sigma": sorted(sigma_sources),
        },
        "observed_source_rule_counts": {
            "yara": yara_source_rule_counts,
            "sigma": sigma_source_rule_counts,
        },
        "missing_required_sources": {
            "yara": missing_yara_sources,
            "sigma": missing_sigma_sources,
        },
    }

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Bundle signature database coverage snapshot:")
    for key in (
        "sigma_count",
        "yara_count",
        "suricata_count",
        "elastic_count",
        "ioc_hash_count",
        "ioc_domain_count",
        "ioc_ip_count",
        "cve_count",
        "cve_kev_count",
        "signature_total",
        "database_total",
        "yara_source_count",
        "sigma_source_count",
    ):
        print(f"- {key}: {measured[key]}")

    if failures:
        print("\nBundle signature coverage gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nBundle signature coverage gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
