#!/usr/bin/env python3
"""Enforce ATT&CK coverage breadth for bundled SIGMA and Elastic rules."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import yaml


ATTACK_TECHNIQUE_SUFFIX_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$")
ATTACK_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    return cleaned.strip("_")


# SigmaHQ renamed/split ATT&CK tactic tags (defense-evasion became
# stealth + defense-impairment). Normalize to canonical ATT&CK tactic
# slugs so required-tactic gates keep working across taxonomy renames.
TACTIC_ALIASES = {
    "stealth": "defense_evasion",
    "defense_impairment": "defense_evasion",
}

# attack.g#### / attack.s#### tags reference ATT&CK groups/software,
# not tactics; they must not inflate tactic coverage counts.
ATTACK_NON_TACTIC_SUFFIX_RE = re.compile(r"^[gs]\d{4}$")


def _normalize_tactic(value: str) -> str:
    slug = _slug(value)
    if not slug or ATTACK_NON_TACTIC_SUFFIX_RE.match(slug):
        return ""
    return TACTIC_ALIASES.get(slug, slug)


def _load_sigma_attack_coverage(sigma_dir: Path) -> tuple[int, int, set[str], set[str]]:
    total_rules = 0
    rules_with_attack = 0
    techniques: set[str] = set()
    tactics: set[str] = set()

    if not sigma_dir.is_dir():
        return total_rules, rules_with_attack, techniques, tactics

    for rule_path in sorted(list(sigma_dir.rglob("*.yml")) + list(sigma_dir.rglob("*.yaml"))):
        total_rules += 1
        try:
            docs = list(yaml.safe_load_all(rule_path.read_text(encoding="utf-8")))
        except Exception:
            continue

        rule_techniques: set[str] = set()
        rule_tactics: set[str] = set()
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            tags = doc.get("tags", [])
            if not isinstance(tags, list):
                continue
            for tag in tags:
                tag_raw = str(tag).strip().lower()
                if not tag_raw.startswith("attack."):
                    continue
                suffix = tag_raw.split(".", 1)[1]
                if ATTACK_TECHNIQUE_SUFFIX_RE.match(suffix):
                    rule_techniques.add(suffix.upper())
                else:
                    tactic = _normalize_tactic(suffix)
                    if tactic:
                        rule_tactics.add(tactic)

        if rule_techniques or rule_tactics:
            rules_with_attack += 1
        techniques.update(rule_techniques)
        tactics.update(rule_tactics)

    return total_rules, rules_with_attack, techniques, tactics


def _load_elastic_attack_coverage(elastic_jsonl: Path) -> tuple[int, int, set[str], set[str]]:
    total_rules = 0
    rules_with_attack = 0
    techniques: set[str] = set()
    tactics: set[str] = set()

    if not elastic_jsonl.is_file():
        return total_rules, rules_with_attack, techniques, tactics

    for line in elastic_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        total_rules += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        rule_techniques: set[str] = set()
        for entry in record.get("mitre_techniques", []):
            if not isinstance(entry, dict):
                continue
            technique_id = str(entry.get("id", "")).strip().upper()
            if ATTACK_TECHNIQUE_ID_RE.match(technique_id):
                rule_techniques.add(technique_id)

        rule_tactics: set[str] = set()
        for entry in record.get("mitre_tactics", []):
            if not isinstance(entry, dict):
                continue
            tactic_name = _normalize_tactic(str(entry.get("name", "")))
            if tactic_name:
                rule_tactics.add(tactic_name)

        if rule_techniques or rule_tactics:
            rules_with_attack += 1
        techniques.update(rule_techniques)
        tactics.update(rule_tactics)

    return total_rules, rules_with_attack, techniques, tactics


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate ATT&CK coverage minimums")
    parser.add_argument("--sigma-dir", required=True, help="Path to bundled sigma directory")
    parser.add_argument("--elastic-jsonl", required=True, help="Path to bundled elastic-rules.jsonl")
    parser.add_argument("--output", default="", help="Optional report output path")
    parser.add_argument("--manifest", default="", help="Optional bundle manifest for restricted-source skips")

    parser.add_argument("--min-techniques", type=int, default=80)
    parser.add_argument("--min-tactics", type=int, default=10)
    parser.add_argument("--min-sigma-rules-with-attack", type=int, default=150)
    parser.add_argument("--min-elastic-rules-with-attack", type=int, default=50)
    parser.add_argument("--min-sigma-techniques", type=int, default=60)
    parser.add_argument("--min-elastic-techniques", type=int, default=20)
    parser.add_argument(
        "--require-tactic",
        action="append",
        default=[],
        help="Require ATT&CK tactic slug (repeatable), e.g. command_and_control",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    elastic_restricted_excluded = False
    if args.manifest:
        manifest_path = Path(args.manifest)
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            marker = manifest.get("restricted_sources", {}).get("elastic", {})
            elastic_restricted_excluded = (
                isinstance(marker, dict) and marker.get("status") == "restricted_excluded"
            )

    sigma_total, sigma_with_attack, sigma_techniques, sigma_tactics = _load_sigma_attack_coverage(
        Path(args.sigma_dir)
    )
    elastic_total, elastic_with_attack, elastic_techniques, elastic_tactics = _load_elastic_attack_coverage(
        Path(args.elastic_jsonl)
    )

    total_techniques = sigma_techniques | elastic_techniques
    total_tactics = sigma_tactics | elastic_tactics
    required_tactics = sorted({_normalize_tactic(t) for t in args.require_tactic if _normalize_tactic(t)})
    missing_required_tactics = sorted([t for t in required_tactics if t not in total_tactics])

    measured = {
        "sigma_rules_total": sigma_total,
        "sigma_rules_with_attack": sigma_with_attack,
        "sigma_techniques_count": len(sigma_techniques),
        "sigma_tactics_count": len(sigma_tactics),
        "elastic_rules_total": elastic_total,
        "elastic_rules_with_attack": elastic_with_attack,
        "elastic_techniques_count": len(elastic_techniques),
        "elastic_tactics_count": len(elastic_tactics),
        "total_techniques": len(total_techniques),
        "total_tactics": len(total_tactics),
    }

    thresholds = {
        "min_techniques": args.min_techniques,
        "min_tactics": args.min_tactics,
        "min_sigma_rules_with_attack": args.min_sigma_rules_with_attack,
        "min_elastic_rules_with_attack": args.min_elastic_rules_with_attack,
        "min_sigma_techniques": args.min_sigma_techniques,
        "min_elastic_techniques": args.min_elastic_techniques,
        "required_tactics": required_tactics,
    }

    checks = [
        ("total_techniques", measured["total_techniques"], args.min_techniques),
        ("total_tactics", measured["total_tactics"], args.min_tactics),
        (
            "sigma_rules_with_attack",
            measured["sigma_rules_with_attack"],
            args.min_sigma_rules_with_attack,
        ),
        ("sigma_techniques_count", measured["sigma_techniques_count"], args.min_sigma_techniques),
    ]
    if not elastic_restricted_excluded:
        checks.extend([
            (
                "elastic_rules_with_attack",
                measured["elastic_rules_with_attack"],
                args.min_elastic_rules_with_attack,
            ),
            (
                "elastic_techniques_count",
                measured["elastic_techniques_count"],
                args.min_elastic_techniques,
            ),
        ])

    failures: list[str] = []
    for label, actual, minimum in checks:
        if actual < minimum:
            failures.append(f"{label} too low: {actual} < {minimum}")
    if missing_required_tactics:
        failures.append("missing required ATT&CK tactics: " + ", ".join(missing_required_tactics))

    report = {
        "suite": "attack_coverage_gate",
        "status": "fail" if failures else "pass",
        "thresholds": thresholds,
        "measured": measured,
        "failures": failures,
        "restricted_excluded": {"elastic": elastic_restricted_excluded},
        "observed_tactics": sorted(total_tactics),
        "observed_techniques": sorted(total_techniques),
        "missing_required_tactics": missing_required_tactics,
    }

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("ATT&CK coverage snapshot:")
    for key in (
        "sigma_rules_total",
        "sigma_rules_with_attack",
        "sigma_techniques_count",
        "elastic_rules_total",
        "elastic_rules_with_attack",
        "elastic_techniques_count",
        "total_techniques",
        "total_tactics",
    ):
        print(f"- {key}: {measured[key]}")

    if failures:
        print("\nATT&CK coverage gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nATT&CK coverage gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
