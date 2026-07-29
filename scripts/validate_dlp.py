#!/usr/bin/env python3
"""Validate the MVP DLP pack and synthetic fixtures without third-party deps."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "dlp/rules/indonesia.json"
FIXTURES = ROOT / "dlp/fixtures/indonesia.json"
REQUIRED_RULE_FIELDS = {
    "id", "name", "pattern", "validator", "context", "severity",
    "default_action", "regulations", "redaction", "max_matches",
}
VALIDATORS = {"context_only", "context_cluster", "luhn", "nik_indonesia",
              "npwp_indonesia", "phone_indonesia"}
SEVERITIES = {"low", "medium", "high", "critical"}
ACTIONS = {"audit", "alert"}
REDACTIONS = {"mask_middle", "last4"}


def fail(message: str) -> None:
    raise ValueError(message)


def load(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: {exc}")


def validate_pack(pack: dict) -> dict[str, dict]:
    if pack.get("schema_version") != "1":
        fail("schema_version must be '1'")
    if pack.get("pack_id") != "indonesia":
        fail("pack_id must be 'indonesia'")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(pack.get("version", ""))):
        fail("version must be semver")
    rules = pack.get("rules")
    if not isinstance(rules, list) or not rules:
        fail("rules must be a non-empty array")

    by_id: dict[str, dict] = {}
    for index, rule in enumerate(rules):
        missing = REQUIRED_RULE_FIELDS - rule.keys()
        if missing:
            fail(f"rule[{index}] missing fields: {sorted(missing)}")
        rule_id = rule["id"]
        if rule_id in by_id:
            fail(f"duplicate rule id: {rule_id}")
        if not re.fullmatch(r"id\.[a-z0-9_.-]+", rule_id):
            fail(f"invalid rule id: {rule_id}")
        if len(rule["pattern"]) > 1024:
            fail(f"{rule_id}: regex exceeds 1024 characters")
        try:
            re.compile(rule["pattern"])
        except re.error as exc:
            fail(f"{rule_id}: invalid regex: {exc}")
        if rule["validator"] not in VALIDATORS:
            fail(f"{rule_id}: unsupported validator {rule['validator']}")
        if rule["severity"] not in SEVERITIES:
            fail(f"{rule_id}: unsupported severity")
        if rule["default_action"] not in ACTIONS:
            fail(f"{rule_id}: block is not allowed in MVP default packs")
        if not isinstance(rule["context"], list) or not rule["context"]:
            fail(f"{rule_id}: context must be non-empty")
        if not isinstance(rule["regulations"], list) or not rule["regulations"]:
            fail(f"{rule_id}: regulations must be non-empty")
        if rule["redaction"] not in REDACTIONS:
            fail(f"{rule_id}: unsupported redaction")
        if not isinstance(rule["max_matches"], int) or rule["max_matches"] <= 0:
            fail(f"{rule_id}: max_matches must be positive")
        by_id[rule_id] = rule
    return by_id


def validate_fixtures(rules: dict[str, dict], fixtures: dict) -> None:
    for section in ("positive", "negative"):
        cases = fixtures.get(section)
        if not isinstance(cases, list) or not cases:
            fail(f"fixtures.{section} must be a non-empty array")
        for index, case in enumerate(cases):
            rule_id = case.get("rule_id")
            if rule_id not in rules:
                fail(f"{section}[{index}]: unknown rule {rule_id}")
            if not isinstance(case.get("text"), str):
                fail(f"{section}[{index}]: text must be a string")
            if case.get("expected_matches") not in (0, 1):
                fail(f"{section}[{index}]: expected_matches must be 0 or 1")
            rule = rules[rule_id]
            matches = list(re.finditer(rule["pattern"], case["text"], re.IGNORECASE))
            if rule["validator"] in {"context_only", "context_cluster", "nik_indonesia", "npwp_indonesia", "phone_indonesia", "luhn"}:
                lowered = case["text"].casefold()
                matches = [match for match in matches if any(term.casefold() in lowered for term in rule["context"])]
            actual = min(len(matches), 1)
            expected = case["expected_matches"]
            if actual != expected:
                fail(f"{section}[{index}] {rule_id}: expected {expected}, got {actual}: {case['text']!r}")


def main() -> int:
    try:
        rules = validate_pack(load(RULES))
        validate_fixtures(rules, load(FIXTURES))
    except ValueError as exc:
        print(f"DLP validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"DLP validation passed: {len(rules)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
