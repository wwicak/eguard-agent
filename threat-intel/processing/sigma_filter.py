#!/usr/bin/env python3
"""Filter and deduplicate SIGMA rules from multiple sources for eGuard."""

import argparse
import json
import re
import os
import shutil
import sys

import yaml


VALID_STATUSES = {"stable", "test"}
WINDOWS_ONLY_PRODUCTS = {"windows", "microsoft365", "azure", "office365"}
WINDOWS_ONLY_SERVICES = {
    "sysmon", "powershell", "powershell-classic", "windefend",
    "bits-client", "wmi", "ntlm", "security", "system",
    "application", "taskscheduler", "dns-server-analytic",
}


def load_first_rule_doc(path: str) -> dict | None:
    """Load and validate the first YAML document in a SIGMA file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception as exc:
        print(f"  SKIP (parse error): {path}: {exc}", file=sys.stderr)
        return None

    if not docs or docs[0] is None:
        return None

    rule = docs[0]
    if not isinstance(rule, dict):
        print(f"  SKIP (invalid top-level rule doc): {path}", file=sys.stderr)
        return None

    return rule


def should_keep_rule(rule: dict, platforms: set[str], min_status: str) -> bool:
    """Decide whether a parsed SIGMA rule should be included."""

    # Check status
    status = str(rule.get("status") or "").strip().lower()
    allowed = VALID_STATUSES if min_status == "test" else {"stable"}
    if status not in allowed:
        return False

    # Check logsource
    logsource = rule.get("logsource", {})
    if not isinstance(logsource, dict):
        return False

    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()
    if service or logsource.get("category") not in {"process_creation", "file_event", "network_connection", "dns"}:
        return False

    # Exclude explicitly Windows-only rules
    if product in WINDOWS_ONLY_PRODUCTS:
        return False
    if service in WINDOWS_ONLY_SERVICES and product not in platforms:
        return False

    # If product is set and is a target platform, keep it
    if product and product in platforms:
        return True

    # If product is not set (generic rule), keep it unless service is Windows-only
    if not product:
        if service in WINDOWS_ONLY_SERVICES:
            return False
        return True

    # Product is set but not in our target platforms — skip
    return False


def get_rule_id(path: str) -> str | None:
    """Extract the rule UUID from a SIGMA YAML file."""
    rule = load_first_rule_doc(path)
    if isinstance(rule, dict):
        return rule.get("id")
    return None


def main():
    parser = argparse.ArgumentParser(description="Filter SigmaHQ rules for eGuard")
    parser.add_argument(
        "--input", required=True, action="append",
        help="Input directory of SIGMA rules (can be specified multiple times)",
    )
    parser.add_argument("--output", required=True, help="Output directory for filtered rules")
    parser.add_argument(
        "--platforms", default="linux",
        help="Comma-separated target platforms (default: linux)",
    )
    parser.add_argument(
        "--min-status", choices=["stable", "test"], default="test",
        help="Minimum status to include (default: test)",
    )
    parser.add_argument("--source-commit", default="", help="Pinned upstream commit for provenance")
    args = parser.parse_args()
    if args.source_commit and not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("source-commit must be a full git commit")

    platforms = {p.strip().lower() for p in args.platforms.split(",")}
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    total = 0
    kept = 0
    dedup_skipped = 0
    seen_ids: set[str] = set()
    provenance = {}

    for input_path in args.input:
        input_dir = os.path.abspath(input_path)
        if not os.path.isdir(input_dir):
            print(f"  SKIP (not a directory): {input_dir}", file=sys.stderr)
            continue

        source_name = os.path.basename(input_dir)
        if source_name in {"mdecrevoisier", "joesecurity", "tsale", "rules-threat-hunting"}:
            print(f"  SKIP (restricted source or hunting-only): {source_name}")
            continue
        source_kept = 0

        for root, _dirs, files in os.walk(input_dir):
            for fname in files:
                if not fname.endswith((".yml", ".yaml")):
                    continue
                total += 1
                src = os.path.join(root, fname)

                rule = load_first_rule_doc(src)
                if not isinstance(rule, dict):
                    continue

                # Dedup by rule ID (UUID)
                rule_id = rule.get("id")
                if rule_id:
                    if rule_id in seen_ids:
                        dedup_skipped += 1
                        continue

                if should_keep_rule(rule, platforms, args.min_status):
                    if rule_id:
                        seen_ids.add(rule_id)
                    # Preserve subdirectory structure, prefixed by source
                    rel = os.path.relpath(src, input_dir)
                    dst = os.path.join(output_dir, source_name, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
                    if args.source_commit:
                        provenance[os.path.relpath(dst, output_dir)] = {"source_path": f"{source_name}/{rel}", "id": rule_id, "commit": args.source_commit}
                    kept += 1
                    source_kept += 1

        print(f"  {source_name}: {source_kept} rules kept")

    if args.source_commit:
        with open(os.path.join(output_dir, "sigma-provenance.json"), "w", encoding="utf-8") as handle:
            json.dump({"commit": args.source_commit, "rules": provenance}, handle, sort_keys=True, indent=2)

    print(
        f"Sigma filter: {kept}/{total} rules kept "
        f"(platforms={platforms}, min_status={args.min_status}, "
        f"{dedup_skipped} dedup skipped)"
    )


if __name__ == "__main__":
    main()
