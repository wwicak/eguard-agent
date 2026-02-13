#!/usr/bin/env python3
"""Filter and deduplicate SIGMA rules from multiple sources for eGuard."""

import argparse
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


def should_keep_rule(path: str, platforms: set[str], min_status: str) -> bool:
    """Decide whether a SIGMA rule file should be included."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception as exc:
        print(f"  SKIP (parse error): {path}: {exc}", file=sys.stderr)
        return False

    if not docs or docs[0] is None:
        return False

    rule = docs[0]

    # Check status
    status = rule.get("status", "").lower()
    allowed = VALID_STATUSES if min_status == "test" else {"stable"}
    if status not in allowed:
        return False

    # Check logsource
    logsource = rule.get("logsource", {})
    if not isinstance(logsource, dict):
        return False

    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()

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
    try:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        if docs and docs[0] and isinstance(docs[0], dict):
            return docs[0].get("id")
    except Exception:
        pass
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
    args = parser.parse_args()

    platforms = {p.strip().lower() for p in args.platforms.split(",")}
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    total = 0
    kept = 0
    dedup_skipped = 0
    seen_ids: set[str] = set()

    for input_path in args.input:
        input_dir = os.path.abspath(input_path)
        if not os.path.isdir(input_dir):
            print(f"  SKIP (not a directory): {input_dir}", file=sys.stderr)
            continue

        source_name = os.path.basename(input_dir)
        source_kept = 0

        for root, _dirs, files in os.walk(input_dir):
            for fname in files:
                if not fname.endswith((".yml", ".yaml")):
                    continue
                total += 1
                src = os.path.join(root, fname)

                # Dedup by rule ID (UUID)
                rule_id = get_rule_id(src)
                if rule_id:
                    if rule_id in seen_ids:
                        dedup_skipped += 1
                        continue
                    seen_ids.add(rule_id)

                if should_keep_rule(src, platforms, args.min_status):
                    # Preserve subdirectory structure, prefixed by source
                    rel = os.path.relpath(src, input_dir)
                    dst = os.path.join(output_dir, source_name, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
                    kept += 1
                    source_kept += 1

        print(f"  {source_name}: {source_kept} rules kept")

    print(
        f"Sigma filter: {kept}/{total} rules kept "
        f"(platforms={platforms}, min_status={args.min_status}, "
        f"{dedup_skipped} dedup skipped)"
    )


if __name__ == "__main__":
    main()
