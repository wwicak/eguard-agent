#!/usr/bin/env python3
"""Subtract known-good hashes and domains from IOC consolidated lists."""

import argparse
import json
import os
import sys


def load_allowlist(path: str) -> set[str]:
    """Load an allowlist file (one entry per line, # comments)."""
    entries = set()
    if not os.path.isfile(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line.lower())
    return entries


def filter_iocs(input_path: str, output_path: str, allowlist: set[str]) -> tuple[int, int]:
    """Filter IOCs from a JSONL file, removing allowlisted values."""
    if not os.path.isfile(input_path):
        return 0, 0

    kept = 0
    removed = 0
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(input_path, "r", encoding="utf-8") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            value = entry.get("value", "").lower()
            if value in allowlist:
                removed += 1
                continue
            fout.write(json.dumps(entry, separators=(",", ":")) + "\n")
            kept += 1

    return kept, removed


def main():
    parser = argparse.ArgumentParser(description="Apply allowlist to IOC data")
    parser.add_argument("--input", required=True, help="Input directory with consolidated IOCs")
    parser.add_argument("--output", required=True, help="Output directory for filtered IOCs")
    parser.add_argument(
        "--hash-allowlist", default="",
        help="Path to known-good hashes file",
    )
    parser.add_argument(
        "--domain-allowlist", default="",
        help="Path to known-good domains file",
    )
    args = parser.parse_args()

    hash_allowlist = load_allowlist(args.hash_allowlist) if args.hash_allowlist else set()
    domain_allowlist = load_allowlist(args.domain_allowlist) if args.domain_allowlist else set()

    input_dir = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)

    # Filter hashes
    kept, removed = filter_iocs(
        os.path.join(input_dir, "hashes", "consolidated.jsonl"),
        os.path.join(output_dir, "hashes.txt"),
        hash_allowlist,
    )
    print(f"Hashes: {kept} kept, {removed} allowlisted")

    # Filter domains
    kept, removed = filter_iocs(
        os.path.join(input_dir, "domains", "consolidated.jsonl"),
        os.path.join(output_dir, "domains.txt"),
        domain_allowlist,
    )
    print(f"Domains: {kept} kept, {removed} allowlisted")

    # IPs: no allowlist, just copy through
    kept, removed = filter_iocs(
        os.path.join(input_dir, "ips", "consolidated.jsonl"),
        os.path.join(output_dir, "ips.txt"),
        set(),
    )
    print(f"IPs: {kept} kept")


if __name__ == "__main__":
    main()
