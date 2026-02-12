#!/usr/bin/env python3
"""Deduplicate and corroborate IOCs across multiple sources for eGuard threat intel."""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Source tier classification
SOURCE_TIERS = {
    # Tier 1: curated commercial / government
    "cisa": 1,
    # Tier 2: community-vetted
    "malwarebazaar": 2,
    "threatfox": 2,
    "feodo": 2,
    "urlhaus": 2,
    "abusech": 2,
    # Tier 3: aggregators
    "otx": 3,
    "alienvault": 3,
    # Tier 4: unvetted
    "other": 4,
}

# Staleness thresholds (days)
STALENESS = {
    "hashes": 90,
    "domains": 60,
    "ips": 30,
}

# Confidence levels
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


def parse_ioc_file(path: str) -> list[dict]:
    """Parse an IOC file (one IOC per line, optional JSON metadata)."""
    entries = []
    source_name = infer_source(path)

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Try JSON-lines format first
            try:
                entry = json.loads(line)
                entry.setdefault("source", source_name)
                entries.append(entry)
                continue
            except (json.JSONDecodeError, ValueError):
                pass
            # Plain text: one IOC value per line
            entries.append({
                "value": line.split(",")[0].strip(),
                "source": source_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    return entries


def infer_source(path: str) -> str:
    """Infer source name from file path."""
    basename = os.path.basename(path).lower()
    for source in SOURCE_TIERS:
        if source in basename:
            return source
    return "other"


def get_tier(source: str) -> int:
    return SOURCE_TIERS.get(source.lower(), 4)


def determine_confidence(sources: set[str]) -> str:
    """Determine confidence based on source tiers and corroboration."""
    tiers = [get_tier(s) for s in sources]
    min_tier = min(tiers)

    # Multiple sources with at least one Tier 1-2 → high
    if len(sources) >= 2 and min_tier <= 2:
        return CONFIDENCE_HIGH

    # Single Tier 1-2 source → medium
    if min_tier <= 2:
        return CONFIDENCE_MEDIUM

    # Multiple Tier 3 sources → medium
    if len(sources) >= 2 and min_tier <= 3:
        return CONFIDENCE_MEDIUM

    # Single Tier 4 or single Tier 3 → low
    return CONFIDENCE_LOW


def is_stale(timestamp_str: str, ioc_type: str) -> bool:
    """Check if an IOC entry is older than staleness threshold."""
    max_age_days = STALENESS.get(ioc_type, 90)
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False  # Can't parse → keep it
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    return ts < cutoff


def deduplicate(entries: list[dict], ioc_type: str) -> list[dict]:
    """Deduplicate IOCs, apply corroboration and staleness rules."""
    # Group by IOC value
    by_value: dict[str, dict] = {}
    for entry in entries:
        val = entry.get("value", "").strip().lower()
        if not val:
            continue
        if val not in by_value:
            by_value[val] = {
                "value": val,
                "sources": set(),
                "first_seen": entry.get("timestamp", ""),
                "last_seen": entry.get("timestamp", ""),
            }
        by_value[val]["sources"].add(entry.get("source", "other"))
        ts = entry.get("timestamp", "")
        if ts:
            if not by_value[val]["first_seen"] or ts < by_value[val]["first_seen"]:
                by_value[val]["first_seen"] = ts
            if not by_value[val]["last_seen"] or ts > by_value[val]["last_seen"]:
                by_value[val]["last_seen"] = ts

    # Apply staleness and confidence
    results = []
    stale_count = 0
    for ioc in by_value.values():
        last_seen = ioc.get("last_seen", "")
        if last_seen and is_stale(last_seen, ioc_type):
            stale_count += 1
            continue
        confidence = determine_confidence(ioc["sources"])
        results.append({
            "value": ioc["value"],
            "confidence": confidence,
            "sources": sorted(ioc["sources"]),
            "first_seen": ioc["first_seen"],
            "last_seen": ioc["last_seen"],
        })

    print(f"  {ioc_type}: {len(results)} unique IOCs ({stale_count} stale removed)")
    return results


def write_output(entries: list[dict], output_path: str):
    """Write deduplicated IOCs as JSON-lines."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Deduplicate and corroborate IOCs")
    parser.add_argument("--input", required=True, help="Input directory with IOC source files")
    parser.add_argument("--output", required=True, help="Output directory for deduplicated IOCs")
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)

    for ioc_type in ("hashes", "domains", "ips"):
        type_dir = os.path.join(input_dir, ioc_type)
        if not os.path.isdir(type_dir):
            print(f"  {ioc_type}: no source directory, skipping")
            continue

        all_entries = []
        for fname in os.listdir(type_dir):
            fpath = os.path.join(type_dir, fname)
            if os.path.isfile(fpath):
                all_entries.extend(parse_ioc_file(fpath))

        deduped = deduplicate(all_entries, ioc_type)
        write_output(deduped, os.path.join(output_dir, ioc_type, "consolidated.jsonl"))

    print("IOC deduplication complete.")


if __name__ == "__main__":
    main()
