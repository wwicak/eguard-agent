#!/usr/bin/env python3
"""Deduplicate and corroborate IOCs across multiple sources for eGuard threat intel.

Tier system:
  0 — Government / zero-FP (CISA, Spamhaus DROP)
  1 — Premium aggregated (FireHOL level 1)
  2 — Community-vetted (abuse.ch, SANS DShield, DigitalSide)
  3 — Community / aggregators (Botvrij, CINS, Blocklist.de)
  4 — Low-confidence aggregators and unvetted sources (OTX/alienvault, unknown)

Confidence scoring:
  high   — 2+ sources with at least one Tier 0-2, or any Tier 0 source
  medium — single Tier 2 source, or corroborated Tier 3/4 sources
  low    — single Tier 3-4 source
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Source tier classification
SOURCE_TIERS: dict[str, int] = {
    # Tier 0: government / zero false-positive
    "cisa": 0,
    "spamhaus": 0,
    # Tier 1: premium aggregated blocklists
    "firehol_l1": 1,
    # Tier 2: community-vetted, researcher-curated
    "malwarebazaar": 2,
    "threatfox": 2,
    "feodo": 2,
    "urlhaus": 2,
    "abusech": 2,
    "sslbl": 2,
    "sslbl_sha1": 2,
    "dshield": 2,
    "digitalside": 2,
    "phishtank": 2,
    # Tier 3: aggregators / community blocklists
    "botvrij": 3,
    "cins": 3,
    "blocklist_de": 3,
    # Tier 4: low-confidence aggregators / unvetted
    "otx": 4,
    "alienvault": 4,
    "other": 4,
    "c2_tracker": 2,
    "phishing_database": 3,
    "tor_exit_list": 3,
}

# Staleness thresholds (days)
STALENESS = {
    "hashes": 90,
    "domains": 60,
    "ips": 30,
}

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


def parse_ioc_file(path: str, *, preserve_provenance: bool = False) -> list[dict]:
    """Parse raw feeds; only trusted re-curation may retain merged provenance."""
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
                if isinstance(entry, dict):
                    if not preserve_provenance:
                        # Raw feed identity comes from the collector, not its content.
                        entry["source"] = source_name
                        entry.pop("sources", None)
                    elif not entry.get("sources"):
                        entry.setdefault("source", source_name)
                    entries.append(entry)
                    continue
            except (json.JSONDecodeError, ValueError):
                pass
            # Plain text: one IOC value per line
            entries.append({
                "value": line.split(",")[0].strip(),
                "source": source_name,
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
    if not sources:
        return CONFIDENCE_LOW

    tiers = [get_tier(s) for s in sources]
    min_tier = min(tiers)

    # Any Tier 0 source → high confidence
    if min_tier == 0:
        return CONFIDENCE_HIGH

    # Single Tier 1 source → high confidence
    if len(sources) == 1 and min_tier == 1:
        return CONFIDENCE_HIGH

    # Multiple sources with at least one Tier 1-2 → high
    if len(sources) >= 2 and min_tier <= 2:
        return CONFIDENCE_HIGH

    # Single Tier 2 source → medium
    if len(sources) == 1 and min_tier == 2:
        return CONFIDENCE_MEDIUM

    # Corroborated Tier 3/4 sources → medium
    if len(sources) >= 2:
        return CONFIDENCE_MEDIUM

    # Single Tier 4 or single Tier 3 → low
    return CONFIDENCE_LOW


def parse_date(value: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    except ValueError:
        return None


def is_stale(timestamp_str: str, ioc_type: str) -> bool:
    """Explicit invalid/future dates fail closed; undated feeds stay undated."""
    if not timestamp_str:
        return False
    ts = parse_date(timestamp_str)
    now = datetime.now(timezone.utc)
    return ts is None or ts > now + timedelta(days=1) or ts < now - timedelta(days=STALENESS.get(ioc_type, 90))


def deduplicate(entries: list[dict], ioc_type: str) -> list[dict]:
    """Expire each observation BEFORE it can corroborate a fresh source."""
    by_value: dict[str, dict] = {}
    stale_count = 0
    for entry in entries:
        val = str(entry.get("value", "")).strip().lower()
        if ioc_type == "domains":
            val = val.rstrip(".")
        elif ioc_type == "ips":
            try:
                val = str(ipaddress.ip_network(val, strict=False) if "/" in val else ipaddress.ip_address(val))
            except ValueError:
                continue
        if not val:
            continue
        last = entry.get("last_seen") or entry.get("last_online") or entry.get("timestamp") or entry.get("first_seen") or ""
        if is_stale(last, ioc_type):
            stale_count += 1
            continue
        first = entry.get("first_seen") or last
        first_date, last_date = parse_date(first), parse_date(last)
        first = first_date.isoformat() if first_date else ""
        last = last_date.isoformat() if last_date else ""
        item = by_value.setdefault(val, {"value": val, "sources": set(), "first_seen": "", "last_seen": ""})
        sources = entry.get("sources")
        if not isinstance(sources, list) or not sources:
            sources = [entry.get("source") or "other"]
        item["sources"].update(s for s in sources if isinstance(s, str) and s)
        if first and (not item["first_seen"] or first < item["first_seen"]):
            item["first_seen"] = first
        if last and (not item["last_seen"] or last > item["last_seen"]):
            item["last_seen"] = last

    results = []
    for item in by_value.values():
        item["confidence"] = determine_confidence(item["sources"])
        item["sources"] = sorted(item["sources"])
        results.append(item)
    priority = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_LOW: 2}
    results.sort(key=lambda x: (priority.get(x["confidence"], 3), x["value"]))
    print(f"  {ioc_type}: {len(results)} unique IOCs ({stale_count} stale observations removed)")
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
