#!/usr/bin/env python3
"""Merge plain IOC feeds into JSONL IOC files without losing provenance."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_entry(entry: dict, fallback_source: str = "other") -> dict | None:
    value = str(entry.get("value", "")).strip()
    if not value:
        return None
    confidence = str(entry.get("confidence", "low")).strip().lower()
    if confidence not in CONFIDENCE_RANK:
        confidence = "low"
    sources = entry.get("sources")
    if not isinstance(sources, list):
        source = str(entry.get("source", fallback_source)).strip() or fallback_source
        sources = [source]
    sources = sorted({str(s).strip() for s in sources if str(s).strip()}) or [fallback_source]
    now = utc_now()
    return {
        "value": value,
        "confidence": confidence,
        "sources": sources,
        "first_seen": str(entry.get("first_seen") or now),
        "last_seen": str(entry.get("last_seen") or now),
    }


def merge_entry(existing: dict | None, new: dict) -> dict:
    if existing is None:
        return new
    sources = sorted(set(existing.get("sources", [])) | set(new.get("sources", [])))
    confidence = max(
        [existing.get("confidence", "low"), new.get("confidence", "low")],
        key=lambda c: CONFIDENCE_RANK.get(c, 0),
    )
    return {
        "value": existing["value"],
        "confidence": confidence,
        "sources": sources,
        "first_seen": min(existing.get("first_seen", ""), new.get("first_seen", "")),
        "last_seen": max(existing.get("last_seen", ""), new.get("last_seen", "")),
    }


def load_target(path: Path) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    if not path.exists():
        return entries
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    entry = normalize_entry(item)
                else:
                    # Bare value that happens to parse as a JSON scalar
                    # (e.g. purely numeric) — treat it as a plain line.
                    entry = normalize_entry({"value": line, "confidence": "low", "sources": ["other"]})
            except json.JSONDecodeError:
                entry = normalize_entry({"value": line, "confidence": "low", "sources": ["other"]})
            if entry is None:
                continue
            entries[entry["value"]] = merge_entry(entries.get(entry["value"]), entry)
    return entries


def parse_merge_spec(spec: str) -> tuple[Path, str, str]:
    parts = spec.rsplit(":", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("merge spec must be <plain_path>:<source_name>:<confidence>")
    path, source, confidence = parts
    source = source.strip()
    confidence = confidence.strip().lower()
    if not source:
        raise argparse.ArgumentTypeError("source_name must not be empty")
    if confidence not in CONFIDENCE_RANK:
        raise argparse.ArgumentTypeError("confidence must be low, medium, or high")
    return Path(path), source, confidence


def merge_plain_file(entries: dict[str, dict], path: Path, source: str, confidence: str, now: str) -> tuple[int, int]:
    if not path.exists():
        print(f"merge_plain_iocs: missing {path}, skipping", file=sys.stderr)
        return 0, 0
    merged = 0
    added = 0
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            entry = {
                "value": value,
                "confidence": confidence,
                "sources": [source],
                "first_seen": now,
                "last_seen": now,
            }
            if value not in entries:
                added += 1
            entries[value] = merge_entry(entries.get(value), entry)
            merged += 1
    return merged, added


def write_target(path: Path, entries: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for value in sorted(entries):
            f.write(json.dumps(entries[value], sort_keys=True, separators=(",", ":")) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge plain IOC feeds into a JSONL IOC file")
    parser.add_argument("--target", required=True, help="Target JSONL IOC path")
    parser.add_argument(
        "--merge",
        action="append",
        default=[],
        type=parse_merge_spec,
        help="Plain feed merge spec: <plain_path>:<source_name>:<confidence>",
    )
    args = parser.parse_args(argv)

    target = Path(args.target)
    entries = load_target(target)
    before = len(entries)
    total_merged = 0
    total_added = 0
    now = utc_now()
    for path, source, confidence in args.merge:
        merged, added = merge_plain_file(entries, path, source, confidence, now)
        total_merged += merged
        total_added += added
    write_target(target, entries)
    print(
        f"merge_plain_iocs: target={target} existing={before} merged={total_merged} added={total_added} final={len(entries)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
