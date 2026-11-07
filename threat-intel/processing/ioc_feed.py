#!/usr/bin/env python3
"""Retain observation dates and avoid URL-to-shared-host assertions."""
import argparse
import csv
import json
from pathlib import Path

from ioc_safety import domain_from_url


def threatfox_entries(text: str) -> dict[str, list[dict]]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('# "first_seen_utc"'):
            lines.append(line[2:])
        elif line and not line.startswith("#"):
            lines.append(line)
    result = {"hashes": [], "domains": [], "ips": []}
    for row in csv.DictReader(lines):
        kind, value = row.get("ioc_type", ""), row.get("ioc_value", "").strip()
        if kind == "domain":
            target = "domains"
        elif kind == "ip:port":
            target, value = "ips", value.rsplit(":", 1)[0].strip("[]")
        elif kind in {"sha256_hash", "sha256"}:
            target = "hashes"
        else:
            continue
        if value:
            result[target].append({"value": value, "source": "threatfox",
                "first_seen": row.get("first_seen_utc", ""),
                "last_seen": row.get("last_seen_utc") or row.get("first_seen_utc", "")})
    return result


def urlhaus_entries(text: str) -> list[dict]:
    hosts = {domain_from_url(line) for line in text.splitlines() if line.strip() and not line.startswith("#")}
    return [{"value": host, "source": "urlhaus"} for host in sorted(hosts - {None})]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["urlhaus", "threatfox"])
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    text = args.input.read_text(encoding="utf-8")
    if args.kind == "urlhaus":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rows = urlhaus_entries(text)
        args.output.write_text("".join(json.dumps(row) + "\n" for row in rows))
        print(f"URLhaus dedicated hosts: {len(rows)}")
    else:
        for kind, rows in threatfox_entries(text).items():
            path = args.output / kind / "threatfox.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            print(f"ThreatFox {kind}: {len(rows)}")


if __name__ == "__main__":
    main()
