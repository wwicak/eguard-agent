#!/usr/bin/env python3
"""Extract Linux-relevant Elastic detection rules and convert to JSON.

Elastic detection-rules uses TOML format with KQL/EQL queries. We extract
the rule metadata, MITRE ATT&CK mapping, and query logic into a simplified
JSON format that eGuard's detection engine can consume.
"""

import argparse
import json
import os
import sys

try:
    import tomli
except ImportError:
    # Python 3.11+ has tomllib in stdlib
    try:
        import tomllib as tomli
    except ImportError:
        print("ERROR: tomli not installed. Install with: pip install tomli", file=sys.stderr)
        sys.exit(1)

TARGET_PLATFORMS = {"linux", "cross-platform", "macos"}  # macos shares many linux detections


def load_toml_rule(path: str) -> dict | None:
    """Load a TOML rule file and return parsed dict."""
    try:
        with open(path, "rb") as f:
            return tomli.load(f)
    except Exception as exc:
        print(f"  SKIP (parse error): {path}: {exc}", file=sys.stderr)
        return None


def extract_rule(data: dict, source_path: str) -> dict | None:
    """Extract relevant fields from an Elastic detection rule."""
    rule = data.get("rule", data)

    name = rule.get("name", "")
    if not name:
        return None

    # Extract platform from tags or directory path
    tags = [t.lower() for t in rule.get("tags", [])]

    # Determine query type and content
    query = rule.get("query", "")
    rule_type = rule.get("type", "query")
    language = rule.get("language", "kuery")

    # Extract MITRE ATT&CK
    threat = rule.get("threat", [])
    mitre_tactics = []
    mitre_techniques = []
    for t in threat:
        framework = t.get("framework", "")
        if "ATT&CK" in framework:
            tactic = t.get("tactic", {})
            if tactic.get("id"):
                mitre_tactics.append({
                    "id": tactic["id"],
                    "name": tactic.get("name", ""),
                })
            for tech in t.get("technique", []):
                if tech.get("id"):
                    entry = {"id": tech["id"], "name": tech.get("name", "")}
                    subtechs = tech.get("subtechnique", [])
                    if subtechs:
                        entry["subtechniques"] = [
                            {"id": s["id"], "name": s.get("name", "")}
                            for s in subtechs if s.get("id")
                        ]
                    mitre_techniques.append(entry)

    severity = rule.get("severity", "medium")
    risk_score = rule.get("risk_score", 50)
    description = rule.get("description", "")

    return {
        "name": name,
        "type": rule_type,
        "language": language,
        "query": query,
        "severity": severity,
        "risk_score": risk_score,
        "description": description[:500],
        "tags": rule.get("tags", []),
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "source": "elastic",
        "source_path": os.path.basename(source_path),
    }


def main():
    parser = argparse.ArgumentParser(description="Extract Elastic detection rules for eGuard")
    parser.add_argument("--input", required=True, help="Input rules/ directory")
    parser.add_argument("--building-blocks", default="", help="Building block rules directory")
    parser.add_argument("--output", required=True, help="Output directory for JSON rules")
    parser.add_argument(
        "--platforms", nargs="+", default=["linux", "cross-platform"],
        help="Target platforms to extract",
    )
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    platforms = {p.lower().replace("-", "_") for p in args.platforms}
    # Also accept hyphenated forms
    platforms.update({p.replace("_", "-") for p in platforms})

    total = 0
    kept = 0
    rules = []

    # Process main rules and building blocks
    dirs_to_scan = [input_dir]
    if args.building_blocks and os.path.isdir(args.building_blocks):
        dirs_to_scan.append(os.path.abspath(args.building_blocks))

    for scan_dir in dirs_to_scan:
        for root, _dirs, files in os.walk(scan_dir):
            for fname in files:
                if not fname.endswith(".toml"):
                    continue
                total += 1
                fpath = os.path.join(root, fname)

                # Check if this rule is for our target platform
                # Elastic organizes rules in platform subdirectories
                rel = os.path.relpath(fpath, scan_dir)
                parts = rel.replace("\\", "/").split("/")

                # First directory component is often the platform
                file_platform = parts[0].lower() if parts else ""
                if file_platform not in platforms and "cross" not in file_platform:
                    continue

                data = load_toml_rule(fpath)
                if data is None:
                    continue

                extracted = extract_rule(data, fpath)
                if extracted:
                    rules.append(extracted)
                    kept += 1

    # Write as JSONL
    output_path = os.path.join(output_dir, "elastic-rules.jsonl")
    with open(output_path, "w", encoding="utf-8") as f:
        for rule in rules:
            f.write(json.dumps(rule, separators=(",", ":")) + "\n")

    # Also write a summary index
    index = {
        "total_rules": kept,
        "platforms": sorted(platforms),
        "severity_breakdown": {},
        "mitre_tactics": {},
    }
    for rule in rules:
        sev = rule.get("severity", "unknown")
        index["severity_breakdown"][sev] = index["severity_breakdown"].get(sev, 0) + 1
        for tactic in rule.get("mitre_tactics", []):
            tid = tactic["id"]
            index["mitre_tactics"][tid] = index["mitre_tactics"].get(tid, 0) + 1

    with open(os.path.join(output_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)

    print(f"Elastic extract: {kept}/{total} rules extracted for platforms {sorted(platforms)}")
    for sev, count in sorted(index["severity_breakdown"].items()):
        print(f"  {sev}: {count}")


if __name__ == "__main__":
    main()
