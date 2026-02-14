#!/usr/bin/env python3
"""Validate, deduplicate, and quality-check YARA rules from multiple sources."""

import argparse
import os
import re
import shutil
import sys

try:
    import yara
except ImportError:
    print("ERROR: yara-python not installed. Install with: pip install yara-python", file=sys.stderr)
    sys.exit(1)

# Regex to extract rule names from YARA files
RULE_NAME_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)", re.MULTILINE)


def extract_rule_names(path: str) -> list[str]:
    """Extract all rule names declared in a YARA file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return RULE_NAME_RE.findall(content)
    except Exception:
        return []


def compile_rule(path: str) -> "yara.Rules | None":
    """Attempt to compile a single YARA rule file."""
    try:
        return yara.compile(filepath=path)
    except yara.SyntaxError as exc:
        print(f"  INVALID (syntax): {path}: {exc}", file=sys.stderr)
        return None
    except yara.Error as exc:
        print(f"  INVALID (error): {path}: {exc}", file=sys.stderr)
        return None


def scan_clean_files(rules: "yara.Rules", test_dir: str) -> tuple[list[str], list[str]]:
    """Scan clean files; return (false-positive matches, scan errors)."""
    matches = []
    errors = []
    if not os.path.isdir(test_dir):
        return matches, errors
    for fname in os.listdir(test_dir):
        fpath = os.path.join(test_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            result = rules.match(fpath)
            if result:
                matches.append(fpath)
        except yara.Error as exc:
            errors.append(f"{fpath}: {exc}")
    return matches, errors


def discover_sources(input_dir: str) -> list[str]:
    """Find source subdirectories (e.g. yara-forge/, elastic/, gcti/)."""
    sources = []
    for entry in sorted(os.listdir(input_dir)):
        full = os.path.join(input_dir, entry)
        if os.path.isdir(full):
            sources.append(entry)
    # If no subdirectories, the input_dir itself is a flat collection
    if not sources:
        sources.append(".")
    return sources


def collect_rule_files(base_dir: str) -> list[str]:
    """Recursively find all .yar/.yara files under a directory."""
    files = []
    for root, _dirs, filenames in os.walk(base_dir):
        for fname in filenames:
            if fname.endswith((".yar", ".yara")):
                files.append(os.path.join(root, fname))
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description="Validate YARA rules for eGuard")
    parser.add_argument("--input", required=True, help="Input directory of YARA rules")
    parser.add_argument("--output", required=True, help="Output directory for validated rules")
    parser.add_argument("--test-files", default="", help="Directory of clean files for FP testing")
    parser.add_argument(
        "--deduplicate", action="store_true",
        help="Deduplicate rules across sources by rule name",
    )
    parser.add_argument(
        "--source-priority", default="",
        help="Comma-separated source priority (highest first), e.g. 'yara-forge,elastic,gcti'",
    )
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)
    test_dir = os.path.abspath(args.test_files) if args.test_files else ""

    os.makedirs(output_dir, exist_ok=True)

    # Determine source processing order
    sources = discover_sources(input_dir)
    if args.source_priority:
        priority = [s.strip() for s in args.source_priority.split(",")]
        # Process in priority order, then remaining sources
        ordered = [s for s in priority if s in sources]
        ordered += [s for s in sources if s not in ordered]
        sources = ordered

    print(f"YARA sources (priority order): {sources}")

    # Global dedup tracking
    seen_rule_names: set[str] = set()

    total = 0
    valid = 0
    dedup_skipped = 0
    compile_fail = 0
    fp_removed = 0
    scan_fail = 0
    source_counts: dict[str, int] = {}

    for source in sources:
        if source == ".":
            source_dir = input_dir
        else:
            source_dir = os.path.join(input_dir, source)

        if not os.path.isdir(source_dir):
            continue

        rule_files = collect_rule_files(source_dir)
        source_valid = 0

        for src in rule_files:
            total += 1

            # ── Dedup check ──────────────────────────────────────────
            if args.deduplicate:
                rule_names = extract_rule_names(src)
                if rule_names and all(n in seen_rule_names for n in rule_names):
                    dedup_skipped += 1
                    continue

            # ── Compile check ────────────────────────────────────────
            compiled = compile_rule(src)
            if compiled is None:
                compile_fail += 1
                continue

            # ── False-positive scan ──────────────────────────────────
            if test_dir:
                fp_files, scan_errors = scan_clean_files(compiled, test_dir)
                if scan_errors:
                    for scan_error in scan_errors[:5]:
                        print(f"  INVALID (scan error): {src}: {scan_error}", file=sys.stderr)
                    if len(scan_errors) > 5:
                        print(
                            f"  INVALID (scan error): {src}: {len(scan_errors) - 5} additional scan errors",
                            file=sys.stderr,
                        )
                    scan_fail += 1
                    continue
                if fp_files:
                    print(f"  FP REMOVED: {src} matched {len(fp_files)} clean file(s)", file=sys.stderr)
                    fp_removed += 1
                    continue

            # ── Register rule names for dedup ────────────────────────
            if args.deduplicate:
                rule_names = extract_rule_names(src)
                seen_rule_names.update(rule_names)

            # ── Copy validated rule to output ────────────────────────
            rel = os.path.relpath(src, input_dir)
            dst = os.path.join(output_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            valid += 1
            source_valid += 1

        source_counts[source] = source_valid
        print(f"  {source}: {source_valid}/{len(rule_files)} rules kept")

    print(
        f"\nYARA validate: {valid}/{total} rules valid "
        f"({compile_fail} compile errors, {scan_fail} scan errors, {fp_removed} false-positive removals, "
        f"{dedup_skipped} dedup skipped)"
    )
    print("Per-source breakdown:")
    for source, count in source_counts.items():
        print(f"  {source}: {count}")


if __name__ == "__main__":
    main()
