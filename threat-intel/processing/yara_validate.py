#!/usr/bin/env python3
"""Validate YARA rules: compile check + false-positive scan against clean files."""

import argparse
import os
import shutil
import sys

try:
    import yara
except ImportError:
    print("ERROR: yara-python not installed. Install with: pip install yara-python", file=sys.stderr)
    sys.exit(1)


def compile_rule(path: str) -> yara.Rules | None:
    """Attempt to compile a single YARA rule file."""
    try:
        return yara.compile(filepath=path)
    except yara.SyntaxError as exc:
        print(f"  INVALID (syntax): {path}: {exc}", file=sys.stderr)
        return None
    except yara.Error as exc:
        print(f"  INVALID (error): {path}: {exc}", file=sys.stderr)
        return None


def scan_clean_files(rules: yara.Rules, test_dir: str) -> list[str]:
    """Scan clean test files; return list of matched file paths (false positives)."""
    matches = []
    if not os.path.isdir(test_dir):
        return matches
    for fname in os.listdir(test_dir):
        fpath = os.path.join(test_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            result = rules.match(fpath)
            if result:
                matches.append(fpath)
        except yara.Error:
            pass
    return matches


def main():
    parser = argparse.ArgumentParser(description="Validate YARA rules for eGuard")
    parser.add_argument("--input", required=True, help="Input directory of YARA rules")
    parser.add_argument("--output", required=True, help="Output directory for validated rules")
    parser.add_argument("--test-files", default="", help="Directory of clean files for FP testing")
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)
    test_dir = os.path.abspath(args.test_files) if args.test_files else ""

    os.makedirs(output_dir, exist_ok=True)

    total = 0
    valid = 0
    fp_removed = 0

    for root, _dirs, files in os.walk(input_dir):
        for fname in files:
            if not fname.endswith((".yar", ".yara")):
                continue
            total += 1
            src = os.path.join(root, fname)

            # Step 1: compile check
            compiled = compile_rule(src)
            if compiled is None:
                continue

            # Step 2: false-positive scan
            if test_dir:
                fp_files = scan_clean_files(compiled, test_dir)
                if fp_files:
                    print(f"  FP REMOVED: {src} matched {len(fp_files)} clean file(s)", file=sys.stderr)
                    fp_removed += 1
                    continue

            # Copy valid rule to output
            rel = os.path.relpath(src, input_dir)
            dst = os.path.join(output_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            valid += 1

    compile_fail = total - valid - fp_removed
    print(
        f"YARA validate: {valid}/{total} rules valid "
        f"({compile_fail} compile errors, {fp_removed} false-positive removals)"
    )


if __name__ == "__main__":
    main()
