#!/usr/bin/env python3
"""Print and enforce the minimum toolchain for real-YARA release artifacts."""
import re
import subprocess

version = subprocess.check_output(["rustc", "--version"], text=True).strip()
print(version, flush=True)
match = re.match(r"rustc (\d+)\.(\d+)", version)
if not match or tuple(map(int, match.groups())) < (1, 95):
    raise SystemExit("real YARA requires Rust >=1.95; select a local/CI toolchain explicitly")
