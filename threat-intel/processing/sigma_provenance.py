#!/usr/bin/env python3
"""Verify each compiled rule's upstream id/path/pin against collector provenance."""
import json
import sys
from pathlib import Path

import yaml


def verify(root: Path, pin: str) -> int:
    doc = json.loads((root / "sigma-provenance.json").read_text())
    if doc.get("commit") != pin:
        raise ValueError("SigmaHQ provenance pin mismatch")
    count = 0
    for path in sorted(root.rglob("*")):
        if path.suffix not in {".yml", ".yaml"}:
            continue
        relative = path.relative_to(root).as_posix()
        rule = yaml.safe_load(path.read_text())
        expected = {"source_path": relative, "id": rule["id"], "commit": pin}
        if doc.get("rules", {}).get(relative) != expected:
            raise ValueError(f"SigmaHQ rule provenance mismatch: {relative}")
        if not relative.startswith(("rules/", "rules-emerging-threats/")):
            raise ValueError(f"not an alerting SigmaHQ source: {relative}")
        count += 1
    if not count:
        raise ValueError("no qualified SigmaHQ rules")
    return count


if __name__ == "__main__":
    print(f"Provenance verified: {verify(Path(sys.argv[1]), sys.argv[2])} rules")
