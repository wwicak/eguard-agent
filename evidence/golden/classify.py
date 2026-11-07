#!/usr/bin/env python3
"""Classify synthetic RAFIX golden changes against the immutable shipped base."""
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidence/golden"
NAMES = ["f4a-legacy.json", "f4c-platforms.json"]
MISSING = "__MISSING__"


def differences(old, new, path=""):
    if old == new:
        return []
    if isinstance(old, dict) and isinstance(new, dict):
        rows = []
        for key in sorted(old.keys() | new.keys()):
            rows += differences(old.get(key, MISSING), new.get(key, MISSING), f"{path}/{key}")
        return rows
    if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        return [row for i, (a, b) in enumerate(zip(old, new)) for row in differences(a, b, f"{path}/{i}")]
    if path.endswith("/payload_json"):
        return differences(json.loads(old), json.loads(new), path)
    return [{"path": path, "old": old, "new": new}]


sources = {}
for line in (OUT / "sources.log").read_text().splitlines():
    if "RAFIX_SOURCE " in line:
        value = json.loads(line.split("RAFIX_SOURCE ", 1)[1])
        sources[(value["file"], value["row"])] = value["input"]

patterns = {
    "additive-image-unlink": r"/\d+/(?:detection|envelope/payload_json/event)/(?:process_exe|file_unlink)",
    "write-intent": r"/\d+/(?:detection|envelope/payload_json/event)/file_write",
    "rename-destination": r"/\d+/(?:(?:detection|envelope/payload_json/event)/file_path|envelope/payload_json/event_txn/(?:key|subject))",
    "invocation-label": r"/\d+/(?:detection|envelope/payload_json/event)/process",
}
all_diff = {}
hashes = {}
for index, name in enumerate(NAMES):
    path = f"crates/agent-core/tests/fixtures/{name}"
    old_bytes = subprocess.check_output(["git", "show", f"fe43f8a:{path}"], cwd=ROOT)
    new_bytes = (ROOT / path).read_bytes()
    hashes[name] = {"before": hashlib.sha256(old_bytes).hexdigest(), "after": hashlib.sha256(new_bytes).hexdigest()}
    all_diff[name] = differences(json.loads(old_bytes), json.loads(new_bytes))
(OUT / "golden-diff.json").write_text(json.dumps(all_diff, indent=2, ensure_ascii=False) + "\n")

# Walk the durable diff artifact, not a visual judgement or a broad golden reset.
all_diff = json.loads((OUT / "golden-diff.json").read_text())
counts = {}
spots = {"write-intent": [], "rename-destination": []}
for index, name in enumerate(NAMES):
    counter = collections.Counter()
    for row in all_diff[name]:
        path = row["path"]
        categories = [category for category, pattern in patterns.items() if re.fullmatch(pattern, path)]
        assert len(categories) == 1, f"STOP unclassified/ambiguous: {name}:{path}"
        assert not any(key in path.split("/") for key in ["severity", "confidence", "rule_name", "temporal_hits", "kill_chain_hits", "yara_hits", "signals", "response", "alert"]), f"STOP verdict change: {path}"
        category = categories[0]
        counter[category] += 1
        row_index = int(path.split("/")[1])
        source = sources[(index, row_index)]
        if category == "rename-destination":
            assert source.get("type", source.get("event_type")) in ("FileRename", "file_rename"), f"STOP non-rename destination: {name}:{path}"
        if category in spots and path.endswith("/detection/" + ("file_write" if category == "write-intent" else "file_path")) and len(spots[category]) < 5:
            spots[category].append({"file": name, "row": row_index, "path": path, "old": row["old"], "new": row["new"], "source_input": source})
    counts[name] = dict(counter)
assert all(len(rows) == 5 for rows in spots.values())
result = {"base": "fe43f8a", "unclassified": 0, "verdict_changes": 0, "category_counts": counts, "sha256": hashes}
(OUT / "classification.json").write_text(json.dumps(result, indent=2) + "\n")
(OUT / "spot-proofs.json").write_text(json.dumps(spots, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(result, indent=2))
