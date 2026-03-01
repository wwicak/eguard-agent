#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="artifacts/baseline-aggregation"
mkdir -p "${OUT_DIR}"

INPUT_FILE="${BASELINE_INPUT_FILE:-scripts/fixtures/baseline-ci-input.json}"
MIN_AGENTS="${BASELINE_MIN_AGENTS:-3}"
BUNDLE_VERSION="${BASELINE_BUNDLE_VERSION:-$(date -u +%Y.%m.%d.%H%M)}"

python3 - "${INPUT_FILE}" "${OUT_DIR}" "${MIN_AGENTS}" "${BUNDLE_VERSION}" <<'PY'
import json
import math
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

input_path = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
min_agents = max(1, int(sys.argv[3]))
bundle_version = sys.argv[4]
out_dir.mkdir(parents=True, exist_ok=True)

if not input_path.exists():
    raise SystemExit(f"missing baseline input: {input_path}")

payload = json.loads(input_path.read_text(encoding="utf-8"))
if isinstance(payload, dict):
    records = payload.get("baselines") or payload.get("endpoint_baselines") or []
elif isinstance(payload, list):
    records = payload
else:
    raise SystemExit("baseline input must be array/object")

grouped = defaultdict(list)
for rec in records:
    agent_id = str(rec.get("agent_id", "")).strip()
    process_key = str(rec.get("process_key", "")).strip()
    distribution = rec.get("event_distribution") or {}
    if not agent_id or not process_key or not isinstance(distribution, dict):
        continue

    cleaned = {}
    total = 0.0
    for key, value in distribution.items():
        key = str(key).strip()
        if not key:
            continue
        try:
            num = float(value)
        except Exception:
            continue
        if not math.isfinite(num) or num <= 0:
            continue
        cleaned[key] = num
        total += num

    if total <= 0:
        continue

    normalized = {k: v / total for k, v in cleaned.items()}
    grouped[process_key].append({"agent_id": agent_id, "distribution": normalized})

fleet_rows = []
skipped = 0
for process_key, entries in grouped.items():
    distinct_agents = sorted({item["agent_id"] for item in entries if item["agent_id"]})
    if len(distinct_agents) < min_agents:
        skipped += 1
        continue

    all_keys = sorted({k for item in entries for k in item["distribution"].keys()})
    median = {}
    for event_key in all_keys:
        values = [item["distribution"].get(event_key, 0.0) for item in entries]
        median[event_key] = statistics.median(values)

    total = sum(v for v in median.values() if v > 0)
    if total <= 0:
        skipped += 1
        continue

    median = {k: v / total for k, v in median.items() if v > 0}

    fleet_rows.append(
        {
            "process_key": process_key,
            "median_distribution": median,
            "agent_count": len(distinct_agents),
            "stddev_kl": 0.0,
            "source": "workflow_bundle",
            "source_version": bundle_version,
        }
    )

fleet_rows.sort(key=lambda row: row["process_key"])

bundle = {
    "source": "workflow_bundle",
    "bundle_version": bundle_version,
    "generated_at_unix": int(time.time()),
    "fleet_baselines": fleet_rows,
}

(out_dir / "fleet-baseline-bundle.json").write_text(
    json.dumps(bundle, indent=2, sort_keys=False) + "\n",
    encoding="utf-8",
)

summary_lines = [
    "task=baseline_aggregation",
    "aggregation=median",
    "scope=process_key",
    f"input_file={input_path}",
    f"min_agents={min_agents}",
    f"bundle_version={bundle_version}",
    f"updated={len(fleet_rows)}",
    f"skipped={skipped}",
    "removed=0",
]
(out_dir / "summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

print(f"wrote {len(fleet_rows)} fleet baseline rows -> {out_dir / 'fleet-baseline-bundle.json'}")
PY
