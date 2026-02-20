#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Windows benchmark artifacts against a target profile")
    parser.add_argument("--metrics", required=True, help="Path to windows benchmark metrics.json")
    parser.add_argument("--mitre", required=True, help="Path to windows mitre-coverage.json")
    parser.add_argument("--profile", required=True, help="Path to competitive target profile JSON")
    parser.add_argument("--out", required=True, help="Output path for evaluation JSON")
    parser.add_argument("--no-gate", action="store_true", help="Do not fail process when gates are missed")
    args = parser.parse_args()

    metrics = load_json(Path(args.metrics))
    mitre = load_json(Path(args.mitre))
    profile = load_json(Path(args.profile))

    targets = profile.get("targets", {})
    wall_clock_max = targets.get("detection_wall_clock_ms_max")
    coverage_min = targets.get("mitre_reference_coverage_pct_min")

    observed_wall_clock = metrics.get("wall_clock_ms")
    observed_coverage = mitre.get("coverage_pct")

    checks = []

    if wall_clock_max is not None:
        checks.append(
            {
                "name": "detection_wall_clock_ms",
                "target": {"op": "<=", "value": wall_clock_max},
                "observed": observed_wall_clock,
                "pass": observed_wall_clock is not None and observed_wall_clock <= wall_clock_max,
            }
        )

    if coverage_min is not None:
        checks.append(
            {
                "name": "mitre_reference_coverage_pct",
                "target": {"op": ">=", "value": coverage_min},
                "observed": observed_coverage,
                "pass": observed_coverage is not None and float(observed_coverage) >= float(coverage_min),
            }
        )

    status = "pass" if all(check["pass"] for check in checks) else "fail"

    result = {
        "evaluated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "profile_name": profile.get("profile_name", "unnamed-profile"),
        "status": status,
        "checks": checks,
        "inputs": {
            "metrics": str(Path(args.metrics)),
            "mitre": str(Path(args.mitre)),
            "profile": str(Path(args.profile)),
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"windows competitive evaluation status={status} out={out_path}")

    if status != "pass" and not args.no_gate:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
