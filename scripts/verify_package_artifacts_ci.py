#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any


def run_check(command: list[str]) -> tuple[bool, str]:
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return completed.returncode == 0, completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate generated .deb and .rpm package artifacts.")
    parser.add_argument("--artifact-dir", default="artifacts/package-agent")
    parser.add_argument("--output", default="artifacts/package-agent/verification.json")
    args = parser.parse_args()

    artifact_dir = pathlib.Path(args.artifact_dir)
    deb_dir = artifact_dir / "debian"
    rpm_dir = artifact_dir / "rpm"

    debs = sorted(deb_dir.glob("*.deb"))
    rpms = sorted(rpm_dir.glob("*.rpm"))

    failures: list[str] = []
    records: list[dict[str, Any]] = []

    if not debs:
        failures.append(f"no .deb artifacts found under {deb_dir}")
    if not rpms:
        failures.append(f"no .rpm artifacts found under {rpm_dir}")

    for deb in debs:
        ok, output = run_check(["dpkg-deb", "--info", str(deb)])
        records.append(
            {
                "artifact": str(deb),
                "type": "deb",
                "status": "ok" if ok else "invalid",
                "validator": "dpkg-deb --info",
                "output": output,
            }
        )
        if not ok:
            failures.append(f"invalid deb package: {deb}")

    for rpm in rpms:
        ok, output = run_check(["rpm", "-qpi", str(rpm)])
        records.append(
            {
                "artifact": str(rpm),
                "type": "rpm",
                "status": "ok" if ok else "invalid",
                "validator": "rpm -qpi",
                "output": output,
            }
        )
        if not ok:
            failures.append(f"invalid rpm package: {rpm}")

    payload = {
        "suite": "package_artifact_validation",
        "artifact_dir": str(artifact_dir),
        "debian_count": len(debs),
        "rpm_count": len(rpms),
        "status": "failed" if failures else "ok",
        "records": records,
        "failures": failures,
    }

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"wrote package artifact validation report to {output_path}")

    if failures:
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
