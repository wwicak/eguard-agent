#!/usr/bin/env python3
"""Promote a benchmark run (or candidate pointer) as active perf baseline."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Dict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Promote a run into baseline pointer")
    parser.add_argument("--run-tag", default="", help="Run tag under --artifact-root (e.g. rerun3-...)")
    parser.add_argument("--artifact-root", default="artifacts/perf", help="Root directory containing run artifacts")
    parser.add_argument("--candidate-pointer", default="", help="Optional candidate pointer JSON path")
    parser.add_argument("--pointer-path", default=".ci/perf-baseline.json", help="Destination pointer path")
    parser.add_argument("--workspace-root", default=".", help="Workspace root")
    parser.add_argument("--skip-gate-check", action="store_true", help="Skip gate.json pass-status requirement")
    parser.add_argument("--json-output", default="", help="Optional output JSON path")
    return parser.parse_args()


def resolve_path(raw: str, workspace_root: pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(raw)
    if not p.is_absolute():
        return (workspace_root / p).resolve()
    return p.resolve()


def load_candidate(path: pathlib.Path) -> Dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"candidate pointer must be an object: {path}")

    summary_path = payload.get("summary_path")
    baseline_run = payload.get("baseline_run")
    if not isinstance(summary_path, str) or not summary_path.strip():
        raise ValueError(f"candidate pointer missing summary_path: {path}")

    return {
        "summary_path": summary_path.strip(),
        "baseline_run": baseline_run.strip() if isinstance(baseline_run, str) else "",
    }


def canonical_summary_path(path: pathlib.Path) -> pathlib.Path:
    if path.is_dir():
        path = path / "summary.json"
    if not path.exists():
        raise ValueError(f"summary path not found: {path}")
    if path.name != "summary.json":
        raise ValueError(f"summary path must target summary.json: {path}")
    return path.resolve()


def read_gate_status(run_dir: pathlib.Path) -> str:
    gate_path = run_dir / "gate.json"
    if not gate_path.exists():
        raise ValueError(f"gate.json missing for run: {run_dir}")
    payload = json.loads(gate_path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid gate.json payload: {gate_path}")
    status = payload.get("status")
    if not isinstance(status, str):
        raise ValueError(f"gate.json missing string status: {gate_path}")
    return status.strip().lower()


def to_workspace_relative(path: pathlib.Path, workspace_root: pathlib.Path) -> str:
    try:
        return str(path.relative_to(workspace_root))
    except ValueError:
        return str(path)


def main() -> int:
    args = parse_args()
    workspace_root = pathlib.Path(args.workspace_root).resolve()

    summary_path: pathlib.Path
    baseline_run: str

    if args.candidate_pointer.strip():
        candidate_path = resolve_path(args.candidate_pointer.strip(), workspace_root)
        if not candidate_path.exists():
            print(f"candidate pointer not found: {candidate_path}", file=sys.stderr)
            return 2
        try:
            candidate = load_candidate(candidate_path)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        summary_path_raw = resolve_path(candidate["summary_path"], workspace_root)
        try:
            summary_path = canonical_summary_path(summary_path_raw)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        baseline_run = candidate.get("baseline_run") or summary_path.parent.name
    else:
        run_tag = args.run_tag.strip()
        if not run_tag:
            print("either --run-tag or --candidate-pointer is required", file=sys.stderr)
            return 2
        run_dir = resolve_path(args.artifact_root, workspace_root) / run_tag
        try:
            summary_path = canonical_summary_path(run_dir)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        baseline_run = run_tag

    run_dir = summary_path.parent
    if not args.skip_gate_check:
        try:
            gate_status = read_gate_status(run_dir)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if gate_status != "pass":
            print(f"cannot promote baseline: gate status is '{gate_status}' for run {run_dir.name}", file=sys.stderr)
            return 2

    pointer_path = resolve_path(args.pointer_path, workspace_root)
    pointer_payload: Dict[str, Any] = {
        "summary_path": to_workspace_relative(summary_path, workspace_root),
        "baseline_run": baseline_run,
        "promoted_from_run": run_dir.name,
    }

    pointer_path.parent.mkdir(parents=True, exist_ok=True)
    pointer_path.write_text(json.dumps(pointer_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = {
        "pointer_path": str(pointer_path),
        "summary_path": pointer_payload["summary_path"],
        "baseline_run": baseline_run,
        "run_tag": run_dir.name,
        "gate_check_skipped": bool(args.skip_gate_check),
    }

    if args.json_output:
        out_path = resolve_path(args.json_output, workspace_root)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
