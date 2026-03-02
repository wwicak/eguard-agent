#!/usr/bin/env python3
"""Update baseline pointer file for perf trend comparisons."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any, Dict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write/update a baseline pointer JSON file")
    parser.add_argument("--baseline-summary", required=True, help="Baseline summary path or run directory")
    parser.add_argument("--baseline-run", default="", help="Optional explicit baseline run tag")
    parser.add_argument("--workspace-root", default=".", help="Workspace root for path normalization")
    parser.add_argument("--pointer-path", default=".ci/perf-baseline.json", help="Pointer file destination")
    parser.add_argument("--absolute-paths", action="store_true", help="Store absolute baseline summary path")
    parser.add_argument("--json-output", default="", help="Optional output path for write result payload")
    return parser.parse_args()


def resolve_path(raw: str, workspace_root: pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(raw)
    if not path.is_absolute():
        path = (workspace_root / path).resolve()
    else:
        path = path.resolve()
    return path


def canonicalize_summary_path(path: pathlib.Path) -> pathlib.Path:
    if path.is_dir():
        candidate = path / "summary.json"
        if not candidate.exists():
            raise ValueError(f"run directory missing summary.json: {path}")
        return candidate.resolve()

    if not path.exists():
        raise ValueError(f"baseline input not found: {path}")

    if path.name != "summary.json":
        raise ValueError(f"baseline file must be summary.json: {path}")

    return path.resolve()


def derive_run_name(path: pathlib.Path) -> str:
    if path.name == "summary.json":
        return path.parent.name
    return path.name


def main() -> int:
    args = parse_args()
    workspace_root = pathlib.Path(args.workspace_root).resolve()

    baseline_path_raw = resolve_path(args.baseline_summary, workspace_root)
    try:
        baseline_path = canonicalize_summary_path(baseline_path_raw)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    pointer_path = resolve_path(args.pointer_path, workspace_root)

    baseline_run = args.baseline_run.strip() if isinstance(args.baseline_run, str) else ""
    if not baseline_run:
        baseline_run = derive_run_name(baseline_path)

    if args.absolute_paths:
        summary_path_out = str(baseline_path)
    else:
        try:
            summary_path_out = str(baseline_path.relative_to(workspace_root))
        except ValueError:
            summary_path_out = str(baseline_path)

    payload: Dict[str, Any] = {
        "summary_path": summary_path_out,
        "baseline_run": baseline_run,
        "updated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

    pointer_path.parent.mkdir(parents=True, exist_ok=True)
    pointer_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = {
        "pointer_path": str(pointer_path),
        "summary_path": summary_path_out,
        "baseline_run": baseline_run,
        "workspace_root": str(workspace_root),
    }

    if args.json_output:
        out_path = resolve_path(args.json_output, workspace_root)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
