#!/usr/bin/env python3
"""Update baseline pointer file for perf trend comparisons."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import shutil
import sys
from typing import Any, Dict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write/update a baseline pointer JSON file")
    parser.add_argument("--baseline-summary", required=True, help="Baseline summary path or run directory")
    parser.add_argument("--baseline-run", default="", help="Optional explicit baseline run tag")
    parser.add_argument("--workspace-root", default=".", help="Workspace root for path normalization")
    parser.add_argument("--pointer-path", default=".ci/perf-baseline.json", help="Pointer file destination")
    parser.add_argument("--absolute-paths", action="store_true", help="Store absolute baseline summary path")
    parser.add_argument("--force", action="store_true", help="Overwrite existing pointer when target changes")
    parser.add_argument("--backup-existing", action="store_true", help="Backup existing pointer before overwrite")
    parser.add_argument(
        "--rewrite-if-unchanged",
        action="store_true",
        help="Rewrite pointer even when baseline target is unchanged",
    )
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


def compute_sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_existing_pointer(path: pathlib.Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"existing pointer is not valid JSON: {path} ({exc})") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"existing pointer payload must be an object: {path}")
    return payload


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

    summary_sha256 = compute_sha256(baseline_path)
    payload: Dict[str, Any] = {
        "summary_path": summary_path_out,
        "summary_sha256": summary_sha256,
        "baseline_run": baseline_run,
        "updated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

    existing_pointer: Dict[str, Any] = {}
    has_existing_pointer = pointer_path.exists()
    pointer_changed = True
    backup_path = ""

    if has_existing_pointer:
        try:
            existing_pointer = load_existing_pointer(pointer_path)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        existing_summary = str(existing_pointer.get("summary_path") or "")
        existing_run = str(existing_pointer.get("baseline_run") or "")
        existing_sha256 = str(existing_pointer.get("summary_sha256") or "")
        pointer_changed = (
            existing_summary != summary_path_out
            or existing_run != baseline_run
            or (existing_sha256 and existing_sha256.lower() != summary_sha256.lower())
        )

        if pointer_changed and not args.force:
            print(
                f"pointer already exists with different baseline; use --force to overwrite: {pointer_path}",
                file=sys.stderr,
            )
            return 2

        if pointer_changed and args.backup_existing:
            backup_name = f"{pointer_path.name}.bak-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
            backup_file = pointer_path.with_name(backup_name)
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pointer_path, backup_file)
            backup_path = str(backup_file)

    pointer_written = False
    if not (has_existing_pointer and not pointer_changed and not args.rewrite_if_unchanged):
        pointer_path.parent.mkdir(parents=True, exist_ok=True)
        pointer_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pointer_written = True

    result = {
        "pointer_path": str(pointer_path),
        "summary_path": summary_path_out,
        "summary_sha256": summary_sha256,
        "baseline_run": baseline_run,
        "workspace_root": str(workspace_root),
        "has_existing_pointer": has_existing_pointer,
        "pointer_changed": pointer_changed,
        "pointer_written": pointer_written,
        "rewrite_if_unchanged": bool(args.rewrite_if_unchanged),
        "backup_path": backup_path,
    }

    if args.json_output:
        out_path = resolve_path(args.json_output, workspace_root)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
