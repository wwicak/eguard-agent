#!/usr/bin/env python3
"""Resolve trend baseline inputs for perf compare workflow usage."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Dict, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve baseline summary/run from direct input or pointer file")
    parser.add_argument("--baseline-summary", default="", help="Direct baseline summary path or run directory")
    parser.add_argument("--baseline-pointer", default="", help="Optional pointer file (plain text or JSON)")
    parser.add_argument("--workspace-root", default=".", help="Workspace root for resolving relative paths")
    parser.add_argument("--strict-pointer", action="store_true", help="Fail when pointer file is provided but missing")
    parser.add_argument(
        "--require-gate-pass",
        action="store_true",
        help="Require resolved baseline run to have gate.json status=pass",
    )
    parser.add_argument("--json-output", default="", help="Optional path for JSON resolution payload")
    parser.add_argument(
        "--github-output",
        default="",
        help="Optional $GITHUB_OUTPUT file path for writing baseline_input/baseline_run/resolved outputs",
    )
    return parser.parse_args()


def parse_pointer(path: pathlib.Path) -> Dict[str, str]:
    text = path.read_text(encoding="utf-8-sig")
    stripped = text.strip()
    if not stripped:
        return {}

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, dict):
        baseline_summary = payload.get("baseline_summary") or payload.get("summary_path") or payload.get("baseline_input")
        baseline_run = payload.get("baseline_run") or payload.get("run")
        return {
            "baseline_summary": str(baseline_summary).strip() if baseline_summary is not None else "",
            "baseline_run": str(baseline_run).strip() if baseline_run is not None else "",
        }

    if isinstance(payload, str):
        value = payload.strip()
        return {"baseline_summary": value, "baseline_run": ""} if value else {}

    for line in text.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        return {"baseline_summary": candidate, "baseline_run": ""}

    return {}


def resolve_path(raw_path: str, workspace_root: pathlib.Path) -> pathlib.Path:
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        candidate = (workspace_root / candidate).resolve()
    else:
        candidate = candidate.resolve()
    return candidate


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


def read_gate_status(summary_path: pathlib.Path) -> str:
    gate_path = summary_path.parent / "gate.json"
    if not gate_path.exists():
        raise ValueError(f"gate.json missing for baseline run: {summary_path.parent}")

    payload = json.loads(gate_path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid gate.json payload: {gate_path}")

    status = payload.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ValueError(f"gate.json missing string status: {gate_path}")

    return status.strip().lower()


def write_github_output(path: pathlib.Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"resolved={'true' if payload.get('resolved') else 'false'}\n")
        fh.write(f"baseline_input={payload.get('baseline_input', '')}\n")
        fh.write(f"baseline_run={payload.get('baseline_run', '')}\n")
        fh.write(f"baseline_gate_status={payload.get('baseline_gate_status', '')}\n")


def main() -> int:
    args = parse_args()
    workspace_root = pathlib.Path(args.workspace_root).resolve()

    direct_summary = args.baseline_summary.strip() if isinstance(args.baseline_summary, str) else ""
    pointer_path_raw = args.baseline_pointer.strip() if isinstance(args.baseline_pointer, str) else ""

    source = "none"
    pointer_data: Dict[str, str] = {}

    if pointer_path_raw:
        pointer_path = resolve_path(pointer_path_raw, workspace_root)
        if pointer_path.exists():
            pointer_data = parse_pointer(pointer_path)
        elif args.strict_pointer:
            print(f"baseline pointer not found: {pointer_path}", file=sys.stderr)
            return 2

    baseline_summary_raw = direct_summary or pointer_data.get("baseline_summary", "")
    baseline_run_raw = "" if direct_summary else pointer_data.get("baseline_run", "")

    payload: Dict[str, Any] = {
        "resolved": False,
        "source": source,
        "baseline_input": "",
        "baseline_run": "",
    }

    if baseline_summary_raw:
        source = "direct" if direct_summary else "pointer"
        baseline_path_raw = resolve_path(baseline_summary_raw, workspace_root)
        try:
            baseline_path = canonicalize_summary_path(baseline_path_raw)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        baseline_run = baseline_run_raw or derive_run_name(baseline_path)
        payload = {
            "resolved": True,
            "source": source,
            "baseline_input": str(baseline_path),
            "baseline_run": baseline_run,
        }

    if args.json_output:
        out_path = pathlib.Path(args.json_output)
        if not out_path.is_absolute():
            out_path = (workspace_root / out_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.github_output:
        gh_out = pathlib.Path(args.github_output)
        if not gh_out.is_absolute():
            gh_out = (workspace_root / gh_out).resolve()
        write_github_output(gh_out, payload)

    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
