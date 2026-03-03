#!/usr/bin/env python3
"""Resolve trend baseline inputs for perf compare workflow usage."""

from __future__ import annotations

import argparse
import hashlib
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
    parser.add_argument(
        "--require-trend-pass",
        action="store_true",
        help="Require resolved baseline run to have trend.json status=pass",
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
        summary_sha256 = payload.get("summary_sha256")
        return {
            "baseline_summary": str(baseline_summary).strip() if baseline_summary is not None else "",
            "baseline_run": str(baseline_run).strip() if baseline_run is not None else "",
            "summary_sha256": str(summary_sha256).strip() if summary_sha256 is not None else "",
        }

    if isinstance(payload, str):
        value = payload.strip()
        return {"baseline_summary": value, "baseline_run": "", "summary_sha256": ""} if value else {}

    for line in text.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        return {"baseline_summary": candidate, "baseline_run": "", "summary_sha256": ""}

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


def compute_sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def read_status(summary_path: pathlib.Path, file_name: str) -> str:
    status_path = summary_path.parent / file_name
    if not status_path.exists():
        raise ValueError(f"{file_name} missing for baseline run: {summary_path.parent}")

    payload = json.loads(status_path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid {file_name} payload: {status_path}")

    status = payload.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ValueError(f"{file_name} missing string status: {status_path}")

    return status.strip().lower()


def read_gate_status(summary_path: pathlib.Path) -> str:
    return read_status(summary_path, "gate.json")


def read_trend_status(summary_path: pathlib.Path) -> str:
    return read_status(summary_path, "trend.json")


def write_github_output(path: pathlib.Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"resolved={'true' if payload.get('resolved') else 'false'}\n")
        fh.write(f"baseline_input={payload.get('baseline_input', '')}\n")
        fh.write(f"baseline_run={payload.get('baseline_run', '')}\n")
        fh.write(f"baseline_gate_status={payload.get('baseline_gate_status', '')}\n")
        fh.write(f"baseline_trend_status={payload.get('baseline_trend_status', '')}\n")
        fh.write(f"baseline_summary_sha256={payload.get('baseline_summary_sha256', '')}\n")


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
    pointer_summary_sha256 = "" if direct_summary else pointer_data.get("summary_sha256", "")

    payload: Dict[str, Any] = {
        "resolved": False,
        "source": source,
        "baseline_input": "",
        "baseline_run": "",
        "baseline_gate_status": "",
        "baseline_trend_status": "",
        "baseline_summary_sha256": "",
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

        summary_sha256 = compute_sha256(baseline_path)
        if pointer_summary_sha256 and pointer_summary_sha256.lower() != summary_sha256.lower():
            print(
                (
                    "baseline summary SHA256 mismatch for pointer input: "
                    f"expected {pointer_summary_sha256}, got {summary_sha256}"
                ),
                file=sys.stderr,
            )
            return 2

        gate_status = ""
        if args.require_gate_pass:
            try:
                gate_status = read_gate_status(baseline_path)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            if gate_status != "pass":
                print(
                    f"baseline gate status must be pass, got '{gate_status}' for run: {baseline_path.parent}",
                    file=sys.stderr,
                )
                return 2

        trend_status = ""
        if args.require_trend_pass:
            try:
                trend_status = read_trend_status(baseline_path)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            if trend_status != "pass":
                print(
                    f"baseline trend status must be pass, got '{trend_status}' for run: {baseline_path.parent}",
                    file=sys.stderr,
                )
                return 2

        payload = {
            "resolved": True,
            "source": source,
            "baseline_input": str(baseline_path),
            "baseline_run": baseline_run,
            "baseline_gate_status": gate_status,
            "baseline_trend_status": trend_status,
            "baseline_summary_sha256": summary_sha256,
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
