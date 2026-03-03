#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
COMPARE_SCRIPT = REPO_ROOT / "scripts" / "perf" / "compare_trend.py"
GATE_SCRIPT = REPO_ROOT / "scripts" / "perf" / "gate.py"
RESOLVE_BASELINE_SCRIPT = REPO_ROOT / "scripts" / "perf" / "resolve_baseline.py"
UPDATE_BASELINE_POINTER_SCRIPT = REPO_ROOT / "scripts" / "perf" / "update_baseline_pointer.py"
PROMOTE_BASELINE_SCRIPT = REPO_ROOT / "scripts" / "perf" / "promote_baseline.py"


def make_summary(
    run_dir: pathlib.Path,
    *,
    overhead_median: float,
    overhead_p95: float,
    agent_cpu: float,
    runs_on: int = 6,
    runs_off: int = 6,
    quality_flags: list[str] | None = None,
    platforms: tuple[str, ...] = ("linux", "windows"),
) -> pathlib.Path:
    payload = {
        "generated_at_utc": "2026-03-02T00:00:00Z",
        "input_root": str(run_dir),
        "headline_scenario": "ransomware",
        "platforms": {},
    }

    for platform in platforms:
        headline = {
            "runs_on": runs_on,
            "runs_off": runs_off,
            "overhead_median_pct": overhead_median,
            "overhead_p95_pct": overhead_p95,
            "agent_cpu_avg_s": agent_cpu,
            "quality_flags": list(quality_flags or []),
        }
        payload["platforms"][platform] = {
            "headline_scenario": "ransomware",
            "headline": headline,
            "scenarios": {"ransomware": dict(headline)},
        }

    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return summary_path


def write_gate(run_dir: pathlib.Path, status: str) -> pathlib.Path:
    gate_path = run_dir / "gate.json"
    gate_path.write_text(json.dumps({"status": status}, indent=2) + "\n", encoding="utf-8")
    return gate_path


def write_trend(run_dir: pathlib.Path, status: str) -> pathlib.Path:
    trend_path = run_dir / "trend.json"
    trend_path.write_text(json.dumps({"status": status}, indent=2) + "\n", encoding="utf-8")
    return trend_path


def sha256_file(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class PerfCliToolsTest(unittest.TestCase):
    def test_compare_trend_respects_selected_baseline_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_a = make_summary(root / "retest-20260302T043407Z", overhead_median=10.0, overhead_p95=10.0, agent_cpu=0.300)
            run_b = make_summary(root / "rerun2-20260302T061620Z", overhead_median=5.0, overhead_p95=4.0, agent_cpu=0.200)
            run_c = make_summary(root / "rerun3-20260302T062911Z", overhead_median=7.0, overhead_p95=6.0, agent_cpu=0.220)

            report_path = root / "trend.md"
            json_path = root / "trend.json"
            proc = subprocess.run(
                [
                    "python3",
                    str(COMPARE_SCRIPT),
                    "--input",
                    str(run_c.parent),
                    "--input",
                    str(run_a.parent),
                    "--input",
                    str(run_b.parent),
                    "--baseline-run",
                    "rerun2-20260302T061620Z",
                    "--report-output",
                    str(report_path),
                    "--json-output",
                    str(json_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("Baseline run: `rerun2-20260302T061620Z`", report)
            self.assertIn(
                "| rerun3-20260302T062911Z | ransomware | 7.00 | 2.00 | 6.00 | 2.00 | 0.220 | 0.020 |",
                report,
            )

    def test_compare_trend_can_fail_on_new_quality_flags(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            make_summary(root / "run-20260302T010000Z", overhead_median=1.0, overhead_p95=1.0, agent_cpu=0.100)
            make_summary(
                root / "run-20260302T020000Z",
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
                quality_flags=["low_sample_count"],
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(COMPARE_SCRIPT),
                    "--artifact-root",
                    str(root),
                    "--fail-on-new-quality-flags",
                    "--fail-on-regression",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 1, proc.stdout + "\n" + proc.stderr)
            self.assertIn("new quality flags vs baseline", proc.stdout)

    def test_compare_trend_fails_when_required_platform_data_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            make_summary(
                root / "run-20260302T010000Z",
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
                platforms=("linux",),
            )
            make_summary(
                root / "run-20260302T020000Z",
                overhead_median=1.2,
                overhead_p95=1.3,
                agent_cpu=0.110,
                platforms=("linux",),
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(COMPARE_SCRIPT),
                    "--artifact-root",
                    str(root),
                    "--fail-on-regression",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 1, proc.stdout + "\n" + proc.stderr)
            self.assertIn("missing required platform data", proc.stdout)

    def test_compare_trend_required_platforms_override_allows_linux_only_runs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            make_summary(
                root / "run-20260302T010000Z",
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
                platforms=("linux",),
            )
            make_summary(
                root / "run-20260302T020000Z",
                overhead_median=1.2,
                overhead_p95=1.3,
                agent_cpu=0.110,
                platforms=("linux",),
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(COMPARE_SCRIPT),
                    "--artifact-root",
                    str(root),
                    "--required-platforms",
                    "linux",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            self.assertIn("TREND CHECK: PASS", proc.stdout)

    def test_resolve_baseline_direct_summary_derives_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            summary = make_summary(
                root / "rerun2-20260302T061620Z",
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(summary),
                    "--workspace-root",
                    str(root),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(proc.stdout.strip())
            self.assertTrue(payload.get("resolved"))
            self.assertEqual(payload.get("baseline_run"), "rerun2-20260302T061620Z")

    def test_resolve_baseline_pointer_json_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            make_summary(
                root / "rerun3-20260302T062911Z",
                overhead_median=1.1,
                overhead_p95=1.2,
                agent_cpu=0.110,
            )
            pointer = root / "baseline-pointer.json"
            pointer.write_text(
                json.dumps(
                    {
                        "summary_path": "rerun3-20260302T062911Z/summary.json",
                        "baseline_run": "blessed-rerun3",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-pointer",
                    str(pointer),
                    "--workspace-root",
                    str(root),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(proc.stdout.strip())
            self.assertTrue(payload.get("resolved"))
            self.assertEqual(payload.get("source"), "pointer")
            self.assertEqual(payload.get("baseline_run"), "blessed-rerun3")
            self.assertTrue(str(payload.get("baseline_input", "")).endswith("rerun3-20260302T062911Z/summary.json"))

    def test_resolve_baseline_rejects_pointer_sha_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            summary = make_summary(
                root / "rerun-sha-20260302T070000Z",
                overhead_median=1.0,
                overhead_p95=1.1,
                agent_cpu=0.100,
            )
            pointer = root / "sha-pointer.json"
            pointer.write_text(
                json.dumps(
                    {
                        "summary_path": str(summary),
                        "baseline_run": "rerun-sha-20260302T070000Z",
                        "summary_sha256": "deadbeef",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-pointer",
                    str(pointer),
                    "--workspace-root",
                    str(root),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("SHA256 mismatch", proc.stderr)

    def test_update_baseline_pointer_roundtrip_with_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "rerun4-20260302T072000Z"
            make_summary(
                run_dir,
                overhead_median=0.8,
                overhead_p95=0.9,
                agent_cpu=0.090,
            )

            pointer_path = root / ".ci" / "perf-baseline.json"
            update_proc = subprocess.run(
                [
                    "python3",
                    str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary",
                    str(run_dir / "summary.json"),
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(pointer_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(update_proc.returncode, 0, update_proc.stdout + "\n" + update_proc.stderr)

            pointer_payload = json.loads(pointer_path.read_text(encoding="utf-8"))
            expected_sha = sha256_file(run_dir / "summary.json")
            self.assertEqual(pointer_payload.get("summary_sha256"), expected_sha)

            resolve_proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-pointer",
                    str(pointer_path),
                    "--workspace-root",
                    str(root),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(resolve_proc.returncode, 0, resolve_proc.stdout + "\n" + resolve_proc.stderr)
            payload = json.loads(resolve_proc.stdout.strip())
            self.assertTrue(payload.get("resolved"))
            self.assertEqual(payload.get("baseline_run"), "rerun4-20260302T072000Z")
            self.assertEqual(payload.get("baseline_summary_sha256"), expected_sha)

    def test_resolve_baseline_prefers_direct_input_over_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            direct = make_summary(
                root / "direct-20260302T080000Z",
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )
            pointer_run = make_summary(
                root / "pointer-20260302T081000Z",
                overhead_median=2.0,
                overhead_p95=2.0,
                agent_cpu=0.200,
            )
            pointer = root / "baseline-pointer.json"
            pointer.write_text(
                json.dumps({"summary_path": str(pointer_run), "baseline_run": "pointer-run"}) + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(direct),
                    "--baseline-pointer",
                    str(pointer),
                    "--workspace-root",
                    str(root),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(proc.stdout.strip())
            self.assertTrue(payload.get("resolved"))
            self.assertEqual(payload.get("source"), "direct")
            self.assertEqual(payload.get("baseline_run"), "direct-20260302T080000Z")

    def test_resolve_baseline_require_gate_pass_accepts_passing_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-gate-pass-20260302T091000Z"
            summary = make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )
            write_gate(run_dir, "pass")

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(summary),
                    "--workspace-root",
                    str(root),
                    "--require-gate-pass",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(proc.stdout.strip())
            self.assertEqual(payload.get("baseline_gate_status"), "pass")

    def test_resolve_baseline_require_gate_pass_rejects_non_pass_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-gate-fail-20260302T091500Z"
            summary = make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )
            write_gate(run_dir, "fail")

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(summary),
                    "--workspace-root",
                    str(root),
                    "--require-gate-pass",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("baseline gate status must be pass", proc.stderr)

    def test_resolve_baseline_require_trend_pass_accepts_passing_trend(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-trend-pass-20260302T091700Z"
            summary = make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )
            write_trend(run_dir, "pass")

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(summary),
                    "--workspace-root",
                    str(root),
                    "--require-trend-pass",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(proc.stdout.strip())
            self.assertEqual(payload.get("baseline_trend_status"), "pass")

    def test_resolve_baseline_require_trend_pass_rejects_non_pass_trend(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-trend-fail-20260302T091800Z"
            summary = make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )
            write_trend(run_dir, "fail")

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(summary),
                    "--workspace-root",
                    str(root),
                    "--require-trend-pass",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("baseline trend status must be pass", proc.stderr)

    def test_resolve_baseline_strict_pointer_missing_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            missing_pointer = root / ".ci" / "missing-baseline.json"
            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-pointer",
                    str(missing_pointer),
                    "--workspace-root",
                    str(root),
                    "--strict-pointer",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("baseline pointer not found", proc.stderr)

    def test_update_baseline_pointer_absolute_paths_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-abs-20260302T082000Z"
            make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.1,
                agent_cpu=0.100,
            )
            pointer_path = root / "abs-pointer.json"

            proc = subprocess.run(
                [
                    "python3",
                    str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary",
                    str(run_dir / "summary.json"),
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(pointer_path),
                    "--absolute-paths",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(pointer_path.read_text(encoding="utf-8"))
            self.assertTrue(str(payload.get("summary_path", "")).startswith("/"))

    def test_resolve_baseline_directory_input_normalizes_to_summary_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "dir-run-20260302T083000Z"
            make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(RESOLVE_BASELINE_SCRIPT),
                    "--baseline-summary",
                    str(run_dir),
                    "--workspace-root",
                    str(root),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(proc.stdout.strip())
            self.assertTrue(str(payload.get("baseline_input", "")).endswith("/summary.json"))

    def test_update_baseline_pointer_directory_input_writes_summary_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "dir-run-20260302T084000Z"
            make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.1,
                agent_cpu=0.110,
            )
            pointer_path = root / "dir-pointer.json"

            proc = subprocess.run(
                [
                    "python3",
                    str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary",
                    str(run_dir),
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(pointer_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(pointer_path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload.get("summary_path"),
                "dir-run-20260302T084000Z/summary.json",
            )

    def test_update_baseline_pointer_rejects_non_summary_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-bad-input-20260302T084500Z"
            run_dir.mkdir(parents=True, exist_ok=True)
            bad_file = run_dir / "not-summary.json"
            bad_file.write_text("{}\n", encoding="utf-8")

            proc = subprocess.run(
                [
                    "python3",
                    str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary",
                    str(bad_file),
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(root / "bad-pointer.json"),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("baseline file must be summary.json", proc.stderr)

    def test_update_baseline_pointer_requires_force_for_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_old = root / "run-old-20260302T084600Z"
            run_new = root / "run-new-20260302T084700Z"
            make_summary(run_old, overhead_median=1.0, overhead_p95=1.0, agent_cpu=0.10)
            make_summary(run_new, overhead_median=1.1, overhead_p95=1.1, agent_cpu=0.11)
            pointer_path = root / ".ci" / "perf-baseline.json"

            first = subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_old / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + "\n" + first.stderr)

            second = subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_new / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 2)
            self.assertIn("use --force", second.stderr)

    def test_update_baseline_pointer_force_with_backup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_old = root / "run-old-20260302T084800Z"
            run_new = root / "run-new-20260302T084900Z"
            make_summary(run_old, overhead_median=1.0, overhead_p95=1.0, agent_cpu=0.10)
            make_summary(run_new, overhead_median=1.1, overhead_p95=1.1, agent_cpu=0.11)
            pointer_path = root / ".ci" / "perf-baseline.json"

            subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_old / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )

            second = subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_new / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                    "--force", "--backup-existing",
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + "\n" + second.stderr)
            result = json.loads(second.stdout.strip())
            backup_path = result.get("backup_path")
            self.assertTrue(backup_path)
            self.assertTrue(pathlib.Path(backup_path).exists())

    def test_update_baseline_pointer_noop_when_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-stable-20260302T085050Z"
            make_summary(run_dir, overhead_median=1.0, overhead_p95=1.0, agent_cpu=0.10)
            pointer_path = root / ".ci" / "perf-baseline.json"

            first = subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_dir / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + "\n" + first.stderr)
            content_before = pointer_path.read_text(encoding="utf-8")

            second = subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_dir / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + "\n" + second.stderr)
            result = json.loads(second.stdout.strip())
            self.assertFalse(result.get("pointer_written"))
            self.assertEqual(content_before, pointer_path.read_text(encoding="utf-8"))

    def test_update_baseline_pointer_rewrite_if_unchanged_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_dir = root / "run-stable-20260302T085150Z"
            make_summary(run_dir, overhead_median=1.0, overhead_p95=1.0, agent_cpu=0.10)
            pointer_path = root / ".ci" / "perf-baseline.json"

            subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_dir / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )
            content_before = pointer_path.read_text(encoding="utf-8")

            second = subprocess.run(
                [
                    "python3", str(UPDATE_BASELINE_POINTER_SCRIPT),
                    "--baseline-summary", str(run_dir / "summary.json"),
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                    "--rewrite-if-unchanged",
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + "\n" + second.stderr)
            result = json.loads(second.stdout.strip())
            self.assertTrue(result.get("pointer_written"))
            self.assertNotEqual(content_before, pointer_path.read_text(encoding="utf-8"))

    def test_promote_baseline_requires_gate_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_tag = "run-promote-fail-20260302T085000Z"
            run_dir = root / "artifacts" / "perf" / run_tag
            make_summary(
                run_dir,
                overhead_median=1.0,
                overhead_p95=1.0,
                agent_cpu=0.100,
            )
            write_gate(run_dir, "fail")

            proc = subprocess.run(
                [
                    "python3",
                    str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag",
                    run_tag,
                    "--artifact-root",
                    "artifacts/perf",
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(root / ".ci" / "perf-baseline.json"),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cannot promote baseline", proc.stderr)

    def test_promote_baseline_from_candidate_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_tag = "run-promote-pass-20260302T090000Z"
            run_dir = root / "artifacts" / "perf" / run_tag
            summary_path = make_summary(
                run_dir,
                overhead_median=0.9,
                overhead_p95=1.0,
                agent_cpu=0.090,
            )
            write_gate(run_dir, "pass")

            candidate = run_dir / "perf-baseline.candidate.json"
            candidate.write_text(
                json.dumps(
                    {
                        "summary_path": str(summary_path.relative_to(root)),
                        "baseline_run": run_tag,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            pointer_path = root / ".ci" / "perf-baseline.json"

            proc = subprocess.run(
                [
                    "python3",
                    str(PROMOTE_BASELINE_SCRIPT),
                    "--candidate-pointer",
                    str(candidate),
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(pointer_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            payload = json.loads(pointer_path.read_text(encoding="utf-8"))
            self.assertEqual(payload.get("baseline_run"), run_tag)
            self.assertEqual(payload.get("summary_path"), f"artifacts/perf/{run_tag}/summary.json")
            self.assertEqual(payload.get("summary_sha256"), sha256_file(summary_path))

    def test_promote_baseline_requires_force_for_pointer_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            old_tag = "run-promote-old-20260302T090500Z"
            new_tag = "run-promote-new-20260302T090600Z"
            old_dir = root / "artifacts" / "perf" / old_tag
            new_dir = root / "artifacts" / "perf" / new_tag
            make_summary(old_dir, overhead_median=0.8, overhead_p95=0.9, agent_cpu=0.08)
            make_summary(new_dir, overhead_median=0.9, overhead_p95=1.0, agent_cpu=0.09)
            write_gate(old_dir, "pass")
            write_gate(new_dir, "pass")
            pointer_path = root / ".ci" / "perf-baseline.json"

            first = subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", old_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + "\n" + first.stderr)

            second = subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", new_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 2)
            self.assertIn("use --force", second.stderr)

    def test_promote_baseline_force_with_backup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            old_tag = "run-promote-old-20260302T090700Z"
            new_tag = "run-promote-new-20260302T090800Z"
            old_dir = root / "artifacts" / "perf" / old_tag
            new_dir = root / "artifacts" / "perf" / new_tag
            make_summary(old_dir, overhead_median=0.8, overhead_p95=0.9, agent_cpu=0.08)
            make_summary(new_dir, overhead_median=0.9, overhead_p95=1.0, agent_cpu=0.09)
            write_gate(old_dir, "pass")
            write_gate(new_dir, "pass")
            pointer_path = root / ".ci" / "perf-baseline.json"

            subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", old_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )

            second = subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", new_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                    "--force", "--backup-existing",
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + "\n" + second.stderr)
            result = json.loads(second.stdout.strip())
            backup_path = result.get("backup_path")
            self.assertTrue(backup_path)
            self.assertTrue(pathlib.Path(backup_path).exists())

    def test_promote_baseline_noop_when_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_tag = "run-promote-stable-20260302T090850Z"
            run_dir = root / "artifacts" / "perf" / run_tag
            make_summary(run_dir, overhead_median=0.8, overhead_p95=0.9, agent_cpu=0.08)
            write_gate(run_dir, "pass")
            pointer_path = root / ".ci" / "perf-baseline.json"

            first = subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", run_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + "\n" + first.stderr)
            content_before = pointer_path.read_text(encoding="utf-8")

            second = subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", run_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + "\n" + second.stderr)
            result = json.loads(second.stdout.strip())
            self.assertFalse(result.get("pointer_written"))
            self.assertEqual(content_before, pointer_path.read_text(encoding="utf-8"))

    def test_promote_baseline_rewrite_if_unchanged_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_tag = "run-promote-stable-20260302T090855Z"
            run_dir = root / "artifacts" / "perf" / run_tag
            make_summary(run_dir, overhead_median=0.8, overhead_p95=0.9, agent_cpu=0.08)
            write_gate(run_dir, "pass")
            pointer_path = root / ".ci" / "perf-baseline.json"

            subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", run_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )
            content_before = pointer_path.read_text(encoding="utf-8")

            second = subprocess.run(
                [
                    "python3", str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag", run_tag,
                    "--artifact-root", "artifacts/perf",
                    "--workspace-root", str(root),
                    "--pointer-path", str(pointer_path),
                    "--rewrite-if-unchanged",
                ],
                cwd=REPO_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + "\n" + second.stderr)
            result = json.loads(second.stdout.strip())
            self.assertTrue(result.get("pointer_written"))
            self.assertNotEqual(content_before, pointer_path.read_text(encoding="utf-8"))

    def test_promote_baseline_require_trend_pass_rejects_fail(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_tag = "run-promote-trend-fail-20260302T091000Z"
            run_dir = root / "artifacts" / "perf" / run_tag
            make_summary(
                run_dir,
                overhead_median=0.9,
                overhead_p95=1.0,
                agent_cpu=0.090,
            )
            write_gate(run_dir, "pass")
            write_trend(run_dir, "fail")

            proc = subprocess.run(
                [
                    "python3",
                    str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag",
                    run_tag,
                    "--artifact-root",
                    "artifacts/perf",
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(root / ".ci" / "perf-baseline.json"),
                    "--require-trend-pass",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cannot promote baseline: trend status", proc.stderr)

    def test_promote_baseline_dry_run_does_not_write_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            run_tag = "run-promote-dry-20260302T091500Z"
            run_dir = root / "artifacts" / "perf" / run_tag
            make_summary(
                run_dir,
                overhead_median=0.9,
                overhead_p95=1.0,
                agent_cpu=0.090,
            )
            write_gate(run_dir, "pass")
            write_trend(run_dir, "pass")
            pointer_path = root / ".ci" / "perf-baseline.json"

            proc = subprocess.run(
                [
                    "python3",
                    str(PROMOTE_BASELINE_SCRIPT),
                    "--run-tag",
                    run_tag,
                    "--artifact-root",
                    "artifacts/perf",
                    "--workspace-root",
                    str(root),
                    "--pointer-path",
                    str(pointer_path),
                    "--require-trend-pass",
                    "--dry-run",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            self.assertFalse(pointer_path.exists())
            payload = json.loads(proc.stdout.strip())
            self.assertTrue(payload.get("dry_run"))
            self.assertEqual(payload.get("trend_status"), "pass")

    def test_gate_min_runs_and_quality_flag_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            summary_a = make_summary(
                root / "gate-a",
                overhead_median=2.0,
                overhead_p95=2.0,
                agent_cpu=0.200,
                runs_on=5,
                runs_off=6,
            )
            min_runs_fail = subprocess.run(
                [
                    "python3",
                    str(GATE_SCRIPT),
                    "--summary",
                    str(summary_a),
                    "--profile",
                    "provisional",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(min_runs_fail.returncode, 1)
            self.assertIn("insufficient measured runs", min_runs_fail.stdout)

            summary_b = make_summary(
                root / "gate-b",
                overhead_median=2.0,
                overhead_p95=2.0,
                agent_cpu=0.200,
                quality_flags=["high_negative_p95_overhead_check_for_noise"],
            )
            pass_default = subprocess.run(
                [
                    "python3",
                    str(GATE_SCRIPT),
                    "--summary",
                    str(summary_b),
                    "--profile",
                    "provisional",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(pass_default.returncode, 0, pass_default.stdout + "\n" + pass_default.stderr)

            fail_custom = subprocess.run(
                [
                    "python3",
                    str(GATE_SCRIPT),
                    "--summary",
                    str(summary_b),
                    "--profile",
                    "provisional",
                    "--fail-on-quality-flags",
                    "high_negative_p95_overhead_check_for_noise",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(fail_custom.returncode, 1, fail_custom.stdout + "\n" + fail_custom.stderr)
            self.assertIn("quality flags triggered failure", fail_custom.stdout)


if __name__ == "__main__":
    unittest.main()
