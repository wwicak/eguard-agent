#!/usr/bin/env python3
"""Tests for eGuard threat intel bundle structure, processing scripts, and enrichment."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

# Allow running from repo root or from tests/ dir
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROCESSING_DIR = os.path.join(REPO_ROOT, "threat-intel/processing")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class TestBundleStructure(unittest.TestCase):
    """Validate that a built bundle has the expected structure."""

    BUNDLE_DIR = os.environ.get("BUNDLE_DIR", os.path.join(REPO_ROOT, "bundle"))

    def setUp(self):
        if not os.path.isdir(self.BUNDLE_DIR):
            self.skipTest(f"Bundle directory not found: {self.BUNDLE_DIR}")

    def test_manifest_exists(self):
        manifest_path = os.path.join(self.BUNDLE_DIR, "manifest.json")
        self.assertTrue(os.path.isfile(manifest_path), "manifest.json must exist")

    def test_manifest_valid_json(self):
        manifest_path = os.path.join(self.BUNDLE_DIR, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)
        self.assertIn("version", manifest)
        self.assertIn("timestamp", manifest)
        self.assertIn("files", manifest)
        self.assertIsInstance(manifest["files"], dict)

    def test_manifest_required_fields(self):
        manifest_path = os.path.join(self.BUNDLE_DIR, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)
        required = [
            "version", "timestamp", "sigma_count", "yara_count",
            "ioc_hash_count", "ioc_domain_count", "ioc_ip_count",
            "cve_count", "cve_kev_count", "cve_epss_count",
            "sources", "files",
        ]
        for field in required:
            self.assertIn(field, manifest, f"Missing required field: {field}")

    def test_file_hashes_match(self):
        """Every file listed in manifest must exist and hash must match."""
        manifest_path = os.path.join(self.BUNDLE_DIR, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)
        for rel_path, expected_hash in manifest.get("files", {}).items():
            file_path = os.path.join(self.BUNDLE_DIR, rel_path)
            self.assertTrue(os.path.isfile(file_path), f"Missing file: {rel_path}")
            if expected_hash.startswith("sha256:"):
                expected = expected_hash[7:]
                actual = sha256_file(file_path)
                self.assertEqual(actual, expected, f"Hash mismatch: {rel_path}")

    def test_counts_non_negative(self):
        manifest_path = os.path.join(self.BUNDLE_DIR, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)
        for key in ("sigma_count", "yara_count", "ioc_hash_count",
                     "ioc_domain_count", "ioc_ip_count", "cve_count",
                     "cve_kev_count", "cve_epss_count"):
            self.assertGreaterEqual(manifest.get(key, 0), 0, f"{key} must be >= 0")


class TestEd25519BundleArtifacts(unittest.TestCase):
    """Validate expected Ed25519 signature artifacts for packed bundle."""

    BUNDLE_ARCHIVE = os.environ.get(
        "BUNDLE_ARCHIVE", os.path.join(REPO_ROOT, "eguard-rules.bundle.tar.zst")
    )

    def setUp(self):
        if not os.path.isfile(self.BUNDLE_ARCHIVE):
            self.skipTest(f"Bundle archive not found: {self.BUNDLE_ARCHIVE}")

    def test_signature_sidecar_exists(self):
        sig = f"{self.BUNDLE_ARCHIVE}.sig"
        self.assertTrue(os.path.isfile(sig), "bundle signature sidecar must exist")
        self.assertGreater(os.path.getsize(sig), 0, "signature sidecar must be non-empty")

    def test_public_key_hex_exists(self):
        pub_hex = f"{self.BUNDLE_ARCHIVE}.pub.hex"
        self.assertTrue(os.path.isfile(pub_hex), "bundle public key hex sidecar must exist")
        with open(pub_hex, "r", encoding="utf-8") as f:
            content = f.read().strip()
        self.assertEqual(len(content), 64, "public key hex must be 32 bytes")


class TestBundleCoverageGate(unittest.TestCase):
    """Validate signature database coverage gate behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manifest_path = os.path.join(self.tmpdir, "manifest.json")
        self.metrics_path = os.path.join(self.tmpdir, "coverage.json")
        self.script_path = os.path.join(PROCESSING_DIR, "bundle_coverage_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_manifest(self, **overrides):
        manifest = {
            "version": "2026.02.14.0100",
            "sigma_count": 300,
            "yara_count": 1600,
            "ioc_hash_count": 5000,
            "ioc_domain_count": 2200,
            "ioc_ip_count": 14000,
            "cve_count": 18000,
            "cve_kev_count": 200,
            "suricata_count": 25000,
            "elastic_count": 800,
            "sources": {
                "sigma": ["rules", "rules-emerging-threats", "mdecrevoisier"],
                "yara": ["yara-forge", "elastic", "gcti", "reversinglabs"],
            },
            "source_rule_counts": {
                "sigma": {
                    "rules": 180,
                    "rules-emerging-threats": 60,
                    "mdecrevoisier": 40,
                },
                "yara": {
                    "yara-forge": 900,
                    "elastic": 250,
                    "gcti": 140,
                    "reversinglabs": 120,
                },
            },
            "files": {},
        }
        manifest.update(overrides)
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--manifest",
            self.manifest_path,
            "--output",
            self.metrics_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_coverage_gate_passes_with_sufficient_counts(self):
        self._write_manifest()
        result = self._run_gate()
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.metrics_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")

    def test_coverage_gate_fails_on_low_sigma_count(self):
        self._write_manifest(sigma_count=5)
        result = self._run_gate(
            "--min-sigma",
            "10",
            "--min-yara",
            "0",
            "--min-ioc-hash",
            "0",
            "--min-ioc-domain",
            "0",
            "--min-ioc-ip",
            "0",
            "--min-cve",
            "0",
            "--min-cve-kev",
            "0",
            "--min-signature-total",
            "0",
            "--min-database-total",
            "0",
            "--min-yara-sources",
            "0",
            "--min-sigma-sources",
            "0",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("sigma_count coverage too low", out)
        with open(self.metrics_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")

    def test_coverage_gate_fails_when_required_source_missing(self):
        self._write_manifest(
            sources={
                "sigma": ["rules"],
                "yara": ["yara-forge"],
            }
        )
        result = self._run_gate(
            "--min-sigma",
            "0",
            "--min-yara",
            "0",
            "--min-ioc-hash",
            "0",
            "--min-ioc-domain",
            "0",
            "--min-ioc-ip",
            "0",
            "--min-cve",
            "0",
            "--min-cve-kev",
            "0",
            "--min-signature-total",
            "0",
            "--min-database-total",
            "0",
            "--min-yara-sources",
            "0",
            "--min-sigma-sources",
            "0",
            "--require-yara-source",
            "gcti",
            "--require-sigma-source",
            "rules-emerging-threats",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("missing required YARA sources", out)
        self.assertIn("missing required SIGMA sources", out)

    def test_coverage_gate_fails_on_low_required_source_rule_counts(self):
        self._write_manifest(
            source_rule_counts={
                "sigma": {
                    "rules": 10,
                },
                "yara": {
                    "yara-forge": 20,
                },
            }
        )
        result = self._run_gate(
            "--min-sigma",
            "0",
            "--min-yara",
            "0",
            "--min-ioc-hash",
            "0",
            "--min-ioc-domain",
            "0",
            "--min-ioc-ip",
            "0",
            "--min-cve",
            "0",
            "--min-cve-kev",
            "0",
            "--min-signature-total",
            "0",
            "--min-database-total",
            "0",
            "--min-yara-sources",
            "0",
            "--min-sigma-sources",
            "0",
            "--min-yara-source-rules",
            "yara-forge=100",
            "--min-sigma-source-rules",
            "rules-emerging-threats=30",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("yara source yara-forge rule coverage too low", out)
        self.assertIn("sigma source rules-emerging-threats rule coverage too low", out)


class TestCoverageRegressionGate(unittest.TestCase):
    """Validate regression guardrail behavior for coverage metrics."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.current_path = os.path.join(self.tmpdir, "current.json")
        self.previous_path = os.path.join(self.tmpdir, "previous.json")
        self.output_path = os.path.join(self.tmpdir, "regression.json")
        self.script_path = os.path.join(PROCESSING_DIR, "coverage_regression_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_report(self, path: str, **overrides):
        measured = {
            "sigma_count": 300,
            "yara_count": 1500,
            "suricata_count": 22000,
            "elastic_count": 900,
            "ioc_total": 22000,
            "cve_count": 18000,
            "signature_total": 27500,
            "database_total": 67500,
            "yara_source_count": 4,
            "sigma_source_count": 4,
        }
        measured.update(overrides)
        report = {
            "suite": "bundle_signature_coverage_gate",
            "status": "pass",
            "measured": measured,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--current",
            self.current_path,
            "--previous",
            self.previous_path,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_regression_gate_skips_without_previous_baseline(self):
        self._write_report(self.current_path)
        result = self._run_gate()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "skipped_no_baseline")

    def test_regression_gate_passes_when_drop_within_tolerance(self):
        self._write_report(self.current_path, signature_total=190)
        self._write_report(self.previous_path, signature_total=200)
        result = self._run_gate("--max-drop-signature-total-pct", "10")
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")

    def test_regression_gate_fails_on_large_signature_drop(self):
        self._write_report(self.current_path, signature_total=100)
        self._write_report(self.previous_path, signature_total=200)
        result = self._run_gate("--max-drop-signature-total-pct", "20")
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("signature_total regressed", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")

    def test_regression_gate_fails_on_large_suricata_drop(self):
        self._write_report(self.current_path, suricata_count=400)
        self._write_report(self.previous_path, suricata_count=1000)
        result = self._run_gate("--max-drop-suricata-pct", "30")
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("suricata_count regressed", out)


class TestAttackCoverageGate(unittest.TestCase):
    """Validate ATT&CK coverage gate behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sigma_dir = os.path.join(self.tmpdir, "sigma")
        self.elastic_jsonl = os.path.join(self.tmpdir, "elastic-rules.jsonl")
        self.output_path = os.path.join(self.tmpdir, "attack-coverage.json")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_coverage_gate.py")
        os.makedirs(self.sigma_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_sigma_rule(self, name: str, tags: list[str]):
        path = os.path.join(self.sigma_dir, name)
        tags_yaml = "\n".join([f"  - {tag}" for tag in tags])
        content = f"""
title: test rule {name}
id: 11111111-1111-1111-1111-{name.replace('.yml', '').replace('.yaml', '').zfill(12)}
status: test
logsource:
  product: linux
tags:
{tags_yaml}
detection:
  selection:
    Image|endswith: /bin/bash
  condition: selection
""".strip()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content + "\n")

    def _write_elastic_rules(self, rules: list[dict]):
        with open(self.elastic_jsonl, "w", encoding="utf-8") as f:
            for rule in rules:
                f.write(json.dumps(rule) + "\n")

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--sigma-dir",
            self.sigma_dir,
            "--elastic-jsonl",
            self.elastic_jsonl,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_coverage_gate_passes_with_required_tactics(self):
        self._write_sigma_rule("rule1.yml", ["attack.t1059", "attack.execution"])
        self._write_sigma_rule("rule2.yml", ["attack.t1078", "attack.initial_access"])
        self._write_elastic_rules(
            [
                {
                    "mitre_techniques": [{"id": "T1021", "name": "Remote Services"}],
                    "mitre_tactics": [{"id": "TA0008", "name": "Lateral Movement"}],
                }
            ]
        )

        result = self._run_gate(
            "--min-techniques",
            "3",
            "--min-tactics",
            "3",
            "--min-sigma-rules-with-attack",
            "2",
            "--min-elastic-rules-with-attack",
            "1",
            "--min-sigma-techniques",
            "2",
            "--min-elastic-techniques",
            "1",
            "--require-tactic",
            "execution",
            "--require-tactic",
            "lateral_movement",
        )
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")

    def test_attack_coverage_gate_fails_on_missing_required_tactic(self):
        self._write_sigma_rule("rule1.yml", ["attack.t1059", "attack.execution"])
        self._write_elastic_rules(
            [
                {
                    "mitre_techniques": [{"id": "T1021", "name": "Remote Services"}],
                    "mitre_tactics": [{"id": "TA0008", "name": "Lateral Movement"}],
                }
            ]
        )

        result = self._run_gate(
            "--min-techniques",
            "0",
            "--min-tactics",
            "0",
            "--min-sigma-rules-with-attack",
            "0",
            "--min-elastic-rules-with-attack",
            "0",
            "--min-sigma-techniques",
            "0",
            "--min-elastic-techniques",
            "0",
            "--require-tactic",
            "credential_access",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("missing required ATT&CK tactics", out)


class TestAttackRegressionGate(unittest.TestCase):
    """Validate ATT&CK regression guard behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.current_path = os.path.join(self.tmpdir, "current.json")
        self.previous_path = os.path.join(self.tmpdir, "previous.json")
        self.output_path = os.path.join(self.tmpdir, "attack-regression.json")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_regression_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_report(self, path: str, **overrides):
        measured = {
            "total_techniques": 120,
            "total_tactics": 11,
            "sigma_rules_with_attack": 320,
            "elastic_rules_with_attack": 180,
            "sigma_techniques_count": 90,
            "elastic_techniques_count": 40,
        }
        measured.update(overrides)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"suite": "attack_coverage_gate", "measured": measured}, f)

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--current",
            self.current_path,
            "--previous",
            self.previous_path,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_regression_gate_skips_without_baseline(self):
        self._write_report(self.current_path)
        result = self._run_gate()
        self.assertEqual(result.returncode, 0)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "skipped_no_baseline")

    def test_attack_regression_gate_fails_on_technique_drop(self):
        self._write_report(self.current_path, total_techniques=60)
        self._write_report(self.previous_path, total_techniques=120)
        result = self._run_gate("--max-drop-total-techniques-pct", "20")
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("total_techniques regressed", out)


class TestAttackGapBurndownGate(unittest.TestCase):
    """Validate ATT&CK burn-down gate behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.current_path = os.path.join(self.tmpdir, "current.json")
        self.previous_path = os.path.join(self.tmpdir, "previous.json")
        self.output_path = os.path.join(self.tmpdir, "attack-gap-burndown.json")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_gap_burndown_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_report(self, path: str, **overrides):
        measured = {
            "total_techniques": 110,
            "total_tactics": 11,
            "sigma_rules_with_attack": 320,
            "elastic_rules_with_attack": 180,
            "sigma_techniques_count": 90,
            "elastic_techniques_count": 40,
        }
        measured.update(overrides)
        report = {
            "suite": "attack_coverage_gate",
            "status": "pass",
            "thresholds": {
                "min_techniques": 80,
                "min_tactics": 10,
                "required_tactics": [
                    "execution",
                    "persistence",
                    "command_and_control",
                    "impact",
                ],
            },
            "measured": measured,
            "observed_tactics": [
                "execution",
                "persistence",
                "command_and_control",
                "impact",
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--current",
            self.current_path,
            "--previous",
            self.previous_path,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_gap_burndown_gate_passes_when_gap_shrinks(self):
        self._write_report(self.previous_path, total_techniques=100, total_tactics=10)
        self._write_report(self.current_path, total_techniques=110, total_tactics=11)

        result = self._run_gate(
            "--goal-techniques",
            "120",
            "--goal-tactics",
            "12",
            "--max-technique-gap-increase",
            "0",
            "--max-tactic-gap-increase",
            "0",
            "--max-new-missing-required-tactics",
            "0",
        )
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")
        self.assertEqual(report.get("deltas", {}).get("technique_gap_delta"), -10)

    def test_attack_gap_burndown_gate_fails_when_technique_gap_worsens(self):
        self._write_report(self.previous_path, total_techniques=115, total_tactics=12)
        self._write_report(self.current_path, total_techniques=105, total_tactics=11)

        result = self._run_gate(
            "--goal-techniques",
            "120",
            "--goal-tactics",
            "12",
            "--max-technique-gap-increase",
            "0",
            "--max-tactic-gap-increase",
            "0",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("technique gap increased", out)

    def test_attack_gap_burndown_gate_fails_on_new_missing_required_tactic(self):
        self._write_report(self.previous_path)
        self._write_report(self.current_path)
        with open(self.current_path, "r", encoding="utf-8") as f:
            current = json.load(f)
        current["observed_tactics"] = ["execution", "persistence", "impact"]
        with open(self.current_path, "w", encoding="utf-8") as f:
            json.dump(current, f)

        result = self._run_gate(
            "--goal-techniques",
            "120",
            "--goal-tactics",
            "12",
            "--max-new-missing-required-tactics",
            "0",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("new missing required tactics exceeded", out)


class TestAttackCriticalTechniqueGate(unittest.TestCase):
    """Validate critical ATT&CK technique gate behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.coverage_path = os.path.join(self.tmpdir, "attack-coverage.json")
        self.critical_path = os.path.join(self.tmpdir, "critical-techniques.json")
        self.output_path = os.path.join(self.tmpdir, "critical-gate.json")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_critical_technique_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_coverage(self, observed_techniques: list[str]):
        report = {
            "suite": "attack_coverage_gate",
            "status": "pass",
            "observed_techniques": observed_techniques,
        }
        with open(self.coverage_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _write_critical(self):
        rows = [
            {
                "technique": "T1059",
                "name": "Command and Scripting Interpreter",
                "owner": "detections-core",
                "eta": "2026-03-15",
                "priority": "P0",
            },
            {
                "technique": "T1078",
                "name": "Valid Accounts",
                "owner": "identity-defense",
                "eta": "2026-03-20",
                "priority": "P0",
            },
            {
                "technique": "T1021",
                "name": "Remote Services",
                "owner": "network-defense",
                "eta": "2026-03-30",
                "priority": "P0",
            },
            {
                "technique": "T1562",
                "name": "Impair Defenses",
                "owner": "detections-core",
                "eta": "2026-03-25",
                "priority": "P0",
            },
            {
                "technique": "T1486",
                "name": "Data Encrypted for Impact",
                "owner": "detections-core",
                "eta": "2026-03-21",
                "priority": "P0",
            },
        ]
        with open(self.critical_path, "w", encoding="utf-8") as f:
            json.dump(rows, f)

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--attack-coverage",
            self.coverage_path,
            "--critical-techniques",
            self.critical_path,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_critical_technique_gate_passes_when_thresholds_met(self):
        self._write_critical()
        self._write_coverage(["T1059", "T1078", "T1021", "T1486"])

        result = self._run_gate(
            "--min-covered-count",
            "4",
            "--min-covered-ratio",
            "0.75",
            "--max-missing-count",
            "1",
            "--require-technique",
            "T1059",
            "--require-technique",
            "T1021",
        )
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")
        self.assertEqual(report.get("measured", {}).get("covered_count"), 4)
        self.assertEqual(report.get("missing_required_techniques"), [])

    def test_attack_critical_technique_gate_fails_on_low_ratio(self):
        self._write_critical()
        self._write_coverage(["T1059", "T1078", "T1486"])

        result = self._run_gate(
            "--min-covered-count",
            "0",
            "--min-covered-ratio",
            "0.80",
            "--max-missing-count",
            "5",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("coverage ratio too low", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        self.assertAlmostEqual(report.get("measured", {}).get("covered_ratio"), 0.6, places=4)

    def test_attack_critical_technique_gate_fails_on_missing_required(self):
        self._write_critical()
        self._write_coverage(["T1059", "T1078", "T1486"])

        result = self._run_gate(
            "--min-covered-count",
            "3",
            "--max-missing-count",
            "2",
            "--require-technique",
            "T1021",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("required critical ATT&CK techniques missing", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        self.assertIn("T1021", report.get("missing_required_techniques", []))

    def test_attack_critical_technique_gate_rejects_invalid_ratio(self):
        self._write_critical()
        self._write_coverage(["T1059", "T1078", "T1486"])

        result = self._run_gate(
            "--min-covered-ratio",
            "1.20",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("invalid min-covered-ratio", out)


class TestAttackCriticalRegressionGate(unittest.TestCase):
    """Validate critical ATT&CK regression guard behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.current_path = os.path.join(self.tmpdir, "current.json")
        self.previous_path = os.path.join(self.tmpdir, "previous.json")
        self.output_path = os.path.join(self.tmpdir, "critical-regression.json")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_critical_regression_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_report(
        self,
        path: str,
        *,
        critical_total: int = 30,
        covered_count: int = 22,
        covered_ratio: float = 0.7333,
        missing_count: int = 8,
        missing_required_techniques: list[str] | None = None,
    ):
        report = {
            "suite": "attack_critical_technique_gate",
            "status": "pass",
            "measured": {
                "critical_total": critical_total,
                "covered_count": covered_count,
                "covered_ratio": covered_ratio,
                "missing_count": missing_count,
            },
            "missing_required_techniques": missing_required_techniques or [],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--current",
            self.current_path,
            "--previous",
            self.previous_path,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_critical_regression_gate_skips_without_baseline(self):
        self._write_report(self.current_path)
        result = self._run_gate()
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "skipped_no_baseline")

    def test_attack_critical_regression_gate_passes_within_tolerance(self):
        self._write_report(
            self.previous_path,
            covered_count=22,
            covered_ratio=0.7333,
            missing_count=8,
        )
        self._write_report(
            self.current_path,
            covered_count=21,
            covered_ratio=0.70,
            missing_count=9,
        )

        result = self._run_gate(
            "--max-covered-count-drop",
            "2",
            "--max-covered-ratio-drop",
            "0.05",
            "--max-missing-count-increase",
            "2",
            "--max-missing-required-increase",
            "0",
        )
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")

    def test_attack_critical_regression_gate_fails_on_ratio_drop(self):
        self._write_report(self.previous_path, covered_count=22, covered_ratio=0.7333, missing_count=8)
        self._write_report(self.current_path, covered_count=18, covered_ratio=0.6, missing_count=12)

        result = self._run_gate(
            "--max-covered-count-drop",
            "2",
            "--max-covered-ratio-drop",
            "0.05",
            "--max-missing-count-increase",
            "2",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("covered_ratio regressed", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")

    def test_attack_critical_regression_gate_fails_on_missing_required_increase(self):
        self._write_report(self.previous_path, missing_required_techniques=[])
        self._write_report(self.current_path, missing_required_techniques=["T1021", "T1059"])

        result = self._run_gate(
            "--max-covered-count-drop",
            "10",
            "--max-covered-ratio-drop",
            "1",
            "--max-missing-count-increase",
            "10",
            "--max-missing-required-increase",
            "0",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("missing_required_count increased", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        deltas = report.get("deltas", {})
        self.assertEqual(deltas.get("missing_required_count_delta"), 2)


class TestAttackBurndownScoreboard(unittest.TestCase):
    """Validate ATT&CK critical burn-down scoreboard generation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.coverage_path = os.path.join(self.tmpdir, "attack-coverage.json")
        self.critical_path = os.path.join(self.tmpdir, "critical-techniques.json")
        self.attack_gap_path = os.path.join(self.tmpdir, "attack-gap-burndown.json")
        self.previous_path = os.path.join(self.tmpdir, "previous-scoreboard.json")
        self.output_json = os.path.join(self.tmpdir, "scoreboard.json")
        self.output_md = os.path.join(self.tmpdir, "scoreboard.md")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_burndown_scoreboard.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_coverage(self, observed_techniques: list[str]):
        report = {
            "suite": "attack_coverage_gate",
            "status": "pass",
            "observed_techniques": observed_techniques,
        }
        with open(self.coverage_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _write_critical(self):
        rows = [
            {"technique": "T1059", "name": "Command and Scripting Interpreter", "owner": "core", "eta": "2026-03-15", "priority": "P0"},
            {"technique": "T1078", "name": "Valid Accounts", "owner": "identity", "eta": "2026-03-20", "priority": "P0"},
            {"technique": "T1021", "name": "Remote Services", "owner": "network", "eta": "2026-03-30", "priority": "P0"},
            {"technique": "T1486", "name": "Data Encrypted for Impact", "owner": "core", "eta": "2026-03-21", "priority": "P0"},
        ]
        with open(self.critical_path, "w", encoding="utf-8") as f:
            json.dump(rows, f)

    def _write_attack_gap(self):
        report = {
            "status": "pass",
            "current": {"technique_gap": 8, "tactic_gap": 1},
            "burn_down": {"technique_gap_reduced_by": 2, "tactic_gap_reduced_by": 1},
        }
        with open(self.attack_gap_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _write_previous(self, uncovered_techniques: list[str]):
        report = {
            "suite": "attack_burndown_scoreboard",
            "uncovered_critical_techniques": uncovered_techniques,
        }
        with open(self.previous_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _run_scoreboard(self, include_previous: bool):
        cmd = [
            sys.executable,
            self.script_path,
            "--attack-coverage",
            self.coverage_path,
            "--critical-techniques",
            self.critical_path,
            "--attack-gap",
            self.attack_gap_path,
            "--output-json",
            self.output_json,
            "--output-md",
            self.output_md,
        ]
        if include_previous:
            cmd.extend(["--previous-scoreboard", self.previous_path])
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_burndown_scoreboard_tracks_trend(self):
        self._write_critical()
        self._write_attack_gap()
        self._write_coverage(["T1059", "T1078", "T1486"])
        self._write_previous(["T1021", "T1486"])

        result = self._run_scoreboard(include_previous=True)
        self.assertEqual(result.returncode, 0, msg=f"scoreboard failed: {result.stdout}\n{result.stderr}")

        with open(self.output_json, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("critical_total"), 4)
        self.assertEqual(report.get("critical_uncovered_count"), 1)
        self.assertEqual(report.get("trend", {}).get("delta_uncovered"), -1)
        self.assertIn("T1486", report.get("trend", {}).get("newly_covered", []))
        self.assertEqual(
            report.get("top_uncovered_critical_techniques", [{}])[0].get("technique"),
            "T1021",
        )

        with open(self.output_md, "r", encoding="utf-8") as f:
            markdown = f.read()
        self.assertIn("# ATT&CK Critical Technique Burn-down Scoreboard", markdown)
        self.assertIn("## Top Uncovered Critical Techniques", markdown)
        self.assertIn("| T1021 |", markdown)

    def test_attack_burndown_scoreboard_allows_missing_previous_baseline(self):
        self._write_critical()
        self._write_attack_gap()
        self._write_coverage(["T1059", "T1078"])

        result = self._run_scoreboard(include_previous=False)
        self.assertEqual(result.returncode, 0, msg=f"scoreboard failed: {result.stdout}\n{result.stderr}")

        with open(self.output_json, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertIsNone(report.get("trend", {}).get("delta_uncovered"))


class TestProcessingScripts(unittest.TestCase):
    """Smoke tests for processing scripts (import check)."""

    SCRIPTS = [
        "sigma_filter", "yara_validate", "ioc_dedup",
        "ioc_allowlist", "cve_extract", "build_bundle", "bundle_coverage_gate",
        "coverage_regression_gate", "attack_coverage_gate", "attack_regression_gate",
        "attack_gap_burndown_gate", "attack_critical_technique_gate",
        "attack_critical_regression_gate",
        "attack_burndown_scoreboard",
        "ed25519_sign", "ed25519_verify",
    ]

    def test_all_scripts_importable(self):
        for name in self.SCRIPTS:
            path = os.path.join(PROCESSING_DIR, f"{name}.py")
            result = subprocess.run(
                [sys.executable, "-c",
                 f"import importlib.util; spec = importlib.util.spec_from_file_location('{name}', '{path}'); "
                 f"mod = importlib.util.module_from_spec(spec)"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, f"{name}.py import failed: {result.stderr}")


class TestIOCTierSystem(unittest.TestCase):
    """Validate IOC corroboration tier logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        for subdir in ("ips", "hashes", "domains"):
            os.makedirs(os.path.join(self.tmpdir, "input", subdir))
        self.output = os.path.join(self.tmpdir, "output")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_ioc(self, ioc_type: str, source: str, values: list[str]):
        path = os.path.join(self.tmpdir, "input", ioc_type, f"{source}.txt")
        with open(path, "w") as f:
            f.write("\n".join(values) + "\n")

    def _run_dedup(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PROCESSING_DIR, "ioc_dedup.py"),
             "--input", os.path.join(self.tmpdir, "input"),
             "--output", self.output],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"ioc_dedup failed: {result.stderr}")

    def _read_output(self, ioc_type: str) -> list[dict]:
        path = os.path.join(self.output, ioc_type, "consolidated.jsonl")
        if not os.path.isfile(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_tier0_single_source_is_high(self):
        """A single Tier 0 source (Spamhaus) should yield high confidence."""
        self._write_ioc("ips", "spamhaus", ["1.2.3.4"])
        self._run_dedup()
        ips = self._read_output("ips")
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["confidence"], "high")

    def test_tier1_single_source_is_high(self):
        """A single Tier 1 source (FireHOL L1) should yield high confidence."""
        self._write_ioc("ips", "firehol_l1", ["3.3.3.3"])
        self._run_dedup()
        ips = self._read_output("ips")
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["confidence"], "high")

    def test_multi_source_corroboration(self):
        """IP seen by 3 sources (Tier 0 + Tier 1 + Tier 2) should be high."""
        self._write_ioc("ips", "spamhaus", ["5.5.5.5"])
        self._write_ioc("ips", "firehol_l1", ["5.5.5.5"])
        self._write_ioc("ips", "feodo", ["5.5.5.5"])
        self._run_dedup()
        ips = self._read_output("ips")
        ip = next(i for i in ips if i["value"] == "5.5.5.5")
        self.assertEqual(ip["confidence"], "high")
        self.assertEqual(len(ip["sources"]), 3)

    def test_single_tier3_is_low(self):
        """A single Tier 3 source should yield low confidence."""
        self._write_ioc("ips", "cins", ["9.9.9.1"])
        self._run_dedup()
        ips = self._read_output("ips")
        ip = next(i for i in ips if i["value"] == "9.9.9.1")
        self.assertEqual(ip["confidence"], "low")

    def test_single_tier4_source_is_low(self):
        """A single Tier 4 source (OTX/AlienVault) should yield low confidence."""
        self._write_ioc("ips", "otx", ["9.9.9.2"])
        self._run_dedup()
        ips = self._read_output("ips")
        ip = next(i for i in ips if i["value"] == "9.9.9.2")
        self.assertEqual(ip["confidence"], "low")

    def test_two_tier3_is_medium(self):
        """Two Tier 3 sources should yield medium confidence."""
        self._write_ioc("ips", "cins", ["8.8.8.1"])
        self._write_ioc("ips", "blocklist_de", ["8.8.8.1"])
        self._run_dedup()
        ips = self._read_output("ips")
        ip = next(i for i in ips if i["value"] == "8.8.8.1")
        self.assertEqual(ip["confidence"], "medium")


class TestSigmaFilterRobustness(unittest.TestCase):
    """Validate SIGMA filter behavior on malformed/edge docs."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.input_dir = os.path.join(self.tmpdir, "input")
        self.output_dir = os.path.join(self.tmpdir, "output")
        os.makedirs(self.input_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _run_sigma_filter(self):
        result = subprocess.run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "sigma_filter.py"),
                "--input",
                self.input_dir,
                "--output",
                self.output_dir,
                "--platforms",
                "linux",
                "--min-status",
                "test",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"sigma_filter failed: {result.stderr}")

    def _output_rule_count(self) -> int:
        total = 0
        for root, _dirs, files in os.walk(self.output_dir):
            for fname in files:
                if fname.endswith((".yml", ".yaml")):
                    total += 1
        return total

    def test_non_dict_top_level_doc_is_skipped_without_crash(self):
        """A top-level YAML list must not crash filtering and must be skipped."""
        with open(os.path.join(self.input_dir, "bad_list.yml"), "w", encoding="utf-8") as f:
            f.write("- not\n- a\n- dict\n")

        self._run_sigma_filter()
        self.assertEqual(self._output_rule_count(), 0)

    def test_null_status_is_skipped_without_crash(self):
        """A rule with explicit status:null must not crash and should be skipped."""
        with open(os.path.join(self.input_dir, "null_status.yml"), "w", encoding="utf-8") as f:
            f.write(
                """
title: Null status test
id: 11111111-1111-1111-1111-111111111111
status: null
logsource:
  product: linux
detection:
  selection:
    Image|endswith: /bin/bash
  condition: selection
""".strip()
            )

        self._run_sigma_filter()
        self.assertEqual(self._output_rule_count(), 0)


class TestCVEEnrichment(unittest.TestCase):
    """Validate CVE extract with KEV and EPSS enrichment."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_kev_flag_and_epss_score(self):
        nvd = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [{"lang": "en", "value": "Kernel vuln"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}, "baseSeverity": "CRITICAL"}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}],
                    "published": "2024-01-01T00:00:00Z",
                }
            }],
        }
        kev = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-15", "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Known"}]}
        epss_csv = "#comment\ncve,epss,percentile\nCVE-2024-0001,0.95,0.99\n"

        nvd_dir = os.path.join(self.tmpdir, "nvd")
        os.makedirs(nvd_dir)
        with open(os.path.join(nvd_dir, "test.json"), "w") as f:
            json.dump(nvd, f)
        with open(os.path.join(self.tmpdir, "kev.json"), "w") as f:
            json.dump(kev, f)
        with open(os.path.join(self.tmpdir, "epss.csv"), "w") as f:
            f.write(epss_csv)

        output = os.path.join(self.tmpdir, "cves.jsonl")
        result = subprocess.run(
            [sys.executable, os.path.join(PROCESSING_DIR, "cve_extract.py"),
             "--input", nvd_dir, "--output", output,
             "--kev", os.path.join(self.tmpdir, "kev.json"),
             "--epss", os.path.join(self.tmpdir, "epss.csv")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"cve_extract failed: {result.stderr}")

        with open(output) as f:
            cves = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(cves), 1)
        self.assertTrue(cves[0]["actively_exploited"])
        self.assertEqual(cves[0]["kev_ransomware"], "Known")
        self.assertAlmostEqual(cves[0]["epss_score"], 0.95, places=2)

    def test_kev_bypasses_cvss_filter(self):
        """A CVE in CISA KEV should be included even if CVSS < min threshold."""
        nvd = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0002",
                    "descriptions": [{"lang": "en", "value": "Low CVSS but actively exploited"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.5}, "baseSeverity": "LOW"}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"}]}]}],
                    "published": "2024-06-01T00:00:00Z",
                }
            }],
        }
        kev = {"vulnerabilities": [{"cveID": "CVE-2024-0002", "dateAdded": "2024-07-01", "dueDate": "2024-07-15", "knownRansomwareCampaignUse": "Unknown"}]}

        nvd_dir = os.path.join(self.tmpdir, "nvd")
        os.makedirs(nvd_dir)
        with open(os.path.join(nvd_dir, "test.json"), "w") as f:
            json.dump(nvd, f)
        with open(os.path.join(self.tmpdir, "kev.json"), "w") as f:
            json.dump(kev, f)

        output = os.path.join(self.tmpdir, "cves.jsonl")
        result = subprocess.run(
            [sys.executable, os.path.join(PROCESSING_DIR, "cve_extract.py"),
             "--input", nvd_dir, "--output", output,
             "--min-cvss", "7.0",
             "--kev", os.path.join(self.tmpdir, "kev.json")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

        with open(output) as f:
            cves = [json.loads(line) for line in f if line.strip()]
        # Should be included despite CVSS 3.5 < min 7.0, because it's in KEV
        self.assertEqual(len(cves), 1)
        self.assertTrue(cves[0]["actively_exploited"])


if __name__ == "__main__":
    unittest.main()
