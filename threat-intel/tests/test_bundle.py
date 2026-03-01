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
        p0_uncovered_count: int = 0,
        p0_by_owner: dict[str, int] | None = None,
    ):
        critical_rows = []
        if p0_by_owner:
            idx = 0
            for owner, count in p0_by_owner.items():
                for _ in range(count):
                    critical_rows.append(
                        {
                            "technique": f"T900{idx}",
                            "priority": "P0",
                            "owner": owner,
                            "covered": False,
                        }
                    )
                    idx += 1
        else:
            for idx in range(p0_uncovered_count):
                critical_rows.append(
                    {
                        "technique": f"T900{idx}",
                        "priority": "P0",
                        "covered": False,
                    }
                )
        critical_rows.append(
            {
                "technique": "T1001",
                "priority": "P1",
                "covered": True,
            }
        )

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
            "critical_techniques": critical_rows,
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

    def test_attack_critical_regression_gate_fails_on_p0_uncovered_increase(self):
        self._write_report(self.previous_path, p0_uncovered_count=1)
        self._write_report(self.current_path, p0_uncovered_count=3)

        result = self._run_gate(
            "--max-covered-count-drop",
            "10",
            "--max-covered-ratio-drop",
            "1",
            "--max-missing-count-increase",
            "10",
            "--max-missing-required-increase",
            "10",
            "--max-p0-uncovered-increase",
            "1",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("p0_uncovered_count increased", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        self.assertEqual(report.get("deltas", {}).get("p0_uncovered_count_delta"), 2)

    def test_attack_critical_regression_gate_fails_on_owner_level_p0_increase(self):
        self._write_report(self.previous_path, p0_by_owner={"core": 1, "identity": 1})
        self._write_report(self.current_path, p0_by_owner={"core": 4, "identity": 1})

        result = self._run_gate(
            "--max-covered-count-drop",
            "10",
            "--max-covered-ratio-drop",
            "1",
            "--max-missing-count-increase",
            "10",
            "--max-missing-required-increase",
            "10",
            "--max-p0-uncovered-increase",
            "10",
            "--max-owner-p0-uncovered-increase",
            "1",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("owner-level P0 uncovered regressions", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        owner_increase = report.get("deltas", {}).get("owner_p0_increase_by_owner", {})
        owner_regressions = report.get("deltas", {}).get("owner_p0_regression_by_owner", {})
        self.assertEqual(owner_increase.get("core"), 3)
        self.assertEqual(owner_regressions.get("core"), 3)
        self.assertEqual(report.get("deltas", {}).get("owner_p0_regression_count"), 1)


class TestAttackCriticalRegressionHistory(unittest.TestCase):
    """Validate critical ATT&CK regression history updater behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.current_report = os.path.join(self.tmpdir, "critical-regression.json")
        self.previous_history = os.path.join(self.tmpdir, "previous-history.ndjson")
        self.output_history = os.path.join(self.tmpdir, "history.ndjson")
        self.output_summary = os.path.join(self.tmpdir, "history-summary.json")
        self.script_path = os.path.join(
            PROCESSING_DIR,
            "update_attack_critical_regression_history.py",
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_current_report(
        self,
        *,
        status: str = "pass",
        recorded_at_utc: str = "2026-02-14T10:00:00Z",
        covered_count: int = 22,
        covered_ratio: float = 0.7333,
        missing_count: int = 8,
        missing_required_count: int = 1,
        p0_uncovered_count: int = 2,
        owner_p0_regression_by_owner: dict[str, int] | None = None,
    ):
        owner_regression_map = owner_p0_regression_by_owner or {"core": 1}
        report = {
            "suite": "attack_critical_regression_gate",
            "recorded_at_utc": recorded_at_utc,
            "status": status,
            "current": {
                "covered_count": covered_count,
                "covered_ratio": covered_ratio,
                "missing_count": missing_count,
                "missing_required_count": missing_required_count,
                "p0_uncovered_count": p0_uncovered_count,
            },
            "deltas": {
                "covered_count_delta": -1,
                "covered_ratio_delta": -0.01,
                "missing_count_delta": 1,
                "missing_required_count_delta": 0,
                "p0_uncovered_count_delta": 1,
                "owner_p0_regression_by_owner": owner_regression_map,
                "owner_p0_regression_count": len(owner_regression_map),
                "owner_p0_increase_by_owner": owner_regression_map,
            },
        }
        with open(self.current_report, "w", encoding="utf-8") as f:
            json.dump(report, f)

    def _write_previous_history(self):
        rows = [
            {
                "recorded_at_utc": "2026-02-13T10:00:00Z",
                "status": "pass",
                "covered_count": 23,
                "covered_ratio": 0.75,
                "missing_count": 7,
                "missing_required_count": 1,
                "p0_uncovered_count": 1,
                "owner_p0_regression_by_owner": {},
            },
            {
                "recorded_at_utc": "2026-02-14T09:00:00Z",
                "status": "fail",
                "covered_count": 21,
                "covered_ratio": 0.70,
                "missing_count": 9,
                "missing_required_count": 2,
                "p0_uncovered_count": 3,
                "owner_p0_regression_by_owner": {"core": 2, "identity": 1},
            },
        ]
        with open(self.previous_history, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")

    def _run_history(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--current-report",
            self.current_report,
            "--previous-history",
            self.previous_history,
            "--output-history",
            self.output_history,
            "--output-summary",
            self.output_summary,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_critical_regression_history_appends_snapshot(self):
        self._write_current_report()
        self._write_previous_history()

        result = self._run_history()
        self.assertEqual(result.returncode, 0, msg=f"history failed: {result.stdout}\n{result.stderr}")

        with open(self.output_history, "r", encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[-1].get("recorded_at_utc"), "2026-02-14T10:00:00Z")
        self.assertEqual(rows[-1].get("p0_uncovered_count"), 2)

        with open(self.output_summary, "r", encoding="utf-8") as f:
            summary = json.load(f)
        self.assertEqual(summary.get("history_points"), 3)
        self.assertEqual(summary.get("window_failures"), 1)
        self.assertEqual(summary.get("window_passes"), 2)
        owner_totals = summary.get("window_owner_p0_regression_totals", {})
        self.assertEqual(owner_totals.get("core"), 3)
        self.assertEqual(owner_totals.get("identity"), 1)

    def test_attack_critical_regression_history_enforces_max_entries(self):
        self._write_current_report(recorded_at_utc="2026-02-14T10:00:00Z")
        self._write_previous_history()

        result = self._run_history("--max-entries", "2")
        self.assertEqual(result.returncode, 0, msg=f"history failed: {result.stdout}\n{result.stderr}")

        with open(self.output_history, "r", encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].get("recorded_at_utc"), "2026-02-14T09:00:00Z")
        self.assertEqual(rows[1].get("recorded_at_utc"), "2026-02-14T10:00:00Z")


class TestAttackCriticalOwnerStreakGate(unittest.TestCase):
    """Validate owner-level critical regression streak guard behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.history_path = os.path.join(self.tmpdir, "critical-history.ndjson")
        self.output_path = os.path.join(self.tmpdir, "owner-streak-gate.json")
        self.script_path = os.path.join(PROCESSING_DIR, "attack_critical_owner_streak_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_history(self, rows: list[dict]):
        with open(self.history_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")

    def _run_gate(self, *extra_args):
        cmd = [
            sys.executable,
            self.script_path,
            "--history",
            self.history_path,
            "--output",
            self.output_path,
            *extra_args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_attack_critical_owner_streak_gate_skips_missing_history(self):
        os.remove(self.history_path) if os.path.exists(self.history_path) else None
        result = self._run_gate()
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "skipped_no_history")

    def test_attack_critical_owner_streak_gate_passes_with_short_streaks(self):
        rows = [
            {
                "recorded_at_utc": "2026-02-14T08:00:00Z",
                "status": "pass",
                "owner_p0_regression_by_owner": {"core": 1},
            },
            {
                "recorded_at_utc": "2026-02-14T09:00:00Z",
                "status": "pass",
                "owner_p0_regression_by_owner": {},
            },
            {
                "recorded_at_utc": "2026-02-14T10:00:00Z",
                "status": "pass",
                "owner_p0_regression_by_owner": {"core": 1, "identity": 1},
            },
        ]
        self._write_history(rows)

        result = self._run_gate(
            "--window-size",
            "10",
            "--min-history-length",
            "3",
            "--max-consecutive-owner-regression",
            "2",
        )
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")
        self.assertEqual(report.get("violating_owner_streaks"), {})

    def test_attack_critical_owner_streak_gate_fails_on_consecutive_owner_regressions(self):
        rows = [
            {
                "recorded_at_utc": "2026-02-14T08:00:00Z",
                "status": "pass",
                "owner_p0_regression_by_owner": {"core": 1},
            },
            {
                "recorded_at_utc": "2026-02-14T09:00:00Z",
                "status": "pass",
                "owner_p0_regression_by_owner": {"core": 2},
            },
            {
                "recorded_at_utc": "2026-02-14T10:00:00Z",
                "status": "pass",
                "owner_p0_regression_by_owner": {"core": 1, "identity": 1},
            },
        ]
        self._write_history(rows)

        result = self._run_gate(
            "--window-size",
            "10",
            "--min-history-length",
            "3",
            "--max-consecutive-owner-regression",
            "2",
        )
        self.assertNotEqual(result.returncode, 0)
        out = f"{result.stdout}\n{result.stderr}"
        self.assertIn("owner-level P0 regression streak exceeded", out)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        self.assertEqual(report.get("violating_owner_streaks", {}).get("core"), 3)


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


class TestSignatureMLReadinessGate(unittest.TestCase):
    """Validate signature ML readiness scoring behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manifest_path = os.path.join(self.tmpdir, "manifest.json")
        self.coverage_path = os.path.join(self.tmpdir, "coverage.json")
        self.attack_coverage_path = os.path.join(self.tmpdir, "attack-coverage.json")
        self.critical_gate_path = os.path.join(self.tmpdir, "attack-critical-technique-gate.json")
        self.critical_regression_path = os.path.join(self.tmpdir, "attack-critical-regression.json")
        self.owner_streak_path = os.path.join(self.tmpdir, "attack-critical-owner-streak-gate.json")
        self.burndown_path = os.path.join(self.tmpdir, "attack-burndown-scoreboard.json")
        self.previous_path = os.path.join(self.tmpdir, "previous-signature-ml-readiness.json")
        self.output_path = os.path.join(self.tmpdir, "signature-ml-readiness.json")
        self.script_path = os.path.join(PROCESSING_DIR, "signature_ml_readiness_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_manifest(self, **overrides):
        payload = {
            "version": "2026.02.15.0100",
            "cve_epss_count": 12000,
        }
        payload.update(overrides)
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _write_coverage(self, *, strong: bool):
        if strong:
            measured = {
                "signature_total": 7200,
                "database_total": 26400,
                "cve_count": 22000,
                "cve_kev_count": 320,
                "yara_source_count": 5,
                "sigma_source_count": 4,
            }
            observed_source_rule_counts = {
                "yara": {
                    "yara-forge": 1200,
                    "elastic": 900,
                    "gcti": 600,
                    "reversinglabs": 300,
                    "bartblaze": 200,
                },
                "sigma": {
                    "rules": 220,
                    "rules-emerging-threats": 130,
                    "rules-threat-hunting": 90,
                    "mdecrevoisier": 60,
                },
            }
        else:
            measured = {
                "signature_total": 950,
                "database_total": 5200,
                "cve_count": 1100,
                "cve_kev_count": 55,
                "yara_source_count": 1,
                "sigma_source_count": 1,
            }
            observed_source_rule_counts = {
                "yara": {
                    "yara-forge": 950,
                },
                "sigma": {
                    "rules": 120,
                },
            }

        payload = {
            "suite": "bundle_signature_coverage_gate",
            "status": "pass",
            "thresholds": {
                "min_signature_total": 900,
                "min_database_total": 5000,
                "min_cve": 1000,
                "min_cve_kev": 50,
                "min_yara_sources": 3,
                "min_sigma_sources": 2,
            },
            "measured": measured,
            "observed_source_rule_counts": observed_source_rule_counts,
        }
        with open(self.coverage_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _write_attack_coverage(self):
        payload = {
            "suite": "attack_coverage_gate",
            "status": "pass",
            "thresholds": {
                "min_techniques": 80,
                "min_tactics": 10,
                "min_sigma_rules_with_attack": 150,
                "min_elastic_rules_with_attack": 50,
            },
            "measured": {
                "total_techniques": 132,
                "total_tactics": 13,
                "sigma_rules_with_attack": 260,
                "elastic_rules_with_attack": 120,
            },
        }
        with open(self.attack_coverage_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _write_critical_reports(self):
        critical_gate = {
            "suite": "attack_critical_technique_gate",
            "status": "pass",
            "measured": {
                "critical_total": 24,
                "covered_count": 22,
                "covered_ratio": 0.9167,
                "missing_count": 2,
            },
        }
        with open(self.critical_gate_path, "w", encoding="utf-8") as f:
            json.dump(critical_gate, f)

        critical_regression = {
            "suite": "attack_critical_regression_gate",
            "status": "pass",
        }
        with open(self.critical_regression_path, "w", encoding="utf-8") as f:
            json.dump(critical_regression, f)

        owner_streak = {
            "suite": "attack_critical_owner_streak_gate",
            "status": "pass",
        }
        with open(self.owner_streak_path, "w", encoding="utf-8") as f:
            json.dump(owner_streak, f)

        burndown = {
            "suite": "attack_burndown_scoreboard",
            "trend": {
                "delta_uncovered": -1,
            },
        }
        with open(self.burndown_path, "w", encoding="utf-8") as f:
            json.dump(burndown, f)

    def _write_previous(self, final_score: float):
        payload = {
            "suite": "signature_ml_readiness_gate",
            "scores": {
                "final_score": final_score,
            },
        }
        with open(self.previous_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _run_gate(self, include_optional: bool, *extra_args: str):
        cmd = [
            sys.executable,
            self.script_path,
            "--manifest",
            self.manifest_path,
            "--coverage",
            self.coverage_path,
            "--output",
            self.output_path,
        ]
        if include_optional:
            cmd.extend(
                [
                    "--attack-coverage",
                    self.attack_coverage_path,
                    "--critical-gate",
                    self.critical_gate_path,
                    "--critical-regression",
                    self.critical_regression_path,
                    "--critical-owner-streak",
                    self.owner_streak_path,
                    "--burndown-scoreboard",
                    self.burndown_path,
                ]
            )
        cmd.extend(extra_args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_signature_ml_readiness_scores_strong_bundle(self):
        self._write_manifest(cve_epss_count=12000)
        self._write_coverage(strong=True)
        self._write_attack_coverage()
        self._write_critical_reports()

        result = self._run_gate(True, "--min-final-score", "88")
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")

        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass")
        self.assertIn(report.get("readiness_tier"), {"strong", "elite"})
        self.assertGreaterEqual(report.get("scores", {}).get("final_score", 0), 88)

    def test_signature_ml_readiness_shadow_alerts_on_large_drop(self):
        self._write_manifest(cve_epss_count=50)
        self._write_coverage(strong=False)
        self._write_previous(95.0)

        result = self._run_gate(
            False,
            "--previous",
            self.previous_path,
            "--min-final-score",
            "88",
            "--max-score-drop",
            "2",
        )
        self.assertEqual(result.returncode, 0, msg=f"gate failed: {result.stdout}\n{result.stderr}")

        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "shadow_alert")
        failures = report.get("failures", [])
        self.assertTrue(any("final_score below threshold" in item for item in failures))
        self.assertTrue(any("score_drop beyond threshold" in item for item in failures))

    def test_signature_ml_readiness_enforced_mode_fails(self):
        self._write_manifest(cve_epss_count=0)
        self._write_coverage(strong=False)

        result = self._run_gate(
            False,
            "--min-final-score",
            "88",
            "--fail-on-threshold",
            "1",
        )
        self.assertNotEqual(result.returncode, 0)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")


class TestSignatureMLReadinessTrendGate(unittest.TestCase):
    """Validate signature ML readiness trend gate behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.current_path = os.path.join(self.tmpdir, "signature-ml-readiness.json")
        self.previous_trend_path = os.path.join(self.tmpdir, "previous-signature-ml-readiness-trend.ndjson")
        self.output_trend_path = os.path.join(self.tmpdir, "signature-ml-readiness-trend.ndjson")
        self.output_report_path = os.path.join(self.tmpdir, "signature-ml-readiness-trend-report.json")
        self.script_path = os.path.join(PROCESSING_DIR, "signature_ml_readiness_trend_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_current(self, *, final_score: float, tier: str, signature_scale: float, source_diversity: float):
        payload = {
            "suite": "signature_ml_readiness_gate",
            "recorded_at_utc": "2026-02-15T10:00:00Z",
            "status": "pass",
            "mode": "shadow",
            "readiness_tier": tier,
            "scores": {
                "final_score": final_score,
            },
            "components": {
                "signature_scale": {"available": True, "score": signature_scale},
                "source_diversity": {"available": True, "score": source_diversity},
            },
            "warnings": [],
            "failures": [],
        }
        with open(self.current_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _write_previous_trend(self, rows: list[dict]):
        with open(self.previous_trend_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")

    def _run_gate(self, include_previous: bool, *extra_args: str):
        cmd = [
            sys.executable,
            self.script_path,
            "--current",
            self.current_path,
            "--output-trend",
            self.output_trend_path,
            "--output-report",
            self.output_report_path,
        ]
        if include_previous:
            cmd.extend(["--previous-trend", self.previous_trend_path])
        cmd.extend(extra_args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_signature_ml_trend_passes_without_baseline(self):
        self._write_current(final_score=91.5, tier="strong", signature_scale=92.0, source_diversity=88.0)

        result = self._run_gate(False)
        self.assertEqual(result.returncode, 0, msg=f"trend gate failed: {result.stdout}\n{result.stderr}")

        with open(self.output_report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass_no_baseline")
        self.assertEqual(report.get("history_status"), "no_baseline")

    def test_signature_ml_trend_shadow_alerts_on_large_score_drop(self):
        self._write_current(final_score=83.0, tier="competitive", signature_scale=84.0, source_diversity=79.0)
        self._write_previous_trend(
            [
                {
                    "recorded_at_utc": "2026-02-14T10:00:00Z",
                    "status": "pass",
                    "readiness_tier": "strong",
                    "final_score": 92.0,
                    "component_scores": {
                        "signature_scale": 93.0,
                        "source_diversity": 90.0,
                    },
                }
            ]
        )

        result = self._run_gate(
            True,
            "--max-score-drop",
            "3",
            "--max-component-drop",
            "5",
            "--fail-on-regression",
            "0",
        )
        self.assertEqual(result.returncode, 0, msg=f"trend gate failed: {result.stdout}\n{result.stderr}")

        with open(self.output_report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "shadow_alert")
        regressions = report.get("regressions", [])
        self.assertTrue(any("final_score drop too high" in item for item in regressions))
        self.assertTrue(any("component score drop too high" in item for item in regressions))

    def test_signature_ml_trend_fails_when_regression_enforced(self):
        self._write_current(final_score=80.0, tier="competitive", signature_scale=78.0, source_diversity=76.0)
        self._write_previous_trend(
            [
                {
                    "recorded_at_utc": "2026-02-14T08:00:00Z",
                    "status": "shadow_alert",
                    "readiness_tier": "strong",
                    "final_score": 90.0,
                    "component_scores": {
                        "signature_scale": 90.0,
                        "source_diversity": 88.0,
                    },
                },
                {
                    "recorded_at_utc": "2026-02-14T09:00:00Z",
                    "status": "shadow_alert",
                    "readiness_tier": "strong",
                    "final_score": 89.0,
                    "component_scores": {
                        "signature_scale": 89.0,
                        "source_diversity": 87.0,
                    },
                },
            ]
        )

        result = self._run_gate(
            True,
            "--max-score-drop",
            "2",
            "--max-component-drop",
            "4",
            "--max-consecutive-alerts",
            "2",
            "--fail-on-regression",
            "1",
        )
        self.assertNotEqual(result.returncode, 0)

        with open(self.output_report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        regressions = report.get("regressions", [])
        self.assertTrue(any("consecutive trend alerts exceeded max" in item for item in regressions))


class TestSignatureMLOfflineEvalTrendGate(unittest.TestCase):
    """Validate signature ML offline eval trend gate behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.trend_path = os.path.join(self.tmpdir, "signature-ml-offline-eval-trend.ndjson")
        self.output_path = os.path.join(self.tmpdir, "signature-ml-offline-eval-trend-report.json")
        self.script_path = os.path.join(PROCESSING_DIR, "signature_ml_offline_eval_trend_gate.py")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_trend(self, rows: list[dict]):
        with open(self.trend_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")

    def _run_gate(self, *extra_args: str):
        cmd = [
            sys.executable,
            self.script_path,
            "--trend",
            self.trend_path,
            "--output",
            self.output_path,
        ]
        cmd.extend(extra_args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_signature_ml_offline_eval_trend_passes_without_baseline(self):
        self._write_trend(
            [
                {
                    "suite": "signature_ml_offline_eval_trend",
                    "status": "pass",
                    "precision": 0.31,
                    "recall": 0.95,
                    "pr_auc": 0.72,
                    "roc_auc": 0.82,
                    "brier_score": 0.19,
                    "ece": 0.15,
                    "operating_threshold": 0.23,
                    "operating_threshold_strategy": "max_recall_with_precision_floor",
                }
            ]
        )

        result = self._run_gate("--fail-on-regression", "1")
        self.assertEqual(result.returncode, 0, msg=f"trend gate failed: {result.stdout}\n{result.stderr}")

        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "pass_no_baseline")
        self.assertEqual(report.get("history_status"), "no_baseline")

    def test_signature_ml_offline_eval_trend_shadow_alerts_on_metric_drop(self):
        self._write_trend(
            [
                {
                    "suite": "signature_ml_offline_eval_trend",
                    "status": "pass",
                    "precision": 0.30,
                    "recall": 0.92,
                    "pr_auc": 0.74,
                    "roc_auc": 0.85,
                    "brier_score": 0.18,
                    "ece": 0.13,
                    "operating_threshold": 0.22,
                    "operating_threshold_strategy": "max_recall_with_precision_floor",
                },
                {
                    "suite": "signature_ml_offline_eval_trend",
                    "status": "pass",
                    "precision": 0.26,
                    "recall": 0.84,
                    "pr_auc": 0.62,
                    "roc_auc": 0.72,
                    "brier_score": 0.27,
                    "ece": 0.25,
                    "operating_threshold": 0.55,
                    "operating_threshold_strategy": "max_recall_fallback",
                },
            ]
        )

        result = self._run_gate(
            "--max-pr-auc-drop",
            "0.05",
            "--max-roc-auc-drop",
            "0.05",
            "--max-brier-increase",
            "0.03",
            "--max-ece-increase",
            "0.05",
            "--max-threshold-drift",
            "0.20",
            "--fail-on-regression",
            "0",
        )
        self.assertEqual(result.returncode, 0, msg=f"trend gate failed: {result.stdout}\n{result.stderr}")

        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "shadow_alert")
        regressions = report.get("regressions", [])
        self.assertTrue(any("pr_auc drop too high" in item for item in regressions))
        self.assertTrue(any("ece increase too high" in item for item in regressions))

    def test_signature_ml_offline_eval_trend_fails_on_alert_streak(self):
        self._write_trend(
            [
                {
                    "suite": "signature_ml_offline_eval_trend",
                    "status": "shadow_alert",
                    "precision": 0.22,
                    "recall": 0.80,
                    "pr_auc": 0.60,
                    "roc_auc": 0.76,
                    "brier_score": 0.23,
                    "ece": 0.20,
                    "operating_threshold": 0.24,
                },
                {
                    "suite": "signature_ml_offline_eval_trend",
                    "status": "shadow_alert",
                    "precision": 0.21,
                    "recall": 0.78,
                    "pr_auc": 0.58,
                    "roc_auc": 0.74,
                    "brier_score": 0.24,
                    "ece": 0.21,
                    "operating_threshold": 0.26,
                },
                {
                    "suite": "signature_ml_offline_eval_trend",
                    "status": "fail",
                    "precision": 0.19,
                    "recall": 0.75,
                    "pr_auc": 0.54,
                    "roc_auc": 0.70,
                    "brier_score": 0.28,
                    "ece": 0.25,
                    "operating_threshold": 0.29,
                },
            ]
        )

        result = self._run_gate(
            "--max-consecutive-alerts",
            "2",
            "--fail-on-regression",
            "1",
        )
        self.assertNotEqual(result.returncode, 0)
        with open(self.output_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")
        regressions = report.get("regressions", [])
        self.assertTrue(any("consecutive offline-eval alerts exceeded max" in item for item in regressions))


class TestSignatureMLBattleReadyPipeline(unittest.TestCase):
    """Validate end-to-end battle-ready signature ML prep pipeline scripts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.bundle_dir = os.path.join(self.tmpdir, "bundle")
        os.makedirs(self.bundle_dir, exist_ok=True)

        self.manifest_path = os.path.join(self.bundle_dir, "manifest.json")
        self.coverage_path = os.path.join(self.bundle_dir, "coverage-metrics.json")
        self.readiness_path = os.path.join(self.bundle_dir, "signature-ml-readiness.json")
        self.corpus_signals = os.path.join(self.bundle_dir, "signature-ml-signals.ndjson")
        self.corpus_summary = os.path.join(self.bundle_dir, "signature-ml-training-corpus-summary.json")
        self.label_report = os.path.join(self.bundle_dir, "signature-ml-label-quality-report.json")
        self.labels_ndjson = os.path.join(self.bundle_dir, "signature-ml-labels.ndjson")
        self.feature_report = os.path.join(self.bundle_dir, "signature-ml-feature-snapshot-report.json")
        self.features_ndjson = os.path.join(self.bundle_dir, "signature-ml-features.ndjson")
        self.feature_schema = os.path.join(self.bundle_dir, "signature-ml-feature-schema.json")
        self.model_path = os.path.join(self.bundle_dir, "signature-ml-model.json")
        self.model_metadata = os.path.join(self.bundle_dir, "signature-ml-model-metadata.json")
        self.previous_eval_report = os.path.join(self.bundle_dir, "previous-signature-ml-offline-eval-report.json")
        self.previous_eval_trend = os.path.join(self.bundle_dir, "previous-signature-ml-offline-eval-trend.ndjson")
        self.offline_eval_report = os.path.join(self.bundle_dir, "signature-ml-offline-eval-report.json")
        self.offline_eval_trend = os.path.join(self.bundle_dir, "signature-ml-offline-eval-trend.ndjson")
        self.offline_eval_trend_report = os.path.join(self.bundle_dir, "signature-ml-offline-eval-trend-report.json")
        self.registry_report = os.path.join(self.bundle_dir, "signature-ml-model-registry.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _run(self, cmd: list[str]):
        return subprocess.run(cmd, capture_output=True, text=True)

    def _write_bundle_inputs(self):
        manifest = {
            "version": "2026.02.15.1234",
            "cve_epss_count": 12000,
        }
        coverage = {
            "suite": "bundle_signature_coverage_gate",
            "status": "pass",
            "thresholds": {
                "min_signature_total": 900,
                "min_database_total": 5000,
                "min_cve": 1000,
                "min_cve_kev": 50,
                "min_yara_sources": 3,
                "min_sigma_sources": 2,
            },
            "measured": {
                "signature_total": 7400,
                "database_total": 26800,
                "cve_count": 22000,
                "cve_kev_count": 320,
                "yara_source_count": 5,
                "sigma_source_count": 4,
            },
            "observed_source_rule_counts": {
                "yara": {
                    "yara-forge": 1200,
                    "elastic": 900,
                    "gcti": 600,
                    "reversinglabs": 300,
                    "bartblaze": 200,
                },
                "sigma": {
                    "rules": 220,
                    "rules-emerging-threats": 130,
                    "rules-threat-hunting": 90,
                    "mdecrevoisier": 60,
                },
            },
        }
        readiness = {
            "suite": "signature_ml_readiness_gate",
            "status": "pass",
            "mode": "shadow",
            "readiness_tier": "strong",
            "scores": {
                "final_score": 91.2,
            },
            "components": {
                "source_diversity": {"available": True, "score": 90.1},
                "attack_surface": {"available": True, "score": 88.4},
                "critical_resilience": {"available": True, "score": 86.8},
            },
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        with open(self.coverage_path, "w", encoding="utf-8") as f:
            json.dump(coverage, f)
        with open(self.readiness_path, "w", encoding="utf-8") as f:
            json.dump(readiness, f)

    def test_signature_ml_battle_ready_pipeline_passes(self):
        self._write_bundle_inputs()

        build_corpus = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_build_training_corpus.py"),
                "--manifest",
                self.manifest_path,
                "--coverage",
                self.coverage_path,
                "--readiness",
                self.readiness_path,
                "--output-signals",
                self.corpus_signals,
                "--output-summary",
                self.corpus_summary,
                "--sample-count",
                "480",
                "--window-days",
                "45",
            ]
        )
        self.assertEqual(build_corpus.returncode, 0, msg=f"build corpus failed: {build_corpus.stdout}\n{build_corpus.stderr}")

        label_gate = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_label_quality_gate.py"),
                "--signals",
                self.corpus_signals,
                "--output-report",
                self.label_report,
                "--output-labels",
                self.labels_ndjson,
                "--min-adjudicated",
                "300",
                "--min-positive",
                "60",
                "--min-negative",
                "140",
                "--min-unique-hosts",
                "70",
                "--min-unique-rules",
                "100",
                "--max-unresolved-ratio",
                "0.2",
                "--max-p95-label-latency-days",
                "6",
                "--fail-on-threshold",
                "1",
            ]
        )
        self.assertEqual(label_gate.returncode, 0, msg=f"label quality failed: {label_gate.stdout}\n{label_gate.stderr}")

        feature_gate = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_feature_snapshot_gate.py"),
                "--labels",
                self.labels_ndjson,
                "--output-features",
                self.features_ndjson,
                "--output-schema",
                self.feature_schema,
                "--output-report",
                self.feature_report,
                "--min-rows",
                "300",
                "--min-unique-hosts",
                "70",
                "--min-unique-rules",
                "100",
                "--max-missing-feature-ratio",
                "0.05",
                "--min-temporal-span-days",
                "20",
                "--fail-on-threshold",
                "1",
            ]
        )
        self.assertEqual(feature_gate.returncode, 0, msg=f"feature snapshot failed: {feature_gate.stdout}\n{feature_gate.stderr}")

        train_model = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_train_model.py"),
                "--dataset",
                self.features_ndjson,
                "--feature-schema",
                self.feature_schema,
                "--labels-report",
                self.label_report,
                "--model-version",
                "ci.signature.ml.v1",
                "--model-out",
                self.model_path,
                "--metadata-out",
                self.model_metadata,
            ]
        )
        self.assertEqual(train_model.returncode, 0, msg=f"train model failed: {train_model.stdout}\n{train_model.stderr}")

        with open(self.previous_eval_report, "w", encoding="utf-8") as f:
            json.dump({"suite": "signature_ml_offline_eval_gate", "metrics": {"pr_auc": 0.62, "roc_auc": 0.80}}, f)
        with open(self.previous_eval_trend, "w", encoding="utf-8") as f:
            f.write(json.dumps({"suite": "signature_ml_offline_eval_trend", "pr_auc": 0.62, "roc_auc": 0.80}) + "\n")

        eval_gate = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_offline_eval_gate.py"),
                "--dataset",
                self.features_ndjson,
                "--model",
                self.model_path,
                "--previous-report",
                self.previous_eval_report,
                "--previous-trend",
                self.previous_eval_trend,
                "--output-report",
                self.offline_eval_report,
                "--output-trend",
                self.offline_eval_trend,
                "--threshold",
                "0.20",
                "--auto-threshold",
                "1",
                "--min-eval-samples",
                "120",
                "--min-precision",
                "0.22",
                "--min-recall",
                "0.80",
                "--min-pr-auc",
                "0.60",
                "--min-roc-auc",
                "0.76",
                "--max-brier-score",
                "0.25",
                "--max-ece",
                "0.30",
                "--max-pr-auc-drop",
                "0.15",
                "--max-roc-auc-drop",
                "0.15",
                "--fail-on-threshold",
                "1",
                "--fail-on-regression",
                "1",
            ]
        )
        self.assertEqual(eval_gate.returncode, 0, msg=f"offline eval failed: {eval_gate.stdout}\n{eval_gate.stderr}")

        eval_trend_gate = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_offline_eval_trend_gate.py"),
                "--trend",
                self.offline_eval_trend,
                "--output",
                self.offline_eval_trend_report,
                "--max-pr-auc-drop",
                "0.15",
                "--max-roc-auc-drop",
                "0.15",
                "--max-brier-increase",
                "0.08",
                "--max-ece-increase",
                "0.10",
                "--max-threshold-drift",
                "0.25",
                "--max-consecutive-alerts",
                "3",
                "--window-size",
                "8",
                "--min-window-pass-rate",
                "0.60",
                "--fail-on-regression",
                "1",
            ]
        )
        self.assertEqual(eval_trend_gate.returncode, 0, msg=f"offline eval trend failed: {eval_trend_gate.stdout}\n{eval_trend_gate.stderr}")

        registry_gate = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_model_registry_gate.py"),
                "--model-artifact",
                self.model_path,
                "--metadata",
                self.model_metadata,
                "--offline-eval",
                self.offline_eval_report,
                "--offline-eval-trend-report",
                self.offline_eval_trend_report,
                "--feature-schema",
                self.feature_schema,
                "--labels-report",
                self.label_report,
                "--output",
                self.registry_report,
                "--min-pr-auc",
                "0.60",
                "--min-roc-auc",
                "0.76",
                "--require-signed-model",
                "0",
                "--verify-signature",
                "0",
                "--require-offline-eval-trend-pass",
                "1",
                "--fail-on-threshold",
                "1",
            ]
        )
        self.assertEqual(registry_gate.returncode, 0, msg=f"model registry failed: {registry_gate.stdout}\n{registry_gate.stderr}")

        with open(self.registry_report, "r", encoding="utf-8") as f:
            registry = json.load(f)
        self.assertEqual(registry.get("status"), "pass")

    def test_signature_ml_label_quality_enforced_fails_with_sparse_labels(self):
        with open(self.corpus_signals, "w", encoding="utf-8") as f:
            f.write(json.dumps({"sample_id": "x1", "observed_at_utc": "2026-02-15T00:00:00Z", "label": None}) + "\n")
            f.write(json.dumps({"sample_id": "x2", "observed_at_utc": "2026-02-15T01:00:00Z", "label": 1}) + "\n")

        result = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_label_quality_gate.py"),
                "--signals",
                self.corpus_signals,
                "--output-report",
                self.label_report,
                "--min-adjudicated",
                "10",
                "--min-positive",
                "5",
                "--min-negative",
                "5",
                "--fail-on-threshold",
                "1",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        with open(self.label_report, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")

    def test_signature_ml_offline_eval_enforced_fails_on_degraded_scores(self):
        with open(self.features_ndjson, "w", encoding="utf-8") as f:
            for idx in range(120):
                label = 1 if idx % 2 == 0 else 0
                row = {
                    "sample_id": f"s-{idx:03d}",
                    "observed_at_utc": f"2026-02-15T{idx % 24:02d}:00:00Z",
                    "host_id": f"h-{idx % 20}",
                    "rule_id": f"r-{idx % 30}",
                    "label": label,
                    "model_score": 0.5,
                    "rule_severity": 3,
                    "signature_total": 1000,
                    "database_total": 5000,
                    "source_diversity_score": 60,
                    "attack_surface_score": 60,
                    "critical_resilience_score": 60,
                }
                f.write(json.dumps(row) + "\n")

        result = self._run(
            [
                sys.executable,
                os.path.join(PROCESSING_DIR, "signature_ml_offline_eval_gate.py"),
                "--dataset",
                self.features_ndjson,
                "--output-report",
                self.offline_eval_report,
                "--min-eval-samples",
                "60",
                "--min-precision",
                "0.9",
                "--min-recall",
                "0.9",
                "--min-pr-auc",
                "0.9",
                "--min-roc-auc",
                "0.9",
                "--fail-on-threshold",
                "1",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        with open(self.offline_eval_report, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report.get("status"), "fail")


class TestProcessingScripts(unittest.TestCase):
    """Smoke tests for processing scripts (import check)."""

    SCRIPTS = [
        "sigma_filter", "yara_validate", "ioc_dedup",
        "ioc_allowlist", "cve_extract", "build_bundle", "bundle_coverage_gate",
        "coverage_regression_gate", "attack_coverage_gate", "attack_regression_gate",
        "attack_gap_burndown_gate", "attack_critical_technique_gate",
        "attack_critical_regression_gate", "attack_critical_owner_streak_gate",
        "attack_burndown_scoreboard", "update_attack_critical_regression_history",
        "signature_ml_build_training_corpus",
        "signature_ml_label_quality_gate",
        "signature_ml_feature_snapshot_gate",
        "signature_ml_train_model",
        "signature_ml_offline_eval_gate",
        "signature_ml_offline_eval_trend_gate",
        "signature_ml_model_registry_gate",
        "signature_ml_readiness_gate",
        "signature_ml_readiness_trend_gate",
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
