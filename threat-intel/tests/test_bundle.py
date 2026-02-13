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


class TestProcessingScripts(unittest.TestCase):
    """Smoke tests for processing scripts (import check)."""

    SCRIPTS = [
        "sigma_filter", "yara_validate", "ioc_dedup",
        "ioc_allowlist", "cve_extract", "build_bundle",
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

    def test_two_tier3_is_medium(self):
        """Two Tier 3 sources should yield medium confidence."""
        self._write_ioc("ips", "cins", ["8.8.8.1"])
        self._write_ioc("ips", "blocklist_de", ["8.8.8.1"])
        self._run_dedup()
        ips = self._read_output("ips")
        ip = next(i for i in ips if i["value"] == "8.8.8.1")
        self.assertEqual(ip["confidence"], "medium")


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
