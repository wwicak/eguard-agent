#!/usr/bin/env python3
"""Tests for eGuard threat intel bundle structure and GPG signature."""

import hashlib
import json
import os
import subprocess
import sys
import unittest

# Allow running from repo root or from tests/ dir
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
            "cve_count", "files",
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
                     "ioc_domain_count", "ioc_ip_count", "cve_count"):
            self.assertGreaterEqual(manifest.get(key, 0), 0, f"{key} must be >= 0")


class TestGPGSignature(unittest.TestCase):
    """Validate GPG signature on manifest."""

    BUNDLE_DIR = os.environ.get("BUNDLE_DIR", os.path.join(REPO_ROOT, "bundle"))

    def setUp(self):
        manifest = os.path.join(self.BUNDLE_DIR, "manifest.json")
        sig = os.path.join(self.BUNDLE_DIR, "manifest.json.asc")
        if not os.path.isfile(manifest) or not os.path.isfile(sig):
            self.skipTest("Bundle or signature not found")

    def test_gpg_verify(self):
        """GPG signature must verify against manifest."""
        result = subprocess.run(
            ["gpg", "--verify",
             os.path.join(self.BUNDLE_DIR, "manifest.json.asc"),
             os.path.join(self.BUNDLE_DIR, "manifest.json")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0,
                         f"GPG verification failed:\n{result.stderr}")


class TestProcessingScripts(unittest.TestCase):
    """Smoke tests for processing scripts (import check)."""

    def test_sigma_filter_importable(self):
        result = subprocess.run(
            [sys.executable, "-c",
             "import importlib.util; spec = importlib.util.spec_from_file_location('sigma_filter', "
             f"'{os.path.join(REPO_ROOT, 'threat-intel/processing/sigma_filter.py')}'); "
             "mod = importlib.util.module_from_spec(spec)"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"sigma_filter.py import failed: {result.stderr}")

    def test_build_bundle_importable(self):
        result = subprocess.run(
            [sys.executable, "-c",
             "import importlib.util; spec = importlib.util.spec_from_file_location('build_bundle', "
             f"'{os.path.join(REPO_ROOT, 'threat-intel/processing/build_bundle.py')}'); "
             "mod = importlib.util.module_from_spec(spec)"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"build_bundle.py import failed: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
