"""Synthetic-only qualification of the pinned, licensed YARA collector."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("yara_curate", Path(__file__).parents[1] / "processing/yara_curate.py")
curator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(curator)


def fixture():
    rules = []
    bodies = {}
    for index in range(9):
        name = f"fixture_{index}"
        raw = f'// Copyright 2026 Synthetic\nrule {name} {{\nmeta: author = "fixture"\ncondition: true\n}}\n'.encode()
        path = name + ".yar"
        bodies[path] = raw
        snippet = "\n".join(raw.decode().splitlines()[1:5]).replace("meta:", "meta:\n        score = 75", 1)
        curated = '// Copyright 2026 Synthetic\nimport "pe"\n' + snippet + "\n"
        rules.append({"rule_sha256": hashlib.sha256(curated.encode()).hexdigest(), "id": name, "source": "mandiant" if index < 3 else "withsecure", "repository": "mandiant/red_team_tool_countermeasures" if index < 3 else "WithSecureLabs/iocs", "commit": "1" * 40, "path": path, "source_sha256": hashlib.sha256(raw).hexdigest(), "first_line": 2, "last_line": 5, "score": 75, "license": "BSD-2-Clause"})
    return {"version": 1, "rules": rules}, lambda url: bodies[url.rsplit("/", 1)[1]]


class CuratedYaraTests(unittest.TestCase):
    def test_exact_count_pins_notices_and_score(self):
        manifest, fetch = fixture()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "pack"
            curator.collect(output, manifest, fetch)
            self.assertEqual(len(list(output.rglob("*.yar"))), 10)
            self.assertTrue((output / "THIRD-PARTY-NOTICES.txt").is_file())
            self.assertTrue((output / "provenance.json").is_file())
            text = (output / "mandiant/fixture_0.yar").read_text()
            self.assertIn("Copyright 2026 Synthetic", text)
            self.assertIn("score = 75", text)

    def test_hash_change_is_loud_and_transactional(self):
        manifest, fetch = fixture()
        manifest["rules"][-1]["source_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "pack"
            with self.assertRaisesRegex(ValueError, "source hash changed"):
                curator.collect(output, manifest, fetch)
            self.assertFalse(output.exists())

    def test_noncommercial_and_missing_license_are_rejected(self):
        for license_name in ["CC-BY-NC-4.0", "N/A", ""]:
            manifest, fetch = fixture()
            manifest["rules"][0]["license"] = license_name
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "unapproved rule license"):
                    curator.collect(Path(directory), manifest, fetch)

    def test_missing_rule_count_and_unexpected_old_rules_fail(self):
        manifest, fetch = fixture()
        manifest["rules"].pop()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "exactly9"):
                curator.collect(Path(directory), manifest, fetch)
        manifest, fetch = fixture()
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "unexpected.yar").write_text("rule unexpected { condition: true }")
            with self.assertRaisesRegex(ValueError, "unexpected pre-existing"):
                curator.collect(Path(directory), manifest, fetch)


if __name__ == "__main__":
    unittest.main()
