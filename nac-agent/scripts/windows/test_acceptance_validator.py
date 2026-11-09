import copy
import json
import pathlib
import re
import unittest

from acceptance_validator import CHECKS, validate

ROOT = pathlib.Path(__file__).resolve().parent


def fixtures():
    manifest = json.loads((ROOT / 'acceptance-manifest.json').read_text())
    cases = json.loads((ROOT / 'acceptance-cases.json').read_text())
    report = {
        'schema_version': 1, 'preflight': {'status': 'FAIL', 'checks': [
            {'id': name, 'status': 'FAIL', 'evidence': []} for name in CHECKS]},
        'runtime_acceptance': [{'id': c['id'], 'status': 'NOT RUN', 'evidence': []}
                               for c in cases['cases']],
    }
    return manifest, cases, report


class PowerShellSourceContractTests(unittest.TestCase):
    """Source contract only: Python regex emulates the shared ASCII component grammar.

    This does NOT run PowerShell, inspect filesystem reparse points, or verify a VM.
    """

    def test_powershell_artifact_path_parity_source_contract(self):
        source = (ROOT / 'invoke-acceptance-preflight.ps1').read_text()
        match = re.search(r"\$artifactComponentPattern = '([^']+)'", source)
        self.assertIsNotNone(match, 'PowerShell component grammar absent')
        self.assertIn('$part -cnotmatch $artifactComponentPattern', source)
        self.assertIn("$relative -cmatch '^dist/'", source)
        self.assertIn("$part.Split('.')[0].ToUpperInvariant()", source)
        pattern = re.compile(match.group(1))
        reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {
            prefix + str(n) for prefix in ('COM', 'LPT') for n in range(1, 10)}
        for path in ('dist/agent.exe', 'dist/sub-dir/agent_1.exe',
                     'dist/', 'dist/../agent.exe', 'dist/./agent.exe',
                     'dist//agent.exe', 'dist/agent.exe:stream',
                     'dist/..\\agent.exe', 'dist/agent.exe ',
                     'dist/agent.exe.', 'dist/NUL.exe', 'dist/CON/file.exe'):
            with self.subTest(path=path):
                m, c, r = fixtures()
                m['artifacts'][0]['path'] = path
                try:
                    validate(m, c, r)
                    python_accepts = True
                except ValueError:
                    python_accepts = False
                parts = path.split('/')[1:]
                ps_contract_accepts = (path.startswith('dist/') and bool(parts) and
                    all(pattern.fullmatch(p) and p not in ('.', '..') and
                        not p.endswith('.') and p.split('.')[0].upper() not in reserved
                        for p in parts))
                self.assertEqual(python_accepts, ps_contract_accepts)

    def test_os_classification_source_contract(self):
        source = (ROOT / 'invoke-acceptance-preflight.ps1').read_text()
        self.assertIn("'WINDOWS10_OBSERVED_NOT_MVP'", source)
        self.assertIn("'WINDOWS11_CANDIDATE'", source)
        self.assertIn('$osInfo.ProductType -eq 1', source)
        self.assertIn('os_acceptance = $osClass', source)


class ValidatorTests(unittest.TestCase):
    def test_default_report_valid_but_not_runtime_success(self):
        validate(*fixtures())

    def test_pass_requires_evidence(self):
        m, c, r = fixtures()
        r['runtime_acceptance'][0]['status'] = 'PASS'
        with self.assertRaises(ValueError):
            validate(m, c, r)
        r['runtime_acceptance'][0]['evidence'] = [{'kind': 'vm-log', 'reference': 'local-log'}]
        validate(m, c, r)
        r['runtime_acceptance'][0]['evidence'] = ['unstructured claim']
        with self.assertRaises(ValueError):
            validate(m, c, r)

    def test_windows10_classification_cannot_pass_platform(self):
        m, c, r = fixtures()
        r['os_acceptance'] = 'WINDOWS10_OBSERVED_NOT_MVP'
        validate(m, c, r)
        r['preflight']['checks'][0]['status'] = 'PASS'
        r['preflight']['checks'][0]['evidence'] = [{'kind': 'observation', 'reference': 'Win10'}]
        with self.assertRaises(ValueError):
            validate(m, c, r)

    def test_preflight_pass_requires_check_evidence(self):
        m, c, r = fixtures()
        r['preflight']['status'] = 'PASS'
        for check in r['preflight']['checks']:
            check['status'] = 'PASS'
        with self.assertRaises(ValueError):
            validate(m, c, r)

    def test_unknown_and_missing_cases(self):
        m, c, r = fixtures()
        r['runtime_acceptance'][0]['id'] = 'invented'
        with self.assertRaises(ValueError):
            validate(m, c, r)
        r['runtime_acceptance'].pop(0)
        with self.assertRaises(ValueError):
            validate(m, c, r)

    def test_unsupported_schema(self):
        for index in range(3):
            items = list(fixtures())
            items[index]['schema_version'] = 999
            with self.assertRaises(ValueError):
                validate(*items)

    def test_rejects_unsafe_windows_artifact_paths(self):
        for path in ('dist/', 'dist/../agent.exe', 'dist/./agent.exe',
                     'dist//agent.exe', 'dist/agent.exe:stream',
                     'dist/..\\agent.exe', 'dist/agent.exe ',
                     'dist/agent.exe.', 'dist/NUL.exe', 'dist/CON/file.exe'):
            with self.subTest(path=path):
                m, c, r = fixtures()
                m['artifacts'][0]['path'] = path
                with self.assertRaises(ValueError):
                    validate(m, c, r)

    def test_bad_checksum(self):
        m, c, r = fixtures()
        m['artifacts'][0]['sha256'] = 'not-a-digest'
        with self.assertRaises(ValueError):
            validate(m, c, r)
        m, c, r = fixtures()
        m['artifacts'][0]['sha256'] = 'A' * 64
        with self.assertRaises(ValueError):
            validate(m, c, r)

    def test_preflight_cannot_mask_runtime_and_no_false_pass(self):
        m, c, r = fixtures()
        r['preflight']['status'] = 'PASS'
        for check in r['preflight']['checks']:
            check['status'] = 'PASS'
            check['evidence'] = [{'kind': 'observation', 'reference': 'VM observation'}]
        validate(m, c, r)
        r['runtime_acceptance'][0]['status'] = 'PASS'
        with self.assertRaises(ValueError):
            validate(m, c, r)


if __name__ == '__main__':
    unittest.main()
