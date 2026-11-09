"""Offline schema/status validator; never evidence of Windows execution."""
import argparse
import json
import pathlib
import re
import sys


CHECKS = ('platform', 'elevation', 'operator_gate', 'artifacts', 'authenticode')
STATUSES = ('PASS', 'FAIL', 'NOT RUN')


def _version(obj):
    if not isinstance(obj, dict) or type(obj.get('schema_version')) is not int or obj['schema_version'] != 1:
        raise ValueError('unsupported schema_version')


def _evidence(items):
    if not isinstance(items, list):
        raise ValueError('evidence must be an array')
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get('kind'), str)
                or not item['kind'].strip() or not isinstance(item.get('reference'), str)
                or not item['reference'].strip()):
            raise ValueError('invalid evidence')


def _status(item):
    if not isinstance(item, dict) or item.get('status') not in STATUSES:
        raise ValueError('invalid status')
    _evidence(item.get('evidence'))
    if item['status'] == 'PASS' and not item['evidence']:
        raise ValueError('PASS without evidence')


def validate(manifest, cases, report):
    for obj in (manifest, cases, report):
        _version(obj)
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError('missing artifacts')
    paths = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError('invalid artifact')
        path = artifact.get('path')
        if (not isinstance(path, str) or not path.startswith('dist/') or
                '..' in pathlib.PurePosixPath(path).parts or path in paths):
            raise ValueError('invalid artifact path')
        parts = path.split('/')[1:]
        reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {
            prefix + str(n) for prefix in ('COM', 'LPT') for n in range(1, 10)}
        if any(not re.fullmatch(r'[A-Za-z0-9._-]+', part)
               or part in ('.', '..') or part.endswith('.')
               or part.split('.')[0].upper() in reserved for part in parts):
            raise ValueError('unsafe Windows artifact path')
        paths.add(path)
        if not isinstance(artifact.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']):
            raise ValueError('malformed checksum')
        if artifact.get('signature_class') not in ('TEST-UNSIGNED', 'SIGNED'):
            raise ValueError('invalid signature class')
    definitions = cases.get('cases')
    if not isinstance(definitions, list) or not definitions:
        raise ValueError('missing case definitions')
    required = {'clean_install', 'upgrade_rollback', 'temporary_on', 'temporary_off',
                'permanent_on', 'permanent_off', 'expiry_offline_reboot_clock',
                'standard_user_tamper', 'authorized_uninstall', 'cleanup', 'coexist_edr'}
    ids = [d.get('id') for d in definitions if isinstance(d, dict)]
    if len(ids) != len(definitions) or len(ids) != len(set(ids)) or set(ids) != required:
        raise ValueError('unknown or missing required case definitions')
    pre = report.get('preflight')
    if not isinstance(pre, dict) or pre.get('status') not in ('PASS', 'FAIL'):
        raise ValueError('invalid preflight')
    checks = pre.get('checks')
    if not isinstance(checks, list) or len(checks) != len(CHECKS) or [x.get('id') for x in checks if isinstance(x, dict)] != list(CHECKS):
        raise ValueError('missing/unknown preflight checks')
    for item in checks:
        _status(item)
    os_class = report.get('os_acceptance')
    if os_class is not None:
        if os_class not in ('WINDOWS11_CANDIDATE', 'WINDOWS10_OBSERVED_NOT_MVP', 'UNSUPPORTED_OR_UNKNOWN'):
            raise ValueError('invalid OS acceptance classification')
        if os_class != 'WINDOWS11_CANDIDATE' and checks[0]['status'] != 'FAIL':
            raise ValueError('non-MVP platform cannot PASS')
    if pre['status'] == 'PASS' and any(x['status'] != 'PASS' for x in checks):
        raise ValueError('preflight PASS with non-PASS checks')
    if pre['status'] == 'FAIL' and all(x['status'] == 'PASS' for x in checks):
        raise ValueError('preflight FAIL without failed check')
    runtime = report.get('runtime_acceptance')
    if not isinstance(runtime, list) or len(runtime) != len(ids) or [x.get('id') for x in runtime if isinstance(x, dict)] != ids:
        raise ValueError('unknown/missing/duplicate runtime cases')
    for item in runtime:
        _status(item)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=pathlib.Path)
    parser.add_argument('cases', type=pathlib.Path)
    parser.add_argument('report', type=pathlib.Path)
    args = parser.parse_args()
    try:
        validate(*(json.loads(p.read_text(encoding='utf-8')) for p in (args.manifest, args.cases, args.report)))
    except (ValueError, OSError) as exc:
        print('INVALID:', exc, file=sys.stderr)
        return 1
    print('VALID SCHEMA ONLY; Windows execution NOT VERIFIED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
