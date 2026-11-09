#!/usr/bin/env python3
"""Build the NAC Unix download contract; fail if any required asset is missing."""
import hashlib
import json
from pathlib import Path
import sys

version, root = sys.argv[1], Path(sys.argv[2])
assets = {
    'deb_amd64': f'eguard-nac-agent_{version}_amd64.deb',
    'deb_arm64': f'eguard-nac-agent_{version}_arm64.deb',
    'rpm_x86_64': f'eguard-nac-agent-{version}-1.x86_64.rpm',
    'rpm_aarch64': f'eguard-nac-agent-{version}-1.aarch64.rpm',
    'pkg': f'eGuard-NAC-{version}.pkg',
}
checksums = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
             for name in assets.values()}
(root / 'eguard-nac-agent-release.json').write_text(json.dumps({
    'schema_version': 1, 'agent_version': version,
    'release_tag': f'nac-v{version}', 'assets': assets,
    'checksums': checksums,
}, indent=2) + '\n')
