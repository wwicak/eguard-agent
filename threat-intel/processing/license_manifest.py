#!/usr/bin/env python3
"""Generate LICENSES/ manifest files for an eGuard threat-intel bundle."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCES = REPO_ROOT / "threat-intel" / "licensing" / "sources.json"

MIT_TEXT = """MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

APACHE_20_TEXT = """Apache License 2.0

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
"""

DRL_11_TEXT = """Detection Rule License 1.1

Detection rules may be used, copied, modified, merged, published, distributed,
and sublicensed, including for commercial purposes, provided that copyright,
author, license, and reference metadata supplied with the rules are retained.
The rules are provided "as is", without warranty. See the upstream Detection
Rule License 1.1 text for the complete terms.
"""

LICENSE_TEXT_BY_SPDX = {
    "MIT": MIT_TEXT,
    "Apache-2.0": APACHE_20_TEXT,
    "DRL-1.1": DRL_11_TEXT,
}


def load_sources(path: Path = DEFAULT_SOURCES) -> dict[str, dict]:
    entries = json.loads(path.read_text(encoding="utf-8"))
    return {str(entry["id"]): entry for entry in entries}


def source_ids_from_manifest(manifest: dict) -> list[str]:
    ids: list[str] = []
    sources = manifest.get("sources", {}) if isinstance(manifest.get("sources"), dict) else {}

    for source in sources.get("sigma", []) or []:
        ids.append(f"sigma:{source}")
    for source in sources.get("yara", []) or []:
        ids.append(f"yara:{source}")
    for source in sources.get("ioc", []) or []:
        ids.append(str(source))
    for source in sources.get("cve", []) or []:
        ids.append(str(source))
    for source in sources.get("ja3", []) or []:
        ids.append(str(source))
    for source in sources.get("supplemental_ioc", []) or []:
        ids.append(str(source))

    if int(manifest.get("suricata_count", 0) or 0) > 0:
        ids.append("suricata:et_open")
    if int(manifest.get("elastic_count", 0) or 0) > 0:
        ids.append("elastic:detection-rules")

    restricted = manifest.get("restricted_sources", {})
    if isinstance(restricted, dict):
        for item in restricted.values():
            if isinstance(item, dict) and item.get("source_id"):
                ids.append(str(item["source_id"]))

    return sorted(dict.fromkeys(ids))


def write_license_manifest(bundle_dir: str | Path, manifest: dict, sources_path: str | Path = DEFAULT_SOURCES) -> None:
    bundle = Path(bundle_dir)
    out_dir = bundle / "LICENSES"
    out_dir.mkdir(parents=True, exist_ok=True)

    source_table = load_sources(Path(sources_path))
    source_ids = source_ids_from_manifest(manifest)
    missing = [source_id for source_id in source_ids if source_id not in source_table]
    if missing:
        raise SystemExit("license manifest missing source entries: " + ", ".join(missing))

    entries = [source_table[source_id] for source_id in source_ids]
    spdx_ids = sorted({entry.get("spdx", "") for entry in entries if entry.get("spdx") in LICENSE_TEXT_BY_SPDX})
    license_texts = {spdx_id: LICENSE_TEXT_BY_SPDX[spdx_id] for spdx_id in spdx_ids}

    doc = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bundle_version": manifest.get("version", ""),
        "sources": entries,
        "license_texts": license_texts,
    }
    (out_dir / "manifest.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    notice_lines = [
        "eGuard Threat-Intel Bundle Notices",
        "====================================",
        "",
        "This bundle contains third-party threat intelligence and detection content.",
        "",
    ]
    for entry in entries:
        notice_lines.extend([
            f"Source: {entry['name']}",
            f"URL: {entry['url']}",
            f"License/SPDX: {entry.get('license', '')} / {entry.get('spdx', 'NOASSERTION')}",
            f"Redistribution status: {entry.get('redistribution', '')}",
            f"Attribution: {entry.get('attribution', '')}",
            f"Evidence: {entry.get('evidence_url', '')}",
            "",
        ])
    if license_texts:
        notice_lines.append("Included license texts")
        notice_lines.append("----------------------")
        for spdx_id, text in license_texts.items():
            notice_lines.extend([f"[{spdx_id}]", text.strip(), ""])
    (out_dir / "NOTICE.txt").write_text("\n".join(notice_lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate eGuard bundle LICENSES manifest")
    parser.add_argument("--bundle", help="Bundle staging directory")
    parser.add_argument("--manifest", help="Bundle manifest JSON path")
    parser.add_argument("--sources", default=str(DEFAULT_SOURCES), help="Source licensing JSON table")
    args = parser.parse_args()

    if not args.bundle or not args.manifest:
        parser.print_help()
        return 0

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    write_license_manifest(args.bundle, manifest, args.sources)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
