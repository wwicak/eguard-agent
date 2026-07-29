#!/usr/bin/env python3
"""Build a deterministic, unsigned DLP bundle directory.

Signing and archive publishing remain a later CI task; this builder only creates
manifest metadata and hashes so the bundle format can be tested first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not args.version or any(part == "" for part in args.version.split(".")):
        print("version is required", file=sys.stderr)
        return 2

    source = ROOT / "dlp"
    output = args.output.resolve()
    if output == source.resolve() or source.resolve() in output.parents:
        print("output must not be inside dlp source", file=sys.stderr)
        return 2

    if output.exists():
        shutil.rmtree(output)
    (output / "rules").mkdir(parents=True)
    (output / "fixtures").mkdir()

    files = [
        (source / "schema.json", output / "schema.json"),
        (source / "rules/indonesia.json", output / "rules/indonesia.json"),
        (source / "fixtures/indonesia.json", output / "fixtures/indonesia.json"),
    ]
    manifest_files = {}
    for source_path, target_path in files:
        shutil.copyfile(source_path, target_path)
        manifest_files[str(target_path.relative_to(output)).replace("\\", "/")] = f"sha256:{sha256(target_path)}"

    manifest = {
        "bundle_type": "eguard-dlp-rules",
        "schema_version": "1",
        "version": args.version,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "pack_ids": ["indonesia"],
        "signed": False,
        "files": manifest_files,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"DLP bundle built: {output} ({len(manifest_files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
