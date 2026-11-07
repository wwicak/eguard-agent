#!/usr/bin/env python3
"""List local OS binaries/scripts without following links; never executes them."""
import argparse
import json
import os
from pathlib import Path
import stat

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--metrics", required=True, type=Path)
args = parser.parse_args()
windows = os.name == "nt"
roots = [Path(os.environ.get("SystemRoot", "C:/Windows")) / name for name in ["System32", "SysWOW64"]] if windows else [Path(path) for path in ["/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu", "/usr/lib/python3.11"]]
quota = 500 if windows else 250
files = []
seen = set()
counts = {}
kinds = {"executable": 0, "other": 0}
skipped = 0
magic = {bytes.fromhex(value) for value in ["feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca"]}
def linked(path):
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()
for root in roots:
    count = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not linked(Path(directory, name)))
        for name in sorted(names):
            path = Path(directory, name)
            try:
                if linked(path):
                    continue
                info = path.lstat()
                identity = (info.st_dev, info.st_ino)
                if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or identity in seen:
                    continue
                with path.open("rb") as stream:
                    header = stream.read(4)
                executable = header.startswith((b"MZ", b"\x7fELF")) or header in magic
                if info.st_size > (16 if executable else 1) * 1024 * 1024:
                    continue
            except OSError:
                skipped += 1
                continue
            seen.add(identity)
            files.append(str(path))
            kinds["executable" if executable else "other"] += 1
            count += 1
            if count >= quota:
                break
        if count >= quota:
            break
    counts[str(root)] = count
if len(files) < 500:
    raise SystemExit(f"only {len(files)} eligible benign files; require >=500")
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text("\n".join(files) + "\n")
report = {"files": len(files), "roots": counts, "kinds": kinds, "unreadable_skipped": skipped}
args.metrics.parent.mkdir(parents=True, exist_ok=True)
args.metrics.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
