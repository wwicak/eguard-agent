#!/usr/bin/env python3
"""Reproduce the reviewed v1 YARA pack from exact, permissively licensed originals."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "threat-intel/yara-v1.json"


def collect(output: Path, manifest: dict, fetch=None):
    fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=60).read())
    expected = set()
    originals = {}
    staged = {}
    for rule in manifest["rules"]:
        repositories = {"mandiant": "mandiant/red_team_tool_countermeasures", "withsecure": "WithSecureLabs/iocs"}
        if (rule["license"] != "BSD-2-Clause" or not re.fullmatch(r"[0-9a-f]{40}", rule["commit"])
                or repositories.get(rule["source"]) != rule["repository"]):
            raise ValueError("unapproved rule license, repository or source pin")
        url = f'https://raw.githubusercontent.com/{rule["repository"]}/{rule["commit"]}/{rule["path"]}'
        raw = originals.setdefault(url, b"") or fetch(url)
        originals[url] = raw
        if hashlib.sha256(raw).hexdigest() != rule["source_sha256"]:
            raise ValueError(f'source hash changed: {rule["id"]}')
        lines = raw.decode("utf-8").splitlines()
        snippet = "\n".join(lines[rule["first_line"] - 1:rule["last_line"]])
        names = re.findall(r"\brule\s+(\w+)", snippet)
        if names != [rule["id"]] or rule["id"] in expected:
            raise ValueError("rule id/count differs from approved manifest")
        if re.search(r"\bscore\s*=", snippet):
            raise ValueError("upstream score must be explicitly reviewed")
        snippet, count = re.subn(r"\bmeta\s*:", f'meta:\n        score = {rule["score"]}', snippet, count=1)
        if count != 1 or not 70 <= rule["score"] <= 100:
            raise ValueError("invalid curated score/meta")
        header = []
        for line in lines:
            if re.match(r"\s*(?:import|rule|private|global)\b", line):
                break
            header.append(line)
        content = "\n".join(header) + '\nimport "pe"\n' + snippet + "\n"
        if hashlib.sha256(content.encode()).hexdigest() != rule["rule_sha256"]:
            raise ValueError(f'curated rule hash changed: {rule["id"]}')
        relative = Path(rule["source"]) / (rule["id"] + ".yar")
        staged[relative] = content
        expected.add(rule["id"])
    if len(expected) != 9:
        raise ValueError(f"v1 pack must have exactly9 community rules, got{len(expected)}")
    # Validate every input before touching the output; stale rule files cannot survive.
    output.mkdir(parents=True, exist_ok=True)
    for path in list(output.rglob("*.yar")) + list(output.rglob("*.yara")):
        if path.name != "default.yar" and path.relative_to(output) not in staged:
            raise ValueError(f"unexpected pre-existing rule: {path}")
    for relative, content in staged.items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    if output.resolve() != (ROOT / "rules/yara").resolve():
        shutil.copyfile(ROOT / "rules/yara/default.yar", output / "default.yar")
        shutil.copyfile(ROOT / "rules/yara/THIRD-PARTY-NOTICES.txt", output / "THIRD-PARTY-NOTICES.txt")
    (output / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"YARA v1:9 community rules +EICAR,2 sources,all original BSD-2-Clause notices retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    collect(args.output, json.loads(MANIFEST.read_text()))


if __name__ == "__main__":
    main()
