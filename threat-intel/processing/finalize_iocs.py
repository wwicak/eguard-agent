#!/usr/bin/env python3
"""Re-deduplicate and apply safety/allowlists AFTER supplemental feed merges."""
import argparse
import shutil
import tempfile
from pathlib import Path

from ioc_allowlist import filter_iocs, filter_ip_iocs, load_allowlist, load_ip_allowlist
from ioc_dedup import deduplicate, parse_ioc_file, write_output


def finalize(input_dir: Path, output_dir: Path, allowlists: Path) -> dict[str, tuple[int, int]]:
    if input_dir.resolve() == output_dir.resolve():
        raise ValueError("final IOC output must differ from its input")
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    with tempfile.TemporaryDirectory(dir=output_dir) as scratch:
        for kind, allowlist_file in [("hashes", "known_good_hashes.txt"), ("domains", "known_good_domains.txt"), ("ips", "known_good_ips.txt")]:
            source = input_dir / f"{kind}.txt"
            if not source.is_file():
                raise ValueError(f"missing final IOC input: {kind}")
            rows = deduplicate(parse_ioc_file(str(source), preserve_provenance=True), kind)
            temporary = str(Path(scratch) / f"{kind}.jsonl")
            write_output(rows, temporary)
            output = str(output_dir / f"{kind}.txt")
            if kind == "ips":
                ips, networks = load_ip_allowlist(str(allowlists / allowlist_file))
                counts[kind] = filter_ip_iocs(temporary, output, ips, networks)
            else:
                counts[kind] = filter_iocs(temporary, output, load_allowlist(str(allowlists / allowlist_file)))
    behavior = input_dir / "ioc_behavior_rules.json"
    if behavior.is_file():
        shutil.copy2(behavior, output_dir / behavior.name)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allowlists", required=True, type=Path)
    args = parser.parse_args()
    print(finalize(args.input, args.output, args.allowlists))


if __name__ == "__main__":
    main()
