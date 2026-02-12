#!/usr/bin/env python3
"""Assemble threat intel bundle directory with manifest for eGuard."""

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_tree(src: str, dst: str) -> int:
    """Copy directory tree, return count of files copied."""
    count = 0
    if not os.path.isdir(src):
        return count
    for root, _dirs, files in os.walk(src):
        for fname in files:
            src_path = os.path.join(root, fname)
            rel = os.path.relpath(src_path, src)
            dst_path = os.path.join(dst, rel)
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            shutil.copy2(src_path, dst_path)
            count += 1
    return count


def copy_file(src: str, dst: str) -> bool:
    """Copy a single file if it exists."""
    if not os.path.isfile(src):
        return False
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    return True


def count_lines(path: str) -> int:
    """Count non-empty lines in a file."""
    if not os.path.isfile(path):
        return 0
    with open(path, "r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def main():
    parser = argparse.ArgumentParser(description="Build eGuard threat intel bundle")
    parser.add_argument("--sigma", default="", help="Directory of filtered SIGMA rules")
    parser.add_argument("--yara", default="", help="Directory of validated YARA rules")
    parser.add_argument("--ioc", default="", help="Directory of filtered IOC files")
    parser.add_argument("--cve", default="", help="Path to CVE JSONL file")
    parser.add_argument("--output", required=True, help="Output bundle directory")
    parser.add_argument("--version", default="", help="Bundle version (default: date-based)")
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output)
    version = args.version or datetime.now(timezone.utc).strftime("%Y.%m.%d")

    # Clean and create output directory
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    # Copy SIGMA rules
    sigma_count = 0
    if args.sigma:
        sigma_count = copy_tree(args.sigma, os.path.join(output_dir, "sigma"))
    print(f"Bundle: {sigma_count} SIGMA rules")

    # Copy YARA rules
    yara_count = 0
    if args.yara:
        yara_count = copy_tree(args.yara, os.path.join(output_dir, "yara"))
    print(f"Bundle: {yara_count} YARA rules")

    # Copy IOC files
    ioc_hash_count = 0
    ioc_domain_count = 0
    ioc_ip_count = 0
    if args.ioc:
        ioc_dir = os.path.abspath(args.ioc)
        for ioc_file in ("hashes.txt", "domains.txt", "ips.txt"):
            src = os.path.join(ioc_dir, ioc_file)
            if copy_file(src, os.path.join(output_dir, "ioc", ioc_file)):
                count = count_lines(os.path.join(output_dir, "ioc", ioc_file))
                if "hashes" in ioc_file:
                    ioc_hash_count = count
                elif "domains" in ioc_file:
                    ioc_domain_count = count
                elif "ips" in ioc_file:
                    ioc_ip_count = count
    print(f"Bundle: {ioc_hash_count} hash IOCs, {ioc_domain_count} domain IOCs, {ioc_ip_count} IP IOCs")

    # Copy CVE data
    cve_count = 0
    if args.cve:
        cve_src = os.path.abspath(args.cve)
        if copy_file(cve_src, os.path.join(output_dir, "cve", "cves.jsonl")):
            cve_count = count_lines(os.path.join(output_dir, "cve", "cves.jsonl"))
    print(f"Bundle: {cve_count} CVEs")

    # Build file hash index
    file_hashes = {}
    for root, _dirs, files in os.walk(output_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, output_dir)
            file_hashes[rel] = f"sha256:{sha256_file(fpath)}"

    # Write manifest
    manifest = {
        "version": version,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sigma_count": sigma_count,
        "yara_count": yara_count,
        "ioc_hash_count": ioc_hash_count,
        "ioc_domain_count": ioc_domain_count,
        "ioc_ip_count": ioc_ip_count,
        "cve_count": cve_count,
        "files": file_hashes,
    }

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"Bundle v{version} assembled: {len(file_hashes)} files, manifest at {manifest_path}")


if __name__ == "__main__":
    main()
