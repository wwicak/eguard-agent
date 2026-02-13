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


def count_kev(path: str) -> int:
    """Count CVEs flagged as actively exploited."""
    if not os.path.isfile(path):
        return 0
    count = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if record.get("actively_exploited"):
                    count += 1
            except json.JSONDecodeError:
                pass
    return count


def count_epss(path: str) -> int:
    """Count CVEs with EPSS scores."""
    if not os.path.isfile(path):
        return 0
    count = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if "epss_score" in record:
                    count += 1
            except json.JSONDecodeError:
                pass
    return count


def detect_sources(output_dir: str) -> dict[str, list[str]]:
    """Detect which sources contributed to the bundle."""
    sources: dict[str, list[str]] = {}

    # YARA sources: top-level subdirs under yara/
    yara_dir = os.path.join(output_dir, "yara")
    if os.path.isdir(yara_dir):
        yara_sources = []
        for entry in sorted(os.listdir(yara_dir)):
            if os.path.isdir(os.path.join(yara_dir, entry)):
                yara_sources.append(entry)
        if yara_sources:
            sources["yara"] = yara_sources

    # SIGMA sources: top-level subdirs under sigma/
    sigma_dir = os.path.join(output_dir, "sigma")
    if os.path.isdir(sigma_dir):
        sigma_sources = []
        for entry in sorted(os.listdir(sigma_dir)):
            if os.path.isdir(os.path.join(sigma_dir, entry)):
                sigma_sources.append(entry)
        if sigma_sources:
            sources["sigma"] = sigma_sources

    return sources


def main():
    parser = argparse.ArgumentParser(description="Build eGuard threat intel bundle")
    parser.add_argument("--sigma", default="", help="Directory of filtered SIGMA rules")
    parser.add_argument("--yara", default="", help="Directory of validated YARA rules")
    parser.add_argument("--ioc", default="", help="Directory of filtered IOC files")
    parser.add_argument("--cve", default="", help="Path to CVE JSONL file")
    parser.add_argument("--suricata", default="", help="Directory of Suricata rules")
    parser.add_argument("--elastic", default="", help="Directory of Elastic detection rules")
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
    cve_kev_count = 0
    cve_epss_count = 0
    cve_path = os.path.join(output_dir, "cve", "cves.jsonl")
    if args.cve:
        cve_src = os.path.abspath(args.cve)
        if copy_file(cve_src, cve_path):
            cve_count = count_lines(cve_path)
            cve_kev_count = count_kev(cve_path)
            cve_epss_count = count_epss(cve_path)
    print(f"Bundle: {cve_count} CVEs ({cve_kev_count} actively exploited, {cve_epss_count} EPSS-enriched)")

    # Copy Suricata rules
    suricata_count = 0
    if args.suricata:
        suricata_dir = os.path.abspath(args.suricata)
        if os.path.isdir(suricata_dir):
            suricata_out = os.path.join(output_dir, "suricata")
            suricata_count = copy_tree(suricata_dir, suricata_out)
            # Count actual alert rules (not just files)
            rule_count = 0
            for root, _dirs, files in os.walk(suricata_out):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        rule_count += sum(1 for line in f if line.strip().startswith("alert "))
            print(f"Bundle: {suricata_count} Suricata rule files ({rule_count} alert rules)")
            suricata_count = rule_count  # Report actual rule count
    else:
        print("Bundle: 0 Suricata rules")

    # Copy Elastic detection rules
    elastic_count = 0
    if args.elastic:
        elastic_dir = os.path.abspath(args.elastic)
        if os.path.isdir(elastic_dir):
            elastic_count = copy_tree(elastic_dir, os.path.join(output_dir, "elastic"))
            # Count actual rules from JSONL
            jsonl_path = os.path.join(output_dir, "elastic", "elastic-rules.jsonl")
            if os.path.isfile(jsonl_path):
                elastic_count = count_lines(jsonl_path)
    print(f"Bundle: {elastic_count} Elastic behavioral rules")

    # Detect sources
    sources = detect_sources(output_dir)

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
        "suricata_count": suricata_count,
        "elastic_count": elastic_count,
        "cve_kev_count": cve_kev_count,
        "cve_epss_count": cve_epss_count,
        "sources": sources,
        "files": file_hashes,
    }

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    total_files = len(file_hashes)
    print(f"\nBundle v{version} assembled: {total_files} files, manifest at {manifest_path}")


if __name__ == "__main__":
    main()
