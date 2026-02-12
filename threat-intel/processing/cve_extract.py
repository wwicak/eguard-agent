#!/usr/bin/env python3
"""Extract Linux-relevant CVEs from NVD JSON feed for eGuard threat intel."""

import argparse
import json
import os
import sys

# CPE vendor/product patterns indicating Linux ecosystem
LINUX_VENDORS = {
    "linux", "debian", "ubuntu", "canonical", "redhat", "centos",
    "fedoraproject", "opensuse", "suse", "oracle", "alma", "rocky",
}

LINUX_PRODUCTS = {
    "linux_kernel", "kernel", "openssl", "openssh", "glibc", "systemd",
    "bash", "curl", "wget", "nginx", "apache", "httpd", "mariadb",
    "mysql", "postgresql", "redis", "docker", "containerd", "runc",
    "sudo", "polkit", "dbus", "glib", "zlib", "libxml2", "libpng",
    "libtiff", "freetype", "icu", "python", "perl", "php", "ruby",
    "nodejs", "node.js", "git", "vim", "emacs", "ntp", "chrony",
    "bind", "isc", "postfix", "dovecot", "samba", "cups", "xorg",
    "wayland", "mesa", "libvirt", "qemu", "kvm", "podman", "cri-o",
}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
}


def is_linux_relevant(cve_item: dict) -> bool:
    """Check if a CVE affects Linux ecosystem based on CPE matches."""
    configurations = cve_item.get("configurations", {})
    nodes = configurations.get("nodes", [])

    for node in nodes:
        for cpe_match in node.get("cpeMatch", []):
            criteria = cpe_match.get("criteria", "")
            parts = criteria.lower().split(":")
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                if vendor in LINUX_VENDORS or product in LINUX_PRODUCTS:
                    return True
    return False


def extract_cve_record(cve_data: dict) -> dict | None:
    """Extract a structured CVE record from NVD JSON (already unwrapped cve object)."""
    cve_id = cve_data.get("id", "")

    if not cve_id.startswith("CVE-"):
        return None

    # Get CVSS score and severity
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    severity = "unknown"

    # Try CVSS v3.1 first, then v3.0, then v2
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            base_severity = metric_list[0].get("baseSeverity", "") or cvss_data.get("baseSeverity", "")
            severity = SEVERITY_MAP.get(base_severity.upper(), "unknown")
            break

    # Get descriptions (English)
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Get affected packages from CPE
    affected_packages = []
    configurations = cve_data.get("configurations", {})
    for node in configurations.get("nodes", []):
        for cpe_match in node.get("cpeMatch", []):
            criteria = cpe_match.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) >= 6:
                product = parts[4]
                version_start = cpe_match.get("versionStartIncluding", "")
                version_end = cpe_match.get("versionEndExcluding", "")
                affected_packages.append({
                    "product": product,
                    "version_start": version_start,
                    "version_end": version_end,
                })

    published = cve_data.get("published", "")

    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss": cvss_score,
        "affected_packages": affected_packages,
        "description": description[:500],  # Truncate long descriptions
        "published": published,
    }


def process_nvd_file(path: str) -> list[dict]:
    """Process an NVD JSON feed file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", data.get("CVE_Items", []))
    results = []

    for item in vulnerabilities:
        # NVD 2.0: item = {"cve": {...}}, NVD 1.0: item is the CVE directly
        cve_data = item.get("cve", item)

        if not is_linux_relevant(cve_data):
            continue

        record = extract_cve_record(cve_data)
        if record:
            results.append(record)

    return results


def main():
    parser = argparse.ArgumentParser(description="Extract Linux CVEs from NVD JSON")
    parser.add_argument("--input", required=True, help="Input NVD JSON file or directory")
    parser.add_argument("--output", required=True, help="Output JSONL file path")
    parser.add_argument(
        "--min-cvss", type=float, default=0.0,
        help="Minimum CVSS score to include (default: 0.0)",
    )
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    all_records = []

    if os.path.isfile(input_path):
        all_records.extend(process_nvd_file(input_path))
    elif os.path.isdir(input_path):
        for fname in sorted(os.listdir(input_path)):
            if fname.endswith(".json"):
                fpath = os.path.join(input_path, fname)
                all_records.extend(process_nvd_file(fpath))

    # Filter by minimum CVSS
    if args.min_cvss > 0:
        all_records = [r for r in all_records if r["cvss"] >= args.min_cvss]

    # Deduplicate by CVE ID
    seen = set()
    unique = []
    for record in all_records:
        if record["cve_id"] not in seen:
            seen.add(record["cve_id"])
            unique.append(record)

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        for record in unique:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")

    print(f"CVE extract: {len(unique)} Linux CVEs extracted")


if __name__ == "__main__":
    main()
