#!/usr/bin/env python3
"""Extract Linux-relevant CVEs from NVD JSON, enriched with CISA KEV and EPSS.

Enrichment sources:
  - CISA KEV: flags CVEs that are actively exploited in the wild
  - EPSS: provides probability of exploitation in the next 30 days (0.0–1.0)
"""

import argparse
import csv
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
    "golang", "rust", "java", "tomcat", "haproxy", "squid", "snort",
    "suricata", "zeek", "freeradius", "openldap",
}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
}


def load_kev(path: str) -> dict[str, dict]:
    """Load CISA Known Exploited Vulnerabilities catalog.

    Returns mapping of CVE ID → {date_added, due_date, ransomware_use}.
    """
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    kev = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if cve_id:
            kev[cve_id] = {
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            }
    print(f"CISA KEV: {len(kev)} actively exploited CVEs loaded")
    return kev


def load_epss(path: str) -> dict[str, dict]:
    """Load EPSS scores CSV.

    Expected format (after header comment):
        cve,epss,percentile
        CVE-2024-1234,0.12345,0.678

    Returns mapping of CVE ID → {epss, percentile}.
    """
    if not path or not os.path.isfile(path):
        return {}
    epss = {}
    with open(path, "r", encoding="utf-8") as f:
        # Skip any comment/metadata lines
        reader = None
        for line in f:
            if line.startswith("#"):
                continue
            if line.strip().startswith("cve,"):
                # This is the header line
                f_remaining = [line] + f.readlines()
                reader = csv.DictReader(f_remaining)
                break
        if reader is None:
            return epss
        for row in reader:
            cve_id = row.get("cve", "").strip()
            if cve_id.startswith("CVE-"):
                try:
                    epss[cve_id] = {
                        "epss": float(row.get("epss", 0)),
                        "percentile": float(row.get("percentile", 0)),
                    }
                except (ValueError, TypeError):
                    pass
    print(f"EPSS: {len(epss)} CVE scores loaded")
    return epss


def _iter_nodes(configurations) -> list[dict]:
    """Extract node list from configurations (handles dict or list format)."""
    if isinstance(configurations, dict):
        return configurations.get("nodes", [])
    if isinstance(configurations, list):
        nodes = []
        for cfg in configurations:
            if isinstance(cfg, dict):
                nodes.extend(cfg.get("nodes", []))
        return nodes
    return []


def is_linux_relevant(cve_item: dict) -> bool:
    """Check if a CVE affects Linux ecosystem based on CPE matches."""
    configurations = cve_item.get("configurations", [])
    nodes = _iter_nodes(configurations)

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


def extract_cve_record(
    cve_data: dict,
    kev: dict[str, dict],
    epss: dict[str, dict],
) -> dict | None:
    """Extract a structured CVE record with KEV/EPSS enrichment."""
    cve_id = cve_data.get("id", "")
    if not cve_id.startswith("CVE-"):
        return None

    # Get CVSS score and severity
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    severity = "unknown"

    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            base_severity = (
                metric_list[0].get("baseSeverity", "")
                or cvss_data.get("baseSeverity", "")
            )
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
    configurations = cve_data.get("configurations", [])
    for node in _iter_nodes(configurations):
        for cpe_match in node.get("cpeMatch", []):
            criteria = cpe_match.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) >= 6:
                affected_packages.append({
                    "product": parts[4],
                    "version_start": cpe_match.get("versionStartIncluding", ""),
                    "version_end": cpe_match.get("versionEndExcluding", ""),
                })

    published = cve_data.get("published", "")

    record: dict = {
        "cve_id": cve_id,
        "severity": severity,
        "cvss": cvss_score,
        "affected_packages": affected_packages,
        "description": description[:500],
        "published": published,
    }

    # ── CISA KEV enrichment ──────────────────────────────────────
    kev_entry = kev.get(cve_id)
    if kev_entry:
        record["actively_exploited"] = True
        record["kev_date_added"] = kev_entry["date_added"]
        record["kev_due_date"] = kev_entry["due_date"]
        record["kev_ransomware"] = kev_entry["ransomware_use"]
    else:
        record["actively_exploited"] = False

    # ── EPSS enrichment ──────────────────────────────────────────
    epss_entry = epss.get(cve_id)
    if epss_entry:
        record["epss_score"] = epss_entry["epss"]
        record["epss_percentile"] = epss_entry["percentile"]

    return record


def process_nvd_file(
    path: str,
    kev: dict[str, dict],
    epss: dict[str, dict],
) -> list[dict]:
    """Process an NVD JSON feed file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", data.get("CVE_Items", []))
    results = []

    for item in vulnerabilities:
        cve_data = item.get("cve", item)

        if not is_linux_relevant(cve_data):
            continue

        record = extract_cve_record(cve_data, kev, epss)
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
    parser.add_argument("--kev", default="", help="Path to CISA KEV JSON catalog")
    parser.add_argument("--epss", default="", help="Path to EPSS scores CSV")
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Load enrichment data
    kev = load_kev(args.kev)
    epss = load_epss(args.epss)

    all_records = []

    if os.path.isfile(input_path):
        all_records.extend(process_nvd_file(input_path, kev, epss))
    elif os.path.isdir(input_path):
        for fname in sorted(os.listdir(input_path)):
            if fname.endswith(".json"):
                fpath = os.path.join(input_path, fname)
                all_records.extend(process_nvd_file(fpath, kev, epss))

    # Filter by minimum CVSS (KEV entries always pass regardless of CVSS)
    if args.min_cvss > 0:
        all_records = [
            r for r in all_records
            if r["cvss"] >= args.min_cvss or r.get("actively_exploited")
        ]

    # Deduplicate by CVE ID
    seen = set()
    unique = []
    for record in all_records:
        if record["cve_id"] not in seen:
            seen.add(record["cve_id"])
            unique.append(record)

    # Sort: actively exploited first, then by CVSS descending
    unique.sort(key=lambda r: (
        0 if r.get("actively_exploited") else 1,
        -r.get("cvss", 0),
    ))

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        for record in unique:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")

    kev_count = sum(1 for r in unique if r.get("actively_exploited"))
    epss_count = sum(1 for r in unique if "epss_score" in r)
    print(f"CVE extract: {len(unique)} Linux CVEs extracted")
    print(f"  CISA KEV (actively exploited): {kev_count}")
    print(f"  EPSS-enriched: {epss_count}")


if __name__ == "__main__":
    main()
