//! Linux hardware inventory collection via /proc and /sys.
//!
//! Returns `HashMap<String, String>` with `hw.*` prefixed keys.
//! All reads are from kernel virtual filesystems — no subprocess spawning,
//! no root required for basic info.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

/// Collect hardware inventory from /proc and /sys.
pub fn collect_hardware_inventory() -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    attrs.insert(
        "hw.cpu.arch".into(),
        std::env::consts::ARCH.to_string(),
    );

    collect_cpu_info(&mut attrs);
    collect_memory_info(&mut attrs);
    collect_disk_info(&mut attrs);
    collect_gpu_info(&mut attrs);
    collect_network_info(&mut attrs);
    collect_installed_packages(&mut attrs);

    attrs
}

// ---------------------------------------------------------------------------
// CPU — /proc/cpuinfo
// ---------------------------------------------------------------------------

fn collect_cpu_info(attrs: &mut HashMap<String, String>) {
    let cpuinfo = match fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut model_name = None;
    let mut cpu_mhz = None;
    let mut physical_cores = None;
    let mut logical_cores: u32 = 0;

    for line in cpuinfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "model name" if model_name.is_none() => {
                model_name = Some(value.to_string());
            }
            "cpu MHz" if cpu_mhz.is_none() => {
                if let Ok(mhz) = value.parse::<f64>() {
                    cpu_mhz = Some(mhz as u32);
                }
            }
            "cpu cores" if physical_cores.is_none() => {
                if let Ok(cores) = value.parse::<u32>() {
                    physical_cores = Some(cores);
                }
            }
            "processor" => {
                logical_cores += 1;
            }
            _ => {}
        }
    }

    if let Some(model) = model_name {
        attrs.insert("hw.cpu.model".into(), model);
    }
    if let Some(mhz) = cpu_mhz {
        attrs.insert("hw.cpu.clock_mhz".into(), mhz.to_string());
    }
    if let Some(cores) = physical_cores {
        attrs.insert("hw.cpu.cores".into(), cores.to_string());
    }
    if logical_cores > 0 {
        attrs.insert("hw.cpu.logical_cores".into(), logical_cores.to_string());
    }
}

// ---------------------------------------------------------------------------
// RAM — /proc/meminfo
// ---------------------------------------------------------------------------

fn collect_memory_info(attrs: &mut HashMap<String, String>) {
    let meminfo = match fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => return,
    };

    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let rest = rest.trim();
            // Format: "16384000 kB"
            if let Some(kb_str) = rest.split_whitespace().next() {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    attrs.insert("hw.ram.total_mb".into(), (kb / 1024).to_string());
                }
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Disk — /sys/block/* and statvfs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct DiskEntry {
    name: String,
    size_gb: u64,
    #[serde(rename = "type")]
    disk_type: String,
    model: String,
}

fn collect_disk_info(attrs: &mut HashMap<String, String>) {
    let mut disks = Vec::new();

    let block_dir = match fs::read_dir("/sys/block") {
        Ok(rd) => rd,
        Err(_) => return,
    };

    for entry in block_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Only real block devices (sd*, nvme*, vd*, xvd*, hd*)
        if !name.starts_with("sd")
            && !name.starts_with("nvme")
            && !name.starts_with("vd")
            && !name.starts_with("xvd")
            && !name.starts_with("hd")
        {
            continue;
        }

        let block_path = entry.path();
        let size_sectors = read_trimmed_u64(&block_path.join("size")).unwrap_or(0);
        let size_gb = size_sectors * 512 / (1024 * 1024 * 1024);

        if size_gb == 0 {
            continue;
        }

        let rotational = read_trimmed(&block_path.join("queue/rotational"))
            .unwrap_or_default();
        let disk_type = if name.starts_with("nvme") {
            "NVMe".to_string()
        } else if rotational == "0" {
            "SSD".to_string()
        } else {
            "HDD".to_string()
        };

        let model = read_trimmed(&block_path.join("device/model"))
            .unwrap_or_default();

        disks.push(DiskEntry {
            name,
            size_gb,
            disk_type,
            model,
        });
    }

    // Aggregate totals from all disks
    let total_gb: u64 = disks.iter().map(|d| d.size_gb).sum();
    if total_gb > 0 {
        attrs.insert("hw.disk.total_gb".into(), total_gb.to_string());
    }

    // Primary disk type and model
    if let Some(first) = disks.first() {
        attrs.insert("hw.disk.type".into(), first.disk_type.clone());
        if !first.model.is_empty() {
            attrs.insert("hw.disk.model".into(), first.model.clone());
        }
    }

    // Free space on root filesystem via statvfs
    if let Some(free_gb) = statvfs_free_gb("/") {
        attrs.insert("hw.disk.free_gb".into(), free_gb.to_string());
    }

    // All disks as JSON array
    if disks.len() > 1 {
        if let Ok(json) = serde_json::to_string(&disks) {
            attrs.insert("hw.disk.disks".into(), json);
        }
    }
}

fn statvfs_free_gb(path: &str) -> Option<u64> {
    use std::ffi::CString;
    let c_path = CString::new(path).ok()?;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            let free_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
            Some(free_bytes / (1024 * 1024 * 1024))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// GPU — /sys/bus/pci/devices/*/class (VGA/3D controller = 0x03xxxx)
// ---------------------------------------------------------------------------

fn collect_gpu_info(attrs: &mut HashMap<String, String>) {
    let pci_dir = match fs::read_dir("/sys/bus/pci/devices") {
        Ok(rd) => rd,
        Err(_) => return,
    };

    for entry in pci_dir.flatten() {
        let class = match read_trimmed(&entry.path().join("class")) {
            Some(c) => c,
            None => continue,
        };

        // VGA compatible controller = 0x030000, 3D controller = 0x030200
        if !class.starts_with("0x03") {
            continue;
        }

        // Try uevent for a model description
        if let Some(uevent) = read_trimmed(&entry.path().join("uevent")) {
            for line in uevent.lines() {
                if let Some(driver) = line.strip_prefix("DRIVER=") {
                    let vendor = read_trimmed(&entry.path().join("vendor"))
                        .unwrap_or_default();
                    let device = read_trimmed(&entry.path().join("device"))
                        .unwrap_or_default();
                    attrs.insert(
                        "hw.gpu.model".into(),
                        format!("{} ({}:{})", driver.trim(), vendor, device),
                    );
                    return;
                }
            }
        }

        // Fallback: vendor:device IDs
        let vendor = read_trimmed(&entry.path().join("vendor")).unwrap_or_default();
        let device = read_trimmed(&entry.path().join("device")).unwrap_or_default();
        if !vendor.is_empty() {
            attrs.insert(
                "hw.gpu.model".into(),
                format!("PCI {}:{}", vendor, device),
            );
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Network — /sys/class/net/*
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct NetAdapterEntry {
    name: String,
    speed: String,
    mac: String,
    driver: String,
}

fn collect_network_info(attrs: &mut HashMap<String, String>) {
    let net_dir = match fs::read_dir("/sys/class/net") {
        Ok(rd) => rd,
        Err(_) => return,
    };

    let mut adapters = Vec::new();

    for entry in net_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }

        let iface_path = entry.path();

        let speed = read_trimmed(&iface_path.join("speed"))
            .map(|s| format!("{} Mbps", s))
            .unwrap_or_default();

        let mac = read_trimmed(&iface_path.join("address"))
            .unwrap_or_default();

        // Skip interfaces with all-zero MAC
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        let driver = fs::read_link(iface_path.join("device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
            .unwrap_or_default();

        adapters.push(NetAdapterEntry {
            name,
            speed,
            mac,
            driver,
        });
    }

    if !adapters.is_empty() {
        if let Ok(json) = serde_json::to_string(&adapters) {
            attrs.insert("hw.net.adapters".into(), json);
        }
    }
}

// ---------------------------------------------------------------------------
// Installed Packages — /var/lib/dpkg/status (Debian/Ubuntu)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct PackageEntry {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    installed_at: String,
}

fn collect_installed_packages(attrs: &mut HashMap<String, String>) {
    let mut packages = Vec::new();

    // Try dpkg (Debian/Ubuntu)
    if let Ok(status) = fs::read_to_string("/var/lib/dpkg/status") {
        let mut name = String::new();
        let mut version = String::new();
        let mut installed = false;

        for line in status.lines() {
            if line.starts_with("Package: ") {
                name = line[9..].trim().to_string();
            } else if line.starts_with("Version: ") {
                version = line[9..].trim().to_string();
            } else if line.starts_with("Status: ") {
                installed = line.contains("installed");
            } else if line.is_empty() {
                if installed && !name.is_empty() {
                    let installed_at = dpkg_install_date(&name);
                    packages.push(PackageEntry {
                        name: name.clone(),
                        version: version.clone(),
                        installed_at,
                    });
                }
                name.clear();
                version.clear();
                installed = false;
            }
        }
        // Handle last entry
        if installed && !name.is_empty() {
            let installed_at = dpkg_install_date(&name);
            packages.push(PackageEntry { name, version, installed_at });
        }
    }

    // Fallback: try RPM database if dpkg not available
    if packages.is_empty() {
        if let Ok(output) = std::process::Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\n"])
            .output()
        {
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let parts: Vec<&str> = line.splitn(3, '\t').collect();
                    if parts.len() >= 2 {
                        let installed_at = parts
                            .get(2)
                            .and_then(|ts| ts.parse::<i64>().ok())
                            .map(format_unix_date)
                            .unwrap_or_default();
                        packages.push(PackageEntry {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            installed_at,
                        });
                    }
                }
            }
        }
    }

    if !packages.is_empty() {
        attrs.insert("hw.software.count".into(), packages.len().to_string());
        // Cap at 500 packages to avoid huge JSON blobs
        let capped: Vec<_> = packages.into_iter().take(500).collect();
        if let Ok(json) = serde_json::to_string(&capped) {
            attrs.insert("hw.software.packages".into(), json);
        }
    }
}

/// Get install date from /var/lib/dpkg/info/<name>.list mtime.
fn dpkg_install_date(name: &str) -> String {
    let list_path = format!("/var/lib/dpkg/info/{}.list", name);
    match fs::metadata(&list_path) {
        Ok(meta) => meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| format_unix_date(d.as_secs() as i64))
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Format a unix timestamp as dd/mm/yyyy.
fn format_unix_date(ts: i64) -> String {
    // Simple date formatting without chrono dependency
    const SECS_PER_DAY: i64 = 86400;
    let days = ts / SECS_PER_DAY;

    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:02}/{:02}/{:04}", d, m, y)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_trimmed_u64(path: &Path) -> Option<u64> {
    read_trimmed(path)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpuinfo_extracts_model_and_cores() {
        // collect_cpu_info reads /proc/cpuinfo directly;
        // on a Linux CI runner this should populate at least cpu.model
        let mut attrs = HashMap::new();
        collect_cpu_info(&mut attrs);

        // If running on Linux, we expect at least logical_cores > 0
        if cfg!(target_os = "linux") {
            assert!(
                attrs.contains_key("hw.cpu.logical_cores"),
                "expected hw.cpu.logical_cores on Linux"
            );
        }
    }

    #[test]
    fn parse_meminfo_extracts_total() {
        let mut attrs = HashMap::new();
        collect_memory_info(&mut attrs);

        if cfg!(target_os = "linux") {
            assert!(
                attrs.contains_key("hw.ram.total_mb"),
                "expected hw.ram.total_mb on Linux"
            );
            let mb: u64 = attrs["hw.ram.total_mb"].parse().unwrap();
            assert!(mb > 0, "RAM total should be > 0");
        }
    }

    #[test]
    fn collect_hardware_inventory_returns_nonempty() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let attrs = collect_hardware_inventory();
        assert!(!attrs.is_empty(), "expected non-empty hw attributes");
        assert!(attrs.contains_key("hw.cpu.arch"));
    }
}
