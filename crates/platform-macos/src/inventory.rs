//! macOS hardware inventory collection via sysctl and system_profiler.
//!
//! Returns `HashMap<String, String>` with `hw.*` prefixed keys.

use std::collections::HashMap;
use std::process::Command;

use serde::Serialize;

/// Collect hardware inventory from sysctl and system_profiler.
pub fn collect_hardware_inventory() -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    attrs.insert("hw.cpu.arch".into(), std::env::consts::ARCH.to_string());

    collect_cpu_info(&mut attrs);
    collect_memory_info(&mut attrs);
    collect_disk_info(&mut attrs);
    collect_gpu_info(&mut attrs);

    attrs
}

// ---------------------------------------------------------------------------
// CPU — sysctl
// ---------------------------------------------------------------------------

fn collect_cpu_info(attrs: &mut HashMap<String, String>) {
    if let Some(model) = sysctl_string("machdep.cpu.brand_string") {
        attrs.insert("hw.cpu.model".into(), model);
    }
    if let Some(freq) = sysctl_u64("hw.cpufrequency") {
        attrs.insert("hw.cpu.clock_mhz".into(), (freq / 1_000_000).to_string());
    }
    if let Some(physical) = sysctl_u64("hw.physicalcpu") {
        attrs.insert("hw.cpu.cores".into(), physical.to_string());
    }
    if let Some(logical) = sysctl_u64("hw.ncpu") {
        attrs.insert("hw.cpu.logical_cores".into(), logical.to_string());
    }
}

// ---------------------------------------------------------------------------
// RAM — sysctl + system_profiler SPMemoryDataType
// ---------------------------------------------------------------------------

fn collect_memory_info(attrs: &mut HashMap<String, String>) {
    if let Some(memsize) = sysctl_u64("hw.memsize") {
        attrs.insert("hw.ram.total_mb".into(), (memsize / (1024 * 1024)).to_string());
    }

    // DIMM details from system_profiler
    if let Some(json) = run_system_profiler("SPMemoryDataType") {
        parse_memory_profiler(&json, attrs);
    }
}

fn parse_memory_profiler(json: &str, attrs: &mut HashMap<String, String>) {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let items = match v.get("SPMemoryDataType").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return,
    };

    let mut dimm_entries = Vec::new();
    let mut first_type = None;
    let mut first_speed = None;

    for item in items {
        // system_profiler nests DIMMs under "_items" in each memory bank
        if let Some(dimms) = item.get("_items").and_then(|v| v.as_array()) {
            for dimm in dimms {
                let size_str = dimm.get("dimm_size").and_then(|v| v.as_str()).unwrap_or("");
                let capacity_mb = parse_size_to_mb(size_str);
                let dimm_type = dimm.get("dimm_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let speed = dimm.get("dimm_speed").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let manufacturer = dimm.get("dimm_manufacturer").and_then(|v| v.as_str()).unwrap_or("").to_string();

                if first_type.is_none() && !dimm_type.is_empty() {
                    first_type = Some(dimm_type.clone());
                }
                if first_speed.is_none() && !speed.is_empty() {
                    first_speed = Some(speed.clone());
                }

                dimm_entries.push(DimmEntry {
                    capacity_mb,
                    memory_type: dimm_type,
                    speed: speed.clone(),
                    manufacturer,
                });
            }
        }
    }

    if !dimm_entries.is_empty() {
        attrs.insert("hw.ram.dimm_count".into(), dimm_entries.len().to_string());
    }
    if let Some(t) = first_type {
        attrs.insert("hw.ram.type".into(), t);
    }
    if let Some(s) = first_speed {
        // Extract numeric MHz from strings like "3200 MHz"
        let mhz = s.split_whitespace().next().unwrap_or(&s);
        if let Ok(n) = mhz.parse::<u32>() {
            attrs.insert("hw.ram.speed_mhz".into(), n.to_string());
        }
    }
    if let Ok(json) = serde_json::to_string(&dimm_entries) {
        attrs.insert("hw.ram.dimms".into(), json);
    }
}

// ---------------------------------------------------------------------------
// Disk — system_profiler SPStorageDataType
// ---------------------------------------------------------------------------

fn collect_disk_info(attrs: &mut HashMap<String, String>) {
    let json = match run_system_profiler("SPStorageDataType") {
        Some(j) => j,
        None => return,
    };

    let v: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let items = match v.get("SPStorageDataType").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return,
    };

    let mut disk_entries = Vec::new();
    let mut total_gb: u64 = 0;
    let mut total_free_gb: u64 = 0;

    for item in items {
        let name = item.get("_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let size_bytes = item.get("size_in_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let free_bytes = item.get("free_space_in_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let medium = item
            .get("physical_drive")
            .and_then(|pd| pd.get("medium_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let size_gb = size_bytes / (1024 * 1024 * 1024);
        let free_gb = free_bytes / (1024 * 1024 * 1024);
        total_gb += size_gb;
        total_free_gb += free_gb;

        let disk_type = if medium.contains("SSD") || medium.contains("ssd") {
            "SSD"
        } else if medium.contains("HDD") || medium.contains("Rotational") {
            "HDD"
        } else {
            medium
        };

        disk_entries.push(DiskEntryMac {
            name,
            size_gb,
            free_gb,
            disk_type: disk_type.to_string(),
        });
    }

    if total_gb > 0 {
        attrs.insert("hw.disk.total_gb".into(), total_gb.to_string());
    }
    if total_free_gb > 0 {
        attrs.insert("hw.disk.free_gb".into(), total_free_gb.to_string());
    }
    if let Some(first) = disk_entries.first() {
        attrs.insert("hw.disk.type".into(), first.disk_type.clone());
        if !first.name.is_empty() {
            attrs.insert("hw.disk.model".into(), first.name.clone());
        }
    }
    if disk_entries.len() > 1 {
        if let Ok(json) = serde_json::to_string(&disk_entries) {
            attrs.insert("hw.disk.disks".into(), json);
        }
    }
}

// ---------------------------------------------------------------------------
// GPU — system_profiler SPDisplaysDataType
// ---------------------------------------------------------------------------

fn collect_gpu_info(attrs: &mut HashMap<String, String>) {
    let json = match run_system_profiler("SPDisplaysDataType") {
        Some(j) => j,
        None => return,
    };

    let v: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let items = match v.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return,
    };

    if let Some(gpu) = items.first() {
        if let Some(model) = gpu.get("sppci_model").and_then(|v| v.as_str()) {
            attrs.insert("hw.gpu.model".into(), model.trim().to_string());
        }
        // VRAM is reported as string like "16 GB" or "1536 MB"
        if let Some(vram_str) = gpu.get("spdisplays_vram").and_then(|v| v.as_str()) {
            let vram_mb = parse_size_to_mb(vram_str);
            if vram_mb > 0 {
                attrs.insert("hw.gpu.vram_mb".into(), vram_mb.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct DimmEntry {
    capacity_mb: u64,
    memory_type: String,
    speed: String,
    manufacturer: String,
}

#[derive(Debug, Serialize)]
struct DiskEntryMac {
    name: String,
    size_gb: u64,
    free_gb: u64,
    #[serde(rename = "type")]
    disk_type: String,
}

fn sysctl_string(key: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn sysctl_u64(key: &str) -> Option<u64> {
    sysctl_string(key)?.parse().ok()
}

fn run_system_profiler(data_type: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/system_profiler")
        .args([data_type, "-json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Parse size strings like "8 GB", "16384 MB", "512 GB" to megabytes.
fn parse_size_to_mb(s: &str) -> u64 {
    let s = s.trim();
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return s.parse().unwrap_or(0);
    }
    let num: f64 = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return 0,
    };
    match parts[1].to_uppercase().as_str() {
        "TB" => (num * 1024.0 * 1024.0) as u64,
        "GB" => (num * 1024.0) as u64,
        "MB" => num as u64,
        "KB" => (num / 1024.0) as u64,
        _ => num as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_to_mb_works() {
        assert_eq!(parse_size_to_mb("8 GB"), 8192);
        assert_eq!(parse_size_to_mb("16384 MB"), 16384);
        assert_eq!(parse_size_to_mb("1 TB"), 1048576);
        assert_eq!(parse_size_to_mb("512 KB"), 0); // rounds to 0
        assert_eq!(parse_size_to_mb(""), 0);
    }
}
