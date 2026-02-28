//! Extended hardware inventory via WMI.
//!
//! Returns `HashMap<String, String>` with `hw.*` prefixed keys including
//! CPU clock speed, RAM DIMM details, disk size/type, GPU, and network adapters.

use std::collections::HashMap;

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;

use serde::Serialize;
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

/// Collect detailed hardware inventory via a single PowerShell invocation.
pub fn collect_hardware_inventory() -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    attrs.insert("hw.cpu.arch".into(), std::env::consts::ARCH.to_string());

    #[cfg(target_os = "windows")]
    {
        let cmd = concat!(
            "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1 ",
            "Name,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors;",
            "$cs=Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 TotalPhysicalMemory,PartOfDomain,Domain;",
            "$mem=@(Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Speed,SMBIOSMemoryType,Manufacturer);",
            "$disk=@(Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,MediaType);",
            "$vol=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,Size,FreeSpace,FileSystem);",
            "$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1 Name,AdapterRAM;",
            "$net=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object Name,LinkSpeed,MacAddress);",
            "[pscustomobject]@{",
            "cpu=$cpu;ram_total_mb=[math]::Round($cs.TotalPhysicalMemory/1MB);",
            "domain_joined=$cs.PartOfDomain;domain_name=$cs.Domain;",
            "dimms=$mem;disks=$disk;volumes=$vol;gpu=$gpu;adapters=$net",
            "} | ConvertTo-Json -Depth 3 -Compress",
        );
        if let Some(json) = run_powershell(cmd) {
            attrs = parse_hardware_detail_json(&json);
        }
        // Collect installed software from registry
        collect_software_inventory(&mut attrs);
    }

    attrs
}

#[cfg(target_os = "windows")]
fn run_powershell(command: &str) -> Option<String> {
    let output = Command::new(POWERSHELL_EXE)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() { None } else { Some(stdout) }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_hardware_detail_json(raw: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    attrs.insert("hw.cpu.arch".into(), std::env::consts::ARCH.to_string());

    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return attrs,
    };

    // CPU
    if let Some(cpu) = v.get("cpu") {
        if let Some(name) = cpu.get("Name").and_then(Value::as_str) {
            attrs.insert("hw.cpu.model".into(), name.trim().to_string());
        }
        if let Some(mhz) = cpu.get("MaxClockSpeed").and_then(Value::as_u64) {
            attrs.insert("hw.cpu.clock_mhz".into(), mhz.to_string());
        }
        if let Some(cores) = cpu.get("NumberOfCores").and_then(Value::as_u64) {
            attrs.insert("hw.cpu.cores".into(), cores.to_string());
        }
        if let Some(logical) = cpu.get("NumberOfLogicalProcessors").and_then(Value::as_u64) {
            attrs.insert("hw.cpu.logical_cores".into(), logical.to_string());
        }
    }

    // RAM total
    if let Some(ram_mb) = v.get("ram_total_mb").and_then(Value::as_u64) {
        attrs.insert("hw.ram.total_mb".into(), ram_mb.to_string());
    }

    // Domain join status (Windows only)
    if let Some(joined) = v.get("domain_joined").and_then(Value::as_bool) {
        attrs.insert("hw.domain.joined".into(), joined.to_string());
    }
    if let Some(domain_name) = v.get("domain_name").and_then(Value::as_str) {
        let domain_name = domain_name.trim();
        if !domain_name.is_empty() {
            attrs.insert("hw.domain.name".into(), domain_name.to_string());
        }
    }

    // RAM DIMMs
    if let Some(dimms) = v.get("dimms").and_then(Value::as_array) {
        attrs.insert("hw.ram.dimm_count".into(), dimms.len().to_string());

        let mut dimm_entries = Vec::new();
        let mut first_type = None;
        let mut first_speed = None;

        for dimm in dimms {
            let capacity_mb = dimm
                .get("Capacity")
                .and_then(Value::as_u64)
                .map(|b| b / (1024 * 1024))
                .unwrap_or(0);
            let speed = dimm.get("Speed").and_then(Value::as_u64).unwrap_or(0);
            let smbios_type = dimm.get("SMBIOSMemoryType").and_then(Value::as_u64).unwrap_or(0);
            let manufacturer = dimm
                .get("Manufacturer")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();

            let type_name = smbios_memory_type(smbios_type);
            if first_type.is_none() && !type_name.is_empty() {
                first_type = Some(type_name.to_string());
            }
            if first_speed.is_none() && speed > 0 {
                first_speed = Some(speed);
            }

            dimm_entries.push(DimmEntry {
                capacity_mb,
                speed_mhz: speed as u32,
                memory_type: type_name.to_string(),
                manufacturer,
            });
        }

        if let Some(t) = first_type {
            attrs.insert("hw.ram.type".into(), t);
        }
        if let Some(s) = first_speed {
            attrs.insert("hw.ram.speed_mhz".into(), s.to_string());
        }
        if let Ok(json) = serde_json::to_string(&dimm_entries) {
            attrs.insert("hw.ram.dimms".into(), json);
        }
    }

    // Disks
    if let Some(disks) = v.get("disks").and_then(Value::as_array) {
        let mut disk_entries = Vec::new();
        let mut total_gb: u64 = 0;

        for disk in disks {
            let size_bytes = disk.get("Size").and_then(Value::as_u64).unwrap_or(0);
            let size_gb = size_bytes / (1024 * 1024 * 1024);
            total_gb += size_gb;

            let model = disk.get("Model").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let media = disk.get("MediaType").and_then(Value::as_str).unwrap_or("");
            let disk_type = classify_windows_media_type(media, &model);

            disk_entries.push(DiskEntry {
                model: model.clone(),
                size_gb,
                disk_type: disk_type.clone(),
            });
        }

        if total_gb > 0 {
            attrs.insert("hw.disk.total_gb".into(), total_gb.to_string());
        }
        if let Some(first) = disk_entries.first() {
            attrs.insert("hw.disk.type".into(), first.disk_type.clone());
            if !first.model.is_empty() {
                attrs.insert("hw.disk.model".into(), first.model.clone());
            }
        }
        if disk_entries.len() > 1 {
            if let Ok(json) = serde_json::to_string(&disk_entries) {
                attrs.insert("hw.disk.disks".into(), json);
            }
        }
    }

    // Volumes (free space)
    if let Some(vols) = v.get("volumes").and_then(Value::as_array) {
        let total_free: u64 = vols
            .iter()
            .filter_map(|vol| vol.get("FreeSpace").and_then(Value::as_u64))
            .sum();
        if total_free > 0 {
            attrs.insert(
                "hw.disk.free_gb".into(),
                (total_free / (1024 * 1024 * 1024)).to_string(),
            );
        }
    }

    // GPU
    if let Some(gpu) = v.get("gpu") {
        if let Some(name) = gpu.get("Name").and_then(Value::as_str) {
            let name = name.trim();
            if !name.is_empty() {
                attrs.insert("hw.gpu.model".into(), name.to_string());
            }
        }
        if let Some(vram) = gpu.get("AdapterRAM").and_then(Value::as_u64) {
            if vram > 0 {
                attrs.insert("hw.gpu.vram_mb".into(), (vram / (1024 * 1024)).to_string());
            }
        }
    }

    // Network adapters
    if let Some(adapters) = v.get("adapters").and_then(Value::as_array) {
        let entries: Vec<NetAdapterEntry> = adapters
            .iter()
            .filter_map(|a| {
                let name = a.get("Name").and_then(Value::as_str)?.trim().to_string();
                let speed = a.get("LinkSpeed").and_then(Value::as_str).unwrap_or("").trim().to_string();
                let mac = a.get("MacAddress").and_then(Value::as_str).unwrap_or("").trim().to_string();
                Some(NetAdapterEntry { name, speed, mac })
            })
            .collect();

        if !entries.is_empty() {
            if let Ok(json) = serde_json::to_string(&entries) {
                attrs.insert("hw.net.adapters".into(), json);
            }
        }
    }

    attrs
}

// ---------------------------------------------------------------------------
// Installed Software (reuses existing software.rs module)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn collect_software_inventory(attrs: &mut HashMap<String, String>) {
    let programs = super::collect_installed_software();
    if programs.is_empty() {
        return;
    }
    attrs.insert("hw.software.count".into(), programs.len().to_string());

    // Convert to simple name+version entries, cap at 500
    let entries: Vec<SoftwareEntry> = programs
        .into_iter()
        .take(500)
        .map(|p| {
            // Windows install_date format is "yyyyMMdd", convert to dd/mm/yyyy
            let installed_at = p
                .install_date
                .as_deref()
                .and_then(format_windows_install_date)
                .unwrap_or_default();
            SoftwareEntry {
                name: p.name,
                version: p.version.unwrap_or_default(),
                installed_at,
            }
        })
        .collect();
    if let Ok(json) = serde_json::to_string(&entries) {
        attrs.insert("hw.software.packages".into(), json);
    }
}

// ---------------------------------------------------------------------------
// Helper types and mappings
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct SoftwareEntry {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    installed_at: String,
}

#[derive(Debug, Serialize)]
struct DimmEntry {
    capacity_mb: u64,
    speed_mhz: u32,
    memory_type: String,
    manufacturer: String,
}

#[derive(Debug, Serialize)]
struct DiskEntry {
    model: String,
    size_gb: u64,
    #[serde(rename = "type")]
    disk_type: String,
}

#[derive(Debug, Serialize)]
struct NetAdapterEntry {
    name: String,
    speed: String,
    mac: String,
}

/// Convert Windows install date "yyyyMMdd" to "dd/mm/yyyy".
#[cfg(target_os = "windows")]
fn format_windows_install_date(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() != 8 {
        return None;
    }
    let year = &raw[0..4];
    let month = &raw[4..6];
    let day = &raw[6..8];
    Some(format!("{}/{}/{}", day, month, year))
}

#[cfg(any(test, target_os = "windows"))]
fn smbios_memory_type(code: u64) -> &'static str {
    match code {
        20 => "DDR",
        21 => "DDR2",
        22 => "DDR2 FB-DIMM",
        24 => "DDR3",
        26 => "DDR4",
        34 => "DDR5",
        _ => "",
    }
}

#[cfg(any(test, target_os = "windows"))]
fn classify_windows_media_type(media: &str, model: &str) -> String {
    let media_lower = media.to_ascii_lowercase();
    let model_lower = model.to_ascii_lowercase();
    if model_lower.contains("nvme") || model_lower.contains("nvm") {
        "NVMe".to_string()
    } else if media_lower.contains("solid state") || media_lower.contains("ssd") {
        "SSD".to_string()
    } else if media_lower.contains("fixed hard disk") || media_lower.contains("hdd") {
        "HDD".to_string()
    } else if media_lower.is_empty() {
        // Virtual disks often have empty MediaType
        "Virtual".to_string()
    } else {
        media.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_hardware_detail_json;

    #[test]
    fn parses_full_hardware_detail_json() {
        let raw = r#"{
            "cpu":{"Name":"Intel(R) Core(TM) i7-12700K","MaxClockSpeed":3600,"NumberOfCores":12,"NumberOfLogicalProcessors":20},
            "ram_total_mb":32768,
            "domain_joined":true,
            "domain_name":"LAB.LOCAL",
            "dimms":[
                {"Capacity":17179869184,"Speed":3200,"SMBIOSMemoryType":26,"Manufacturer":"Samsung"},
                {"Capacity":17179869184,"Speed":3200,"SMBIOSMemoryType":26,"Manufacturer":"Samsung"}
            ],
            "disks":[
                {"Model":"Samsung SSD 970 EVO","Size":512110190592,"MediaType":"Fixed hard disk media"}
            ],
            "volumes":[
                {"DeviceID":"C:","Size":512058654720,"FreeSpace":234567890000,"FileSystem":"NTFS"}
            ],
            "gpu":{"Name":"NVIDIA GeForce RTX 3080","AdapterRAM":10737418240},
            "adapters":[
                {"Name":"Ethernet","LinkSpeed":"1 Gbps","MacAddress":"00-1A-2B-3C-4D-5E"}
            ]
        }"#;

        let attrs = parse_hardware_detail_json(raw);

        assert_eq!(attrs.get("hw.cpu.model").unwrap(), "Intel(R) Core(TM) i7-12700K");
        assert_eq!(attrs.get("hw.cpu.clock_mhz").unwrap(), "3600");
        assert_eq!(attrs.get("hw.cpu.cores").unwrap(), "12");
        assert_eq!(attrs.get("hw.cpu.logical_cores").unwrap(), "20");
        assert_eq!(attrs.get("hw.ram.total_mb").unwrap(), "32768");
        assert_eq!(attrs.get("hw.domain.joined").unwrap(), "true");
        assert_eq!(attrs.get("hw.domain.name").unwrap(), "LAB.LOCAL");
        assert_eq!(attrs.get("hw.ram.type").unwrap(), "DDR4");
        assert_eq!(attrs.get("hw.ram.speed_mhz").unwrap(), "3200");
        assert_eq!(attrs.get("hw.ram.dimm_count").unwrap(), "2");
        assert_eq!(attrs.get("hw.disk.total_gb").unwrap(), "476");
        assert_eq!(attrs.get("hw.disk.type").unwrap(), "HDD");
        assert_eq!(attrs.get("hw.disk.model").unwrap(), "Samsung SSD 970 EVO");
        assert_eq!(attrs.get("hw.disk.free_gb").unwrap(), "218");
        assert_eq!(attrs.get("hw.gpu.model").unwrap(), "NVIDIA GeForce RTX 3080");
        assert_eq!(attrs.get("hw.gpu.vram_mb").unwrap(), "10240");
        assert!(attrs.get("hw.net.adapters").unwrap().contains("Ethernet"));
        assert!(attrs.get("hw.ram.dimms").unwrap().contains("Samsung"));
    }

    #[test]
    fn handles_empty_and_minimal_json() {
        let attrs = parse_hardware_detail_json("{}");
        assert!(attrs.contains_key("hw.cpu.arch"));

        let attrs2 = parse_hardware_detail_json(r#"{"cpu":{"Name":"Test"}}"#);
        assert_eq!(attrs2.get("hw.cpu.model").unwrap(), "Test");
    }
}
