//! In-memory YARA scanning for live process memory.
//!
//! Reads `/proc/[pid]/maps` to enumerate readable memory regions, then
//! scans each region via `/proc/[pid]/mem` using loaded YARA rules.
//! This detects fileless malware, injected shellcode, and in-memory
//! payloads that never touch disk.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};

use crate::yara_engine::YaraEngine;

/// Maximum total bytes to scan per process (256 MB).
const MAX_PROCESS_SCAN_BYTES: usize = 256 * 1024 * 1024;

/// Maximum size of a single memory region to scan (64 MB).
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024;

/// Minimum region size worth scanning (4 KB — skip tiny mappings).
const MIN_REGION_BYTES: usize = 4096;

/// Regions to skip (kernel, vvar, vdso, vsyscall — never contain malware).
const SKIP_REGIONS: &[&str] = &["[vvar]", "[vdso]", "[vsyscall]"];

/// A parsed memory region from /proc/[pid]/maps.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub path: String,
}

impl MemoryRegion {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns true if the region is readable (first char of perms is 'r').
    pub fn is_readable(&self) -> bool {
        self.perms.starts_with('r')
    }

    /// Returns true if the region is executable (third char of perms is 'x').
    pub fn is_executable(&self) -> bool {
        self.perms.len() >= 3 && self.perms.as_bytes()[2] == b'x'
    }

    /// Returns true if the region is a named file mapping (not anonymous, stack, heap, or special).
    pub fn is_file_backed(&self) -> bool {
        !self.path.is_empty()
            && !self.path.starts_with('[')
            && !self.path.starts_with("anon_inode:")
    }
}

/// Result of scanning a single process's memory.
#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub pid: u32,
    pub hits: Vec<MemoryYaraHit>,
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    pub errors: Vec<String>,
}

/// A YARA hit found in process memory.
#[derive(Debug, Clone)]
pub struct MemoryYaraHit {
    pub rule_name: String,
    pub matched_literal: String,
    pub region_start: u64,
    pub region_perms: String,
    pub region_path: String,
}

/// Scan mode: which memory regions to examine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Scan only executable regions (rx) — fastest, catches injected code.
    ExecutableOnly,
    /// Scan executable + anonymous writable (rwx, rw-) — catches shellcode in heap/stack.
    ExecutableAndAnonymous,
    /// Scan all readable regions — most thorough, slowest.
    AllReadable,
}

/// Parse /proc/[pid]/maps into a list of memory regions.
pub fn parse_proc_maps(pid: u32) -> io::Result<Vec<MemoryRegion>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path)?;
    Ok(parse_maps_content(&content))
}

fn parse_maps_content(content: &str) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Format: start-end perms offset dev inode pathname
        // e.g.: 7f1234560000-7f1234570000 r-xp 00000000 fd:01 12345 /usr/lib/libc.so.6
        let mut parts = line.splitn(6, char::is_whitespace);

        let Some(range) = parts.next() else {
            continue;
        };
        let Some(perms) = parts.next() else {
            continue;
        };

        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };

        let Ok(start) = u64::from_str_radix(start_hex, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end_hex, 16) else {
            continue;
        };

        // Skip offset, dev, inode; grab pathname if present
        let _offset = parts.next();
        let _dev = parts.next();
        let _inode = parts.next();
        let path = parts
            .next()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        regions.push(MemoryRegion {
            start,
            end,
            perms: perms.to_string(),
            path,
        });
    }

    regions
}

/// Filter regions based on scan mode and skip rules.
fn filter_regions(regions: &[MemoryRegion], mode: ScanMode) -> Vec<&MemoryRegion> {
    regions
        .iter()
        .filter(|r| {
            // Must be readable
            if !r.is_readable() {
                return false;
            }

            // Skip special kernel regions
            if SKIP_REGIONS.iter().any(|skip| r.path == *skip) {
                return false;
            }

            // Skip tiny regions
            if r.size() < MIN_REGION_BYTES as u64 {
                return false;
            }

            // Skip oversized regions
            if r.size() > MAX_REGION_BYTES as u64 {
                return false;
            }

            match mode {
                ScanMode::ExecutableOnly => r.is_executable(),
                ScanMode::ExecutableAndAnonymous => {
                    r.is_executable() || (!r.is_file_backed() && r.perms.starts_with("rw"))
                }
                ScanMode::AllReadable => true,
            }
        })
        .collect()
}

/// Read a memory region from /proc/[pid]/mem.
fn read_region(pid: u32, region: &MemoryRegion) -> io::Result<Vec<u8>> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = File::open(&mem_path)?;
    file.seek(SeekFrom::Start(region.start))?;

    let size = region.size().min(MAX_REGION_BYTES as u64) as usize;
    let mut buf = vec![0u8; size];

    // Process memory reads can fail partially (unmapped pages, race conditions).
    // Read what we can and truncate.
    match file.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(e) if e.kind() == io::ErrorKind::Other || e.raw_os_error() == Some(libc::EIO) => {
            // EIO is common for partially mapped regions — return empty
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    }
}

/// Scan a live process's memory with YARA rules.
///
/// Requires CAP_SYS_PTRACE or same-user access to read /proc/[pid]/mem.
/// The process should be stopped (SIGSTOP) before scanning for consistency,
/// but this function does NOT stop the process — the caller is responsible.
pub fn scan_process_memory(
    yara: &YaraEngine,
    pid: u32,
    mode: ScanMode,
) -> MemoryScanResult {
    let mut result = MemoryScanResult {
        pid,
        hits: Vec::new(),
        regions_scanned: 0,
        bytes_scanned: 0,
        errors: Vec::new(),
    };

    // Parse memory map
    let regions = match parse_proc_maps(pid) {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("parse_proc_maps: {}", e));
            return result;
        }
    };

    let targets = filter_regions(&regions, mode);
    let mut total_bytes: u64 = 0;

    for region in targets {
        if total_bytes >= MAX_PROCESS_SCAN_BYTES as u64 {
            result
                .errors
                .push("max_process_scan_bytes reached".to_string());
            break;
        }

        let buf = match read_region(pid, region) {
            Ok(b) => b,
            Err(e) => {
                result
                    .errors
                    .push(format!("read_region 0x{:x}: {}", region.start, e));
                continue;
            }
        };

        if buf.is_empty() {
            continue;
        }

        total_bytes += buf.len() as u64;
        result.regions_scanned += 1;

        // Scan with YARA
        let source_label = format!(
            "mem:{}:0x{:x}-0x{:x}:{}",
            pid, region.start, region.end, region.perms
        );
        let yara_hits = yara.scan_bytes(&source_label, &buf);

        for hit in yara_hits {
            result.hits.push(MemoryYaraHit {
                rule_name: hit.rule_name,
                matched_literal: hit.matched_literal,
                region_start: region.start,
                region_perms: region.perms.clone(),
                region_path: region.path.clone(),
            });
        }
    }

    result.bytes_scanned = total_bytes;
    result
}

/// Scan multiple processes, returning results for each.
pub fn scan_processes_memory(
    yara: &YaraEngine,
    pids: &[u32],
    mode: ScanMode,
) -> Vec<MemoryScanResult> {
    pids.iter()
        .map(|&pid| scan_process_memory(yara, pid, mode))
        .collect()
}

/// List PIDs of all running processes (reads /proc).
pub fn list_all_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

/// Identify suspicious processes worth memory-scanning.
///
/// Returns PIDs of processes that show signs of fileless malware:
/// - Executable deleted from disk (exe path contains " (deleted)")
/// - Anonymous executable regions (rwx with no file backing)
/// - memfd-based execution (memfd: in maps)
pub fn find_suspicious_pids() -> io::Result<Vec<u32>> {
    let mut suspicious = Vec::new();

    for pid in list_all_pids()? {
        if is_suspicious_process(pid) {
            suspicious.push(pid);
        }
    }

    Ok(suspicious)
}

fn is_suspicious_process(pid: u32) -> bool {
    // Check if exe is deleted
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(target) = fs::read_link(&exe_path) {
        let target_str = target.to_string_lossy();
        if target_str.contains(" (deleted)") {
            return true;
        }
    }

    // Check for memfd or anonymous executable regions
    let maps_path = format!("/proc/{}/maps", pid);
    if let Ok(content) = fs::read_to_string(&maps_path) {
        for line in content.lines() {
            // rwxp anonymous region — possible shellcode injection
            if line.contains("rwxp") && !line.contains('/') {
                return true;
            }
            // memfd-based execution
            if line.contains("memfd:") {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests;
