use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct KernelIntegrityScanOptions {
    pub proc_modules_path: PathBuf,
    pub sys_module_path: PathBuf,
    pub kprobe_events_path: PathBuf,
    pub current_tracer_path: PathBuf,
    pub ftrace_filter_path: PathBuf,
    pub lsm_list_path: PathBuf,
    pub bpffs_root: PathBuf,
}

impl Default for KernelIntegrityScanOptions {
    fn default() -> Self {
        Self {
            proc_modules_path: PathBuf::from("/proc/modules"),
            sys_module_path: PathBuf::from("/sys/module"),
            kprobe_events_path: resolve_tracefs_path("kprobe_events"),
            current_tracer_path: resolve_tracefs_path("current_tracer"),
            ftrace_filter_path: resolve_tracefs_path("set_ftrace_filter"),
            lsm_list_path: PathBuf::from("/sys/kernel/security/lsm"),
            bpffs_root: PathBuf::from("/sys/fs/bpf"),
        }
    }
}

impl KernelIntegrityScanOptions {
    pub fn from_env() -> Self {
        let mut opts = Self::default();
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_PROC_MODULES_PATH") {
            if !path.trim().is_empty() {
                opts.proc_modules_path = PathBuf::from(path);
            }
        }
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_SYS_MODULES_PATH") {
            if !path.trim().is_empty() {
                opts.sys_module_path = PathBuf::from(path);
            }
        }
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_KPROBE_EVENTS_PATH") {
            if !path.trim().is_empty() {
                opts.kprobe_events_path = PathBuf::from(path);
            }
        }
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_TRACER_PATH") {
            if !path.trim().is_empty() {
                opts.current_tracer_path = PathBuf::from(path);
            }
        }
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_FTRACE_FILTER_PATH") {
            if !path.trim().is_empty() {
                opts.ftrace_filter_path = PathBuf::from(path);
            }
        }
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_LSM_PATH") {
            if !path.trim().is_empty() {
                opts.lsm_list_path = PathBuf::from(path);
            }
        }
        if let Ok(path) = std::env::var("EGUARD_KERNEL_INTEGRITY_BPF_FS_PATH") {
            if !path.trim().is_empty() {
                opts.bpffs_root = PathBuf::from(path);
            }
        }
        opts
    }
}

#[derive(Debug, Clone, Default)]
pub struct KernelIntegrityReport {
    pub indicators: Vec<String>,
    pub proc_module_count: usize,
    pub sysfs_module_count: usize,
    pub kprobe_count: usize,
    pub ftrace_filter_count: usize,
    pub current_tracer: Option<String>,
    pub bpffs_objects: Vec<String>,
    pub lsm_list: Vec<String>,
}

impl KernelIntegrityReport {
    pub fn command_line(&self) -> String {
        let indicators = if self.indicators.is_empty() {
            "none".to_string()
        } else {
            self.indicators.join(",")
        };
        let tracer = self
            .current_tracer
            .clone()
            .unwrap_or_else(|| "nop".to_string());
        let lsm = if self.lsm_list.is_empty() {
            "none".to_string()
        } else {
            self.lsm_list.join(",")
        };
        format!(
            "indicators={}; proc_modules={}; sys_modules={}; kprobe_count={}; ftrace_filter_count={}; ftrace_tracer={}; lsm_list={}; bpffs_count={}",
            indicators,
            self.proc_module_count,
            self.sysfs_module_count,
            self.kprobe_count,
            self.ftrace_filter_count,
            tracer,
            lsm,
            self.bpffs_objects.len(),
        )
    }
}

pub fn scan_kernel_integrity(
    opts: &KernelIntegrityScanOptions,
) -> io::Result<KernelIntegrityReport> {
    let proc_modules = read_proc_modules(&opts.proc_modules_path)?;
    let sys_modules = read_sys_modules(&opts.sys_module_path)?;

    let proc_set: HashSet<String> = proc_modules.iter().cloned().collect();
    let sys_set: HashSet<String> = sys_modules.iter().cloned().collect();

    let mut report = KernelIntegrityReport {
        proc_module_count: proc_modules.len(),
        sysfs_module_count: sys_modules.len(),
        ..KernelIntegrityReport::default()
    };

    for name in sys_set.difference(&proc_set) {
        // Built-in kernel modules appear in /sys/module/ but never in
        // /proc/modules.  They lack an `initstate` file, unlike loaded
        // modules which have `initstate = "live"`.  Flagging built-ins
        // as "hidden" produces hundreds of false positives on VPS and
        // cloud hosts where many subsystems are compiled-in.
        let initstate_path = opts.sys_module_path.join(name).join("initstate");
        if !initstate_path.exists() {
            continue;
        }
        report
            .indicators
            .push(format!("hidden_module_sysfs:{}", name));
    }

    for name in proc_set.difference(&sys_set) {
        report
            .indicators
            .push(format!("hidden_module_proc:{}", name));
    }

    for module in &sys_modules {
        let taint_path = opts.sys_module_path.join(module).join("taint");
        if let Some(taint) = read_numeric(&taint_path) {
            if taint > 0 {
                report
                    .indicators
                    .push(format!("tainted_module:{}:{}", module, taint));
                let signer_path = opts.sys_module_path.join(module).join("signer");
                if let Some(signer) = read_trimmed(&signer_path) {
                    if signer.is_empty() {
                        report
                            .indicators
                            .push(format!("unsigned_module:{}", module));
                    }
                }
            }
        }
    }

    if let Ok(contents) = fs::read_to_string(&opts.kprobe_events_path) {
        let mut count = 0usize;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            count += 1;
            if let Some(symbol) = extract_probe_symbol(trimmed) {
                if is_sensitive_symbol(&symbol) {
                    report.indicators.push(format!("kprobe_hook:{}", symbol));
                }
            }
        }
        if count > 0 {
            report.kprobe_count = count;
            report
                .indicators
                .push(format!("kprobe_hook_count:{}", count));
        }
    }

    if let Some(tracer) = read_trimmed(&opts.current_tracer_path) {
        if !tracer.is_empty() && tracer != "nop" {
            report.current_tracer = Some(tracer.clone());
            report.indicators.push(format!("ftrace_tracer:{}", tracer));
        }
    }

    if let Ok(contents) = fs::read_to_string(&opts.ftrace_filter_path) {
        let count = contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .count();
        if count > 0 {
            report.ftrace_filter_count = count;
            report
                .indicators
                .push(format!("ftrace_filter_count:{}", count));
        }
    }

    if let Some(lsm_raw) = read_trimmed(&opts.lsm_list_path) {
        let list = lsm_raw
            .split([',', ' '])
            .filter_map(|val| {
                let trimmed = val.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect::<Vec<_>>();
        if !list.is_empty() {
            report.lsm_list = list.clone();
            if list.iter().any(|entry| entry == "bpf") {
                report.indicators.push("lsm_bpf_enabled".to_string());
            }
        }
    }

    if let Ok(entries) = fs::read_dir(&opts.bpffs_root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() || name == "eguard" {
                continue;
            }
            report.bpffs_objects.push(name.clone());
            report
                .indicators
                .push(format!("bpffs_pinned_object:{}", name));
        }
    }

    Ok(report)
}

fn resolve_tracefs_path(file: &str) -> PathBuf {
    let tracefs = Path::new("/sys/kernel/tracing").join(file);
    if tracefs.exists() {
        return tracefs;
    }
    Path::new("/sys/kernel/debug/tracing").join(file)
}

fn read_proc_modules(path: &Path) -> io::Result<Vec<String>> {
    let contents = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, _rest)) = trimmed.split_once(' ') {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

fn read_sys_modules(path: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    Ok(out)
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|val| val.trim().to_string())
}

fn read_numeric(path: &Path) -> Option<u64> {
    read_trimmed(path).and_then(|value| value.parse::<u64>().ok())
}

fn extract_probe_symbol(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    parts.last().map(|val| val.to_string())
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    symbol.starts_with("__x64_sys_")
        || symbol.starts_with("__arm64_sys_")
        || symbol.starts_with("sys_")
        || symbol.starts_with("security_")
        || symbol.contains("sys_call_table")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn kernel_integrity_scan_detects_hidden_modules_and_hooks() {
        let root = temp_dir("kernel-integrity-test");
        let proc_modules = root.join("proc_modules");
        let sys_modules = root.join("sys_module");
        let tracefs = root.join("tracefs");
        let bpffs = root.join("bpffs");
        let lsm_path = root.join("lsm");

        std::fs::create_dir_all(&sys_modules).expect("create sys module dir");
        std::fs::create_dir_all(&tracefs).expect("create tracefs");
        std::fs::create_dir_all(&bpffs).expect("create bpffs");

        std::fs::write(&proc_modules, "good 0 0 - Live 0\nproc_only 0 0 - Live 0\n")
            .expect("write proc modules");
        std::fs::create_dir_all(sys_modules.join("good")).expect("create good module");
        std::fs::create_dir_all(sys_modules.join("sys_only")).expect("create sys module");
        // Simulate a loaded (not built-in) module by creating an
        // initstate file.  Built-in modules lack this file.
        std::fs::write(sys_modules.join("sys_only").join("initstate"), "live")
            .expect("write initstate");
        std::fs::write(sys_modules.join("sys_only").join("taint"), "1").expect("write taint");
        std::fs::write(sys_modules.join("sys_only").join("signer"), "").expect("write signer");

        std::fs::write(
            tracefs.join("kprobe_events"),
            "p:kprobes/evil __x64_sys_execve\n",
        )
        .expect("write kprobe events");
        std::fs::write(tracefs.join("current_tracer"), "function").expect("write tracer");
        std::fs::write(tracefs.join("set_ftrace_filter"), "sys_execve\n")
            .expect("write ftrace filter");

        std::fs::write(&lsm_path, "selinux,bpf").expect("write lsm list");

        std::fs::create_dir_all(bpffs.join("evil_prog")).expect("create bpffs entry");

        let report = scan_kernel_integrity(&KernelIntegrityScanOptions {
            proc_modules_path: proc_modules,
            sys_module_path: sys_modules,
            kprobe_events_path: tracefs.join("kprobe_events"),
            current_tracer_path: tracefs.join("current_tracer"),
            ftrace_filter_path: tracefs.join("set_ftrace_filter"),
            lsm_list_path: lsm_path,
            bpffs_root: bpffs,
        })
        .expect("scan");

        let indicators = report.indicators.join("|");
        assert!(indicators.contains("hidden_module_sysfs:sys_only"));
        assert!(indicators.contains("hidden_module_proc:proc_only"));
        assert!(indicators.contains("tainted_module:sys_only"));
        assert!(indicators.contains("unsigned_module:sys_only"));
        assert!(indicators.contains("kprobe_hook_count:1"));
        assert!(indicators.contains("kprobe_hook:__x64_sys_execve"));
        assert!(indicators.contains("ftrace_tracer:function"));
        assert!(indicators.contains("ftrace_filter_count:1"));
        assert!(indicators.contains("lsm_bpf_enabled"));
        assert!(indicators.contains("bpffs_pinned_object:evil_prog"));
    }
}
