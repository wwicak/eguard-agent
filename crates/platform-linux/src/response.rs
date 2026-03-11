use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_PROCESS_ROWS: usize = 512;
const DEFAULT_MAX_NETWORK_ROWS: usize = 512;
const DEFAULT_MAX_OPEN_FILE_ROWS: usize = 1_024;
const DEFAULT_MAX_OPEN_FILE_PIDS: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForensicsSnapshot {
    pub processes: String,
    pub network: String,
    pub open_files: String,
    pub loaded_modules: String,
}

#[derive(Debug, Clone)]
pub struct ForensicsCollector {
    proc_root: PathBuf,
    proc_modules_path: PathBuf,
    max_process_rows: usize,
    max_network_rows: usize,
    max_open_file_rows: usize,
    max_open_file_pids: usize,
}

impl Default for ForensicsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsCollector {
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            proc_modules_path: PathBuf::from("/proc/modules"),
            max_process_rows: DEFAULT_MAX_PROCESS_ROWS,
            max_network_rows: DEFAULT_MAX_NETWORK_ROWS,
            max_open_file_rows: DEFAULT_MAX_OPEN_FILE_ROWS,
            max_open_file_pids: DEFAULT_MAX_OPEN_FILE_PIDS,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_paths(proc_root: PathBuf, proc_modules_path: PathBuf) -> Self {
        Self {
            proc_root,
            proc_modules_path,
            ..Self::new()
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(
        mut self,
        max_process_rows: usize,
        max_network_rows: usize,
        max_open_file_rows: usize,
        max_open_file_pids: usize,
    ) -> Self {
        self.max_process_rows = max_process_rows.max(1);
        self.max_network_rows = max_network_rows.max(1);
        self.max_open_file_rows = max_open_file_rows.max(1);
        self.max_open_file_pids = max_open_file_pids.max(1);
        self
    }

    pub fn collect_full_snapshot(
        &self,
        include_processes: bool,
        include_network: bool,
        include_open_files: bool,
        include_loaded_modules: bool,
    ) -> ForensicsSnapshot {
        ForensicsSnapshot {
            processes: if include_processes {
                self.collect_processes()
            } else {
                String::new()
            },
            network: if include_network {
                self.collect_network()
            } else {
                String::new()
            },
            open_files: if include_open_files {
                self.collect_open_files()
            } else {
                String::new()
            },
            loaded_modules: if include_loaded_modules {
                self.collect_loaded_modules()
            } else {
                String::new()
            },
        }
    }

    fn collect_processes(&self) -> String {
        let process_ids = self.list_process_ids();
        if process_ids.is_empty() {
            return "no active processes captured".to_string();
        }

        let mut rows = Vec::new();
        for pid in process_ids.iter().copied().take(self.max_process_rows) {
            rows.push(self.collect_process_row(pid));
        }

        if process_ids.len() > self.max_process_rows {
            rows.push(format!(
                "... truncated {} additional processes",
                process_ids.len().saturating_sub(self.max_process_rows)
            ));
        }

        rows.join("\n")
    }

    fn collect_process_row(&self, pid: u32) -> String {
        let pid_root = self.proc_root.join(pid.to_string());
        let status_path = pid_root.join("status");
        let comm = read_status_field(&status_path, "Name")
            .or_else(|| read_trimmed(pid_root.join("comm")))
            .unwrap_or_else(|| "<unknown>".to_string());
        let ppid = read_status_field(&status_path, "PPid").unwrap_or_else(|| "?".to_string());
        let uid = read_status_field(&status_path, "Uid")
            .and_then(|raw| raw.split_whitespace().next().map(|value| value.to_string()))
            .unwrap_or_else(|| "?".to_string());
        let exe = fs::read_link(pid_root.join("exe"))
            .ok()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cmdline = read_cmdline(pid_root.join("cmdline")).unwrap_or_default();

        format!(
            "pid={pid} ppid={ppid} uid={uid} comm={comm} exe={} cmdline={}",
            display_or_dash(&exe),
            display_or_dash(&cmdline),
        )
    }

    fn collect_network(&self) -> String {
        let mut rows = Vec::new();
        for (proto, family, path) in self.network_tables() {
            let Ok(contents) = fs::read_to_string(path) else {
                continue;
            };
            for line in contents.lines().skip(1) {
                if rows.len() >= self.max_network_rows {
                    break;
                }
                if let Some(row) = parse_network_row(proto, family, line) {
                    rows.push(row);
                }
            }
            if rows.len() >= self.max_network_rows {
                break;
            }
        }

        if rows.is_empty() {
            return "no active sockets captured".to_string();
        }

        if rows.len() == self.max_network_rows {
            rows.push("... truncated additional sockets".to_string());
        }

        rows.join("\n")
    }

    fn collect_open_files(&self) -> String {
        let process_ids = self.list_process_ids();
        if process_ids.is_empty() {
            return "no open files captured".to_string();
        }

        let mut rows = Vec::new();
        let mut scanned_processes = 0usize;
        for pid in process_ids {
            if scanned_processes >= self.max_open_file_pids || rows.len() >= self.max_open_file_rows
            {
                break;
            }

            let fd_dir = self.proc_root.join(pid.to_string()).join("fd");
            let Ok(entries) = fs::read_dir(&fd_dir) else {
                continue;
            };

            scanned_processes = scanned_processes.saturating_add(1);
            let comm = read_trimmed(self.proc_root.join(pid.to_string()).join("comm"))
                .unwrap_or_else(|| "<unknown>".to_string());

            for entry in entries.flatten() {
                if rows.len() >= self.max_open_file_rows {
                    break;
                }

                let fd = entry.file_name().to_string_lossy().into_owned();
                let target = fs::read_link(entry.path())
                    .ok()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "<unreadable>".to_string());
                rows.push(format!(
                    "pid={pid} comm={comm} fd={fd} target={}",
                    display_or_dash(&target)
                ));
            }
        }

        if rows.is_empty() {
            return "no open files captured".to_string();
        }

        if rows.len() == self.max_open_file_rows {
            rows.push("... truncated additional open files".to_string());
        } else if scanned_processes == self.max_open_file_pids {
            rows.push("... truncated additional processes while scanning open files".to_string());
        }

        rows.join("\n")
    }

    fn collect_loaded_modules(&self) -> String {
        match fs::read_to_string(&self.proc_modules_path) {
            Ok(contents) if !contents.trim().is_empty() => contents.trim_end().to_string(),
            Ok(_) => "no kernel modules captured".to_string(),
            Err(err) => format!(
                "failed reading {}: {}",
                self.proc_modules_path.display(),
                err
            ),
        }
    }

    fn list_process_ids(&self) -> Vec<u32> {
        let Ok(entries) = fs::read_dir(&self.proc_root) else {
            return Vec::new();
        };

        let mut pids = entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .collect::<Vec<_>>();
        pids.sort_unstable();
        pids
    }

    fn network_tables(&self) -> [(&'static str, NetworkFamily, PathBuf); 4] {
        [
            ("tcp", NetworkFamily::V4, self.proc_root.join("net/tcp")),
            ("tcp6", NetworkFamily::V6, self.proc_root.join("net/tcp6")),
            ("udp", NetworkFamily::V4, self.proc_root.join("net/udp")),
            ("udp6", NetworkFamily::V6, self.proc_root.join("net/udp6")),
        ]
    }
}

#[derive(Debug, Clone, Copy)]
enum NetworkFamily {
    V4,
    V6,
}

fn parse_network_row(proto: &str, family: NetworkFamily, line: &str) -> Option<String> {
    let columns = line.split_whitespace().collect::<Vec<_>>();
    if columns.len() < 10 {
        return None;
    }

    let local = decode_proc_net_endpoint(columns[1], family);
    let remote = decode_proc_net_endpoint(columns[2], family);
    let state = if proto.starts_with("tcp") {
        decode_tcp_state(columns[3])
    } else {
        "UNCONN"
    };
    let uid = columns[7];
    let inode = columns[9];

    Some(format!(
        "proto={proto} local={local} remote={remote} state={state} uid={uid} inode={inode}"
    ))
}

fn decode_proc_net_endpoint(raw: &str, family: NetworkFamily) -> String {
    let Some((address_hex, port_hex)) = raw.split_once(':') else {
        return raw.to_string();
    };

    let port = u16::from_str_radix(port_hex, 16).unwrap_or_default();
    match family {
        NetworkFamily::V4 => {
            let address = decode_ipv4(address_hex).unwrap_or_else(|| address_hex.to_string());
            format!("{address}:{port}")
        }
        NetworkFamily::V6 => {
            let address = decode_ipv6(address_hex).unwrap_or_else(|| address_hex.to_string());
            format!("[{address}]:{port}")
        }
    }
}

fn decode_ipv4(raw: &str) -> Option<String> {
    if raw.len() != 8 {
        return None;
    }

    let octets = (0..4)
        .map(|idx| u8::from_str_radix(&raw[idx * 2..idx * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "{}.{}.{}.{}",
        octets[3], octets[2], octets[1], octets[0]
    ))
}

fn decode_ipv6(raw: &str) -> Option<String> {
    if raw.len() != 32 {
        return None;
    }

    let groups = raw
        .as_bytes()
        .chunks(4)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .ok()
                .map(|value| value.to_ascii_lowercase())
        })
        .collect::<Option<Vec<_>>>()?;
    Some(groups.join(":"))
}

fn decode_tcp_state(raw: &str) -> &'static str {
    match raw {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn read_status_field(path: &Path, field: &str) -> Option<String> {
    let prefix = format!("{field}:");
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix(&prefix)
            .map(|value| value.trim().to_string())
    })
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_cmdline(path: PathBuf) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let parts = bytes
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8_lossy(segment).to_string())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn display_or_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}
