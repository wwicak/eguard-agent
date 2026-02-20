//! Process introspection via NtQueryInformationProcess / ToolHelp32.
//!
//! On non-Windows builds, returns empty stubs so the crate compiles.

const MAX_PARENT_CHAIN_DEPTH: usize = 12;

/// Collected process metadata.
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_name: Option<String>,
    pub parent_chain: Vec<u32>,
}

/// Query process information for the given PID.
pub fn query_process_info(pid: u32) -> ProcessInfo {
    #[cfg(target_os = "windows")]
    {
        query_process_info_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        tracing::warn!(pid, "query_process_info is a stub on non-Windows");
        ProcessInfo::default()
    }
}

/// Collect the parent chain (up to `MAX_PARENT_CHAIN_DEPTH` ancestors).
pub fn collect_parent_chain(pid: u32) -> Vec<u32> {
    #[cfg(target_os = "windows")]
    {
        collect_parent_chain_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Read the parent PID using ToolHelp32 snapshot.
pub fn read_ppid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        read_ppid_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        None
    }
}

// ── Windows implementations ────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn query_process_info_windows(pid: u32) -> ProcessInfo {
    // TODO: OpenProcess + NtQueryInformationProcess / QueryFullProcessImageNameW
    // TODO: read PEB for command line
    let parent_chain = collect_parent_chain_windows(pid);
    let parent_name = parent_chain.first().and_then(|ppid| {
        // TODO: resolve parent name
        let _ = ppid;
        None
    });

    ProcessInfo {
        exe_path: None,
        command_line: None,
        parent_name,
        parent_chain,
    }
}

#[cfg(target_os = "windows")]
fn collect_parent_chain_windows(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut current = pid;
    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(ppid) = read_ppid_windows(current) else {
            break;
        };
        if ppid == 0 || ppid == current {
            break;
        }
        out.push(ppid);
        current = ppid;
    }
    out
}

#[cfg(target_os = "windows")]
fn read_ppid_windows(pid: u32) -> Option<u32> {
    // TODO: CreateToolhelp32Snapshot + Process32First/Next
    let _ = pid;
    None
}
