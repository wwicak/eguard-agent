//! Process introspection for macOS.
//!
//! Uses libproc FFI to query process metadata (exe path, cmdline, parent chain).

#[cfg(target_os = "macos")]
const MAX_PARENT_CHAIN_DEPTH: usize = 12;

#[cfg(target_os = "macos")]
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

#[cfg(target_os = "macos")]
extern "C" {
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_char, bufsize: u32) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

/// PROC_PIDTBSDINFO flavor constant for proc_pidinfo.
#[cfg(target_os = "macos")]
const PROC_PIDTBSDINFO: libc::c_int = 3;

/// BSD info structure returned by proc_pidinfo(PROC_PIDTBSDINFO).
///
/// Must match `struct proc_bsdinfo` from `<sys/proc_info.h>` (size = 136 bytes).
#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    _reserved: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[cfg(target_os = "macos")]
const _: () = assert!(
    std::mem::size_of::<ProcBsdInfo>() == 136,
    "ProcBsdInfo size must match proc_bsdinfo (136 bytes)"
);

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
    #[cfg(target_os = "macos")]
    {
        query_process_info_macos(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        ProcessInfo::default()
    }
}

/// Collect the parent chain (up to `MAX_PARENT_CHAIN_DEPTH` ancestors).
pub fn collect_parent_chain(pid: u32) -> Vec<u32> {
    #[cfg(target_os = "macos")]
    {
        collect_parent_chain_macos(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Read the parent PID.
pub fn read_ppid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        read_ppid_macos(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

// -- macOS implementations --------------------------------------------------

#[cfg(target_os = "macos")]
fn query_process_info_macos(pid: u32) -> ProcessInfo {
    let exe_path = query_exe_path(pid);
    let parent_chain = collect_parent_chain_macos(pid);
    let parent_name = parent_chain.first().and_then(|ppid| query_exe_path(*ppid));

    let command_line = query_cmdline(pid);

    ProcessInfo {
        exe_path,
        command_line,
        parent_name,
        parent_chain,
    }
}

#[cfg(target_os = "macos")]
fn query_exe_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let ret = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len() as u32,
        )
    };
    if ret <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buf[..ret as usize])
        .trim_end_matches('\0')
        .to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

#[cfg(target_os = "macos")]
fn query_cmdline(pid: u32) -> Option<String> {
    // Use sysctl(CTL_KERN, KERN_PROCARGS2) to get process arguments.
    let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;

    // First call to get the buffer size.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }

    // Buffer layout: [argc(4 bytes)][exec_path\0][padding\0...][arg0\0][arg1\0]...]
    if size < 4 {
        return None;
    }
    let argc = (u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize).min(4096);

    // Skip past the exec_path and its null padding.
    let mut pos = 4;
    // Skip exec path.
    while pos < size && buf[pos] != 0 {
        pos += 1;
    }
    // Skip null bytes after exec path.
    while pos < size && buf[pos] == 0 {
        pos += 1;
    }

    // Collect argc arguments.
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if pos >= size {
            break;
        }
        let start = pos;
        while pos < size && buf[pos] != 0 {
            pos += 1;
        }
        let arg = String::from_utf8_lossy(&buf[start..pos]).to_string();
        args.push(arg);
        pos += 1; // skip null
    }

    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

#[cfg(target_os = "macos")]
fn collect_parent_chain_macos(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut current = pid;
    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(ppid) = read_ppid_macos(current) else {
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

#[cfg(target_os = "macos")]
fn read_ppid_macos(pid: u32) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    let ret = unsafe {
        proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut libc::c_void,
            std::mem::size_of::<ProcBsdInfo>() as libc::c_int,
        )
    };
    if ret <= 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some(info.pbi_ppid)
}

#[cfg(test)]
mod tests {
    use super::ProcessInfo;

    #[test]
    fn process_info_default_fields_are_none() {
        let info = ProcessInfo::default();
        assert!(info.exe_path.is_none());
        assert!(info.command_line.is_none());
        assert!(info.parent_name.is_none());
        assert!(info.parent_chain.is_empty());
    }
}
