//! Windows process identities use Unix-epoch nanoseconds, not boot time.

pub(crate) fn filetime_to_unix_ns(time: u64) -> Option<u64> {
    time.checked_sub(116_444_736_000_000_000)?.checked_mul(100)
}

/// Query creation time without requesting VM access. Failure is not identity evidence.
pub fn process_start_ns(pid: u32) -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::{CloseHandle, FILETIME};
        use windows::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut creation = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            let result = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
            let _ = CloseHandle(handle);
            result.ok()?;
            // An exited process may remain queryable while another owner holds a handle.
            if exit.dwHighDateTime != 0 || exit.dwLowDateTime != 0 {
                return None;
            }
            filetime_to_unix_ns(
                ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64,
            )
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        None
    }
}
