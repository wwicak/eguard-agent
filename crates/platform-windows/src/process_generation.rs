//! Windows process identities use Unix-epoch nanoseconds, not boot time.

pub(crate) fn filetime_to_unix_ns(time: u64) -> Option<u64> {
    time.checked_sub(116_444_736_000_000_000)?.checked_mul(100)
}

/// Capture our creation time at startup using the always-valid pseudo handle.
pub fn current_process_start_ns() -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: current-process pseudo handle and valid output pointers;
        // pseudo handles must not be closed.
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
            .ok()?;
        }
        filetime_to_unix_ns(
            ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64,
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// Query creation time without requesting VM access. Failure is not identity evidence.
pub fn process_start_ns(pid: u32) -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::{CloseHandle, FILETIME, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        };
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
            .ok()?;
            let mut creation = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            let result = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
            // A process handle is signaled on exit. lpExitTime is undefined while live.
            let live = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
            let _ = CloseHandle(handle);
            result.ok()?;
            live_creation_time(
                live,
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

#[cfg(any(target_os = "windows", test))]
fn live_creation_time(live: bool, creation: u64) -> Option<u64> {
    live.then(|| filetime_to_unix_ns(creation)).flatten()
}

#[test]
fn process_liveness_is_wait_state_not_undefined_exit_time() {
    let creation = 116_444_736_123_456_789;
    // A live process has undefined exit FILETIME; only its wait state matters.
    assert_eq!(live_creation_time(true, creation), Some(12_345_678_900));
    // Retained handles for exited processes must never authenticate a PID.
    assert_eq!(live_creation_time(false, creation), None);
}
