pub fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse().ok())
            })
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct Counters {
            cb: u32,
            faults: u32,
            peak: usize,
            working: usize,
            rest: [usize; 6],
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn K32GetProcessMemoryInfo(
                process: *mut std::ffi::c_void,
                counters: *mut Counters,
                size: u32,
            ) -> i32;
        }
        let mut counters = Counters {
            cb: std::mem::size_of::<Counters>() as u32,
            faults: 0,
            peak: 0,
            working: 0,
            rest: [0; 6],
        };
        // SAFETY: current-process pseudo-handle and documented repr(C) structure/size.
        let ok = unsafe {
            K32GetProcessMemoryInfo(
                -1isize as *mut std::ffi::c_void,
                &mut counters,
                std::mem::size_of::<Counters>() as u32,
            )
        };
        (ok != 0).then_some(counters.working as u64 / 1024)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

/// Harness only: calling-thread CPU, excluding scheduler preemption and other threads.
pub fn thread_cpu_ns() -> Option<u128> {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct Timespec {
            seconds: i64,
            nanoseconds: i64,
        }
        unsafe extern "C" {
            fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
        }
        let mut time = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        // SAFETY: Linux CLOCK_THREAD_CPUTIME_ID and writable native timespec.
        if unsafe { clock_gettime(3, &mut time) } != 0 {
            return None;
        }
        Some(time.seconds as u128 * 1_000_000_000 + time.nanoseconds as u128)
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default)]
        struct FileTime {
            low: u32,
            high: u32,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetThreadTimes(
                thread: *mut std::ffi::c_void,
                created: *mut FileTime,
                exited: *mut FileTime,
                kernel: *mut FileTime,
                user: *mut FileTime,
            ) -> i32;
        }
        let (mut created, mut exited, mut kernel, mut user) = (
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
        );
        // SAFETY: current-thread pseudo-handle and four writable FILETIMEs.
        if unsafe {
            GetThreadTimes(
                -2isize as *mut std::ffi::c_void,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return None;
        }
        let ticks = |time: FileTime| (u64::from(time.high) << 32) | u64::from(time.low);
        Some(u128::from(ticks(kernel) + ticks(user)) * 100)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}
