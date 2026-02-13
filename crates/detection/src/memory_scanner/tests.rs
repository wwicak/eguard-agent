use super::*;

#[test]
fn test_parse_maps_content() {
    let content = "\
55a1b2c3d000-55a1b2c4e000 r--p 00000000 fd:01 12345 /usr/bin/bash
55a1b2c4e000-55a1b2d1f000 r-xp 00011000 fd:01 12345 /usr/bin/bash
55a1b2d1f000-55a1b2d56000 r--p 000e2000 fd:01 12345 /usr/bin/bash
7f1234560000-7f1234570000 rw-p 00000000 00:00 0
7fff12345000-7fff12366000 rw-p 00000000 00:00 0 [stack]
7fff12367000-7fff1236b000 r--p 00000000 00:00 0 [vvar]
7fff1236b000-7fff1236d000 r-xp 00000000 00:00 0 [vdso]
";

    let regions = parse_maps_content(content);
    assert_eq!(regions.len(), 7);

    assert_eq!(regions[0].start, 0x55a1b2c3d000);
    assert_eq!(regions[0].end, 0x55a1b2c4e000);
    assert_eq!(regions[0].perms, "r--p");
    assert_eq!(regions[0].path, "/usr/bin/bash");
    assert!(regions[0].is_readable());
    assert!(!regions[0].is_executable());
    assert!(regions[0].is_file_backed());

    assert_eq!(regions[1].perms, "r-xp");
    assert!(regions[1].is_executable());

    assert_eq!(regions[3].path, "");
    assert!(!regions[3].is_file_backed());

    assert_eq!(regions[4].path, "[stack]");
    assert!(!regions[4].is_file_backed());
}

#[test]
fn test_filter_regions_executable_only() {
    let regions = vec![
        MemoryRegion {
            start: 0x1000,
            end: 0x1000 + 0x10000,
            perms: "r-xp".to_string(),
            path: "/bin/bash".to_string(),
        },
        MemoryRegion {
            start: 0x20000,
            end: 0x20000 + 0x10000,
            perms: "rw-p".to_string(),
            path: "".to_string(),
        },
        MemoryRegion {
            start: 0x30000,
            end: 0x30000 + 0x10000,
            perms: "r--p".to_string(),
            path: "/bin/bash".to_string(),
        },
    ];

    let filtered = filter_regions(&regions, ScanMode::ExecutableOnly);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].perms, "r-xp");
}

#[test]
fn test_filter_regions_executable_and_anonymous() {
    let regions = vec![
        MemoryRegion {
            start: 0x1000,
            end: 0x1000 + 0x10000,
            perms: "r-xp".to_string(),
            path: "/bin/bash".to_string(),
        },
        MemoryRegion {
            start: 0x20000,
            end: 0x20000 + 0x10000,
            perms: "rw-p".to_string(),
            path: "".to_string(),
        },
        MemoryRegion {
            start: 0x30000,
            end: 0x30000 + 0x10000,
            perms: "rw-p".to_string(),
            path: "/lib/libc.so".to_string(),
        },
    ];

    let filtered = filter_regions(&regions, ScanMode::ExecutableAndAnonymous);
    assert_eq!(filtered.len(), 2);
    assert_eq!(filtered[0].perms, "r-xp");
    assert_eq!(filtered[1].perms, "rw-p");
    assert!(filtered[1].path.is_empty());
}

#[test]
fn test_skip_special_regions() {
    let regions = vec![
        MemoryRegion {
            start: 0x1000,
            end: 0x1000 + 0x10000,
            perms: "r-xp".to_string(),
            path: "[vdso]".to_string(),
        },
        MemoryRegion {
            start: 0x2000,
            end: 0x2000 + 0x10000,
            perms: "r--p".to_string(),
            path: "[vvar]".to_string(),
        },
        MemoryRegion {
            start: 0x3000,
            end: 0x3000 + 0x10000,
            perms: "r-xp".to_string(),
            path: "/bin/bash".to_string(),
        },
    ];

    let filtered = filter_regions(&regions, ScanMode::AllReadable);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].path, "/bin/bash");
}

#[test]
fn test_skip_tiny_regions() {
    let regions = vec![MemoryRegion {
        start: 0x1000,
        end: 0x1000 + 100, // only 100 bytes
        perms: "r-xp".to_string(),
        path: "/bin/bash".to_string(),
    }];

    let filtered = filter_regions(&regions, ScanMode::AllReadable);
    assert_eq!(filtered.len(), 0);
}

#[test]
fn test_region_size() {
    let r = MemoryRegion {
        start: 0x1000,
        end: 0x2000,
        perms: "r-xp".to_string(),
        path: "".to_string(),
    };
    assert_eq!(r.size(), 0x1000);
}

#[test]
fn test_find_suspicious_self() {
    // Our own process should NOT be suspicious
    let pid = std::process::id();
    assert!(!is_suspicious_process(pid));
}
