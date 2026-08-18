//! Read-only removable-media path classification.

/// Windows `GetDriveTypeW` value for removable media.
const DRIVE_REMOVABLE: u32 = 2;

#[cfg(test)]
fn is_removable_drive_type(drive_type: u32) -> bool {
    drive_type == DRIVE_REMOVABLE
}

/// Returns true only when `path` is rooted on a Windows removable drive.
#[cfg(target_os = "windows")]
pub fn is_removable_path(path: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;

    let bytes = path.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || !matches!(bytes[2], b'\\' | b'/') {
        return false;
    }
    let root = format!("{}:\\", &path[..1]);
    let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) == DRIVE_REMOVABLE }
}

/// Non-Windows platforms do not infer removable media from a file path.
#[cfg(not(target_os = "windows"))]
pub fn is_removable_path(_: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::is_removable_path;

    #[test]
    fn only_windows_removable_drive_type_is_accepted() {
        assert!(super::is_removable_drive_type(2));
        assert!(!super::is_removable_drive_type(0));
        assert!(!super::is_removable_drive_type(3));
        assert!(!super::is_removable_drive_type(4));
    }

    #[test]
    fn malformed_or_non_windows_paths_fail_closed() {
        assert!(!is_removable_path("relative.txt"));
        assert!(!is_removable_path("\\\\server\\share\\file.txt"));
        assert!(!is_removable_path("/tmp/file.txt"));
    }
}
