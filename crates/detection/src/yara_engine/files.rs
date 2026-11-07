#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::{fs::File, io, path::Path};

pub(super) fn is_executable(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ]
        .iter()
        .any(|magic| bytes.starts_with(magic))
}

#[cfg(unix)]
pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd},
        path::Component,
    };
    // Walk relative to held directory handles: no parent-component symlink race,
    // including on Linux 5.4 where openat2 is unavailable.
    let mut directory = File::open(if path.is_absolute() { "/" } else { "." })?;
    let parts: Vec<_> = path
        .components()
        .filter(|part| !matches!(part, Component::RootDir | Component::CurDir))
        .collect();
    for (index, part) in parts.iter().enumerate() {
        use std::os::unix::ffi::OsStrExt;
        let name = match part {
            Component::Normal(name) => name.as_bytes(),
            Component::ParentDir => b"..",
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: directory is live, name is NUL-terminated and openat returns a new owned fd.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    if parts.is_empty() || !directory.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(directory)
}

#[cfg(windows)]
pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
    };
    const REPARSE: u32 = 0x400;
    let original = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut prefix = std::path::PathBuf::new();
    for part in original.components() {
        prefix.push(part);
        if matches!(part, std::path::Component::Prefix(_)) {
            continue;
        }
        if std::fs::symlink_metadata(&prefix)?.file_attributes() & REPARSE != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    let mut normalized = std::path::PathBuf::new();
    for part in original.components() {
        match part {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => normalized.push(part),
        }
    }
    let path = normalized.as_path();
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1 | 2 | 4)
        .custom_flags(0x00200000)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & REPARSE != 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFinalPathNameByHandleW(
            handle: *mut c_void,
            path: *mut u16,
            size: u32,
            flags: u32,
        ) -> u32;
        fn GetLongPathNameW(short: *const u16, long: *mut u16, size: u32) -> u32;
    }
    let mut resolved = vec![0u16; 32768];
    // SAFETY: live file handle and writable UTF-16 buffer with its exact capacity.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            resolved.as_mut_ptr(),
            resolved.len() as u32,
            0,
        )
    } as usize;
    if len == 0 || len >= resolved.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let resolved = String::from_utf16_lossy(&resolved[..len]);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let original: Vec<u16> = absolute
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut long = vec![0u16; 32768];
    // Expand DOS 8.3 aliases without canonicalizing junction targets.
    let long_len =
        unsafe { GetLongPathNameW(original.as_ptr(), long.as_mut_ptr(), long.len() as u32) }
            as usize;
    if long_len == 0 || long_len >= long.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let absolute = String::from_utf16_lossy(&long[..long_len]);
    fn spelling(value: &str) -> String {
        let value = value
            .strip_prefix(r"\\?\UNC\")
            .map(|s| format!(r"\\{s}"))
            .unwrap_or_else(|| value.strip_prefix(r"\\?\").unwrap_or(value).to_string());
        value.replace('/', "\\").to_lowercase()
    }
    // Reject a junction substituted between component checks and the final open.
    if spelling(&resolved) != spelling(&absolute) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    OpenOptions::new().read(true).open(path)
}
