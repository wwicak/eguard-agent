use std::{
    fs::{File, Metadata},
    time::SystemTime,
};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct FileKey {
    pub(super) path: String,
    identity: (u64, u64),
    pub(super) size: u64,
    modified: SystemTime,
    pub(super) changed: (i64, i64),
}
impl FileKey {
    pub(super) fn cache_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.path.capacity()
    }
    pub(super) fn still_matches(&self, path: &str, file: &File) -> bool {
        file.metadata()
            .ok()
            .and_then(|metadata| Self::new(path, file, &metadata))
            .as_ref()
            == Some(self)
    }
    pub(super) fn new(path: &str, _file: &File, metadata: &Metadata) -> Option<Self> {
        #[cfg(unix)]
        return Self::from_metadata(path, metadata);
        #[cfg(windows)]
        let (identity, changed) = (
            windows_identity(_file)?,
            windows_change_time(_file).unwrap_or((0, 0)),
        );
        #[cfg(not(any(unix, windows)))]
        return None;
        #[cfg(windows)]
        Some(Self {
            path: path.to_string(),
            identity,
            size: metadata.len(),
            modified: metadata.modified().ok()?,
            changed,
        })
    }
    pub(super) fn mature_at(&self, read_start: SystemTime) -> bool {
        const TIMESTAMP_TRUST_MARGIN: std::time::Duration = std::time::Duration::from_secs(2);
        if !self.reliable_change_time() {
            return false;
        }
        #[cfg(unix)]
        let epoch_offset = 0;
        #[cfg(windows)]
        let epoch_offset = 11_644_473_600i64;
        #[cfg(not(any(unix, windows)))]
        let epoch_offset = 0;
        let Some(seconds) = self
            .changed
            .0
            .checked_sub(epoch_offset)
            .and_then(|s| u64::try_from(s).ok())
        else {
            return false;
        };
        let Some(nanos) = u32::try_from(self.changed.1)
            .ok()
            .filter(|n| *n < 1_000_000_000)
        else {
            return false;
        };
        let Some(changed) =
            SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(seconds, nanos))
        else {
            return false;
        };
        read_start
            .duration_since(changed)
            .is_ok_and(|age| age >= TIMESTAMP_TRUST_MARGIN)
    }
    pub(super) fn reliable_change_time(&self) -> bool {
        self.changed != (0, 0)
    }
    pub(super) fn at_path(path: &str) -> Option<Self> {
        #[cfg(unix)]
        {
            // Metadata-only admission still refuses symlinked parent components.
            let mut prefix = std::path::PathBuf::new();
            for part in std::path::Path::new(path).components() {
                prefix.push(part.as_os_str());
                if std::fs::symlink_metadata(&prefix)
                    .ok()?
                    .file_type()
                    .is_symlink()
                {
                    return None;
                }
            }
            let metadata = std::fs::symlink_metadata(path).ok()?;
            if !metadata.is_file() {
                return None;
            }
            Self::from_metadata(path, &metadata)
        }
        #[cfg(not(unix))]
        {
            let file = super::files::open_regular(std::path::Path::new(path)).ok()?;
            Self::new(path, &file, &file.metadata().ok()?)
        }
    }
    #[cfg(unix)]
    fn from_metadata(path: &str, metadata: &Metadata) -> Option<Self> {
        let (identity, changed) = {
            use std::os::unix::fs::MetadataExt;
            (
                (metadata.dev(), metadata.ino()),
                (metadata.ctime(), metadata.ctime_nsec()),
            )
        };
        Some(Self {
            path: path.to_string(),
            identity,
            size: metadata.len(),
            modified: metadata.modified().ok()?,
            changed,
        })
    }
}

#[cfg(windows)]
fn windows_identity(file: &File) -> Option<(u64, u64)> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle};
    // BY_HANDLE_FILE_INFORMATION consists of thirteen DWORDs, including FILETIMEs.
    #[repr(C)]
    #[derive(Default)]
    struct FileInformation {
        attributes: u32,
        creation: [u32; 2],
        access: [u32; 2],
        write: [u32; 2],
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInformation) -> i32;
    }
    let mut info = FileInformation::default();
    // SAFETY: the borrowed live File owns this handle and info has the documented layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    let index = (u64::from(info.index_high) << 32) | u64::from(info.index_low);
    if index == 0 {
        return None;
    }
    Some((u64::from(info.volume), index))
}

#[cfg(windows)]
fn windows_change_time(file: &File) -> Option<(i64, i64)> {
    use std::{ffi::c_void, os::windows::io::AsRawHandle};
    #[repr(C)]
    #[derive(Default)]
    struct BasicInfo {
        creation: i64,
        access: i64,
        write: i64,
        change: i64,
        attributes: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
    }
    let mut info = BasicInfo::default();
    // SAFETY: live borrowed handle and the documented FILE_BASIC_INFO layout/class (0).
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            0,
            (&mut info as *mut BasicInfo).cast(),
            std::mem::size_of::<BasicInfo>() as u32,
        )
    } == 0
        || info.change == 0
    {
        return None;
    }
    Some((info.change / 10_000_000, (info.change % 10_000_000) * 100))
}
