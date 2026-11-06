use std::{
    fs::{File, Metadata},
    time::SystemTime,
};

#[derive(Debug, Hash, PartialEq, Eq)]
pub(super) struct FileKey {
    path: String,
    identity: (u64, u64),
    size: u64,
    modified: SystemTime,
    changed: (i64, i64),
}
impl FileKey {
    pub(super) fn new(path: &str, file: &File, metadata: &Metadata) -> Option<Self> {
        #[cfg(unix)]
        let (identity, changed) = {
            use std::os::unix::fs::MetadataExt;
            (
                (metadata.dev(), metadata.ino()),
                (metadata.ctime(), metadata.ctime_nsec()),
            )
        };
        #[cfg(windows)]
        let (identity, changed) = (windows_identity(file)?, (0, 0));
        #[cfg(not(any(unix, windows)))]
        return None;
        let _ = file;
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
    Some((
        u64::from(info.volume),
        (u64::from(info.index_high) << 32) | u64::from(info.index_low),
    ))
}
