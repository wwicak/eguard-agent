use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle};
#[cfg(windows)]
use windows::Win32::Foundation::{
    RtlNtStatusToDosError, BOOLEAN, HANDLE, NTSTATUS, UNICODE_STRING,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    FileDispositionInfo, SetFileInformationByHandle, DELETE, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

#[cfg(windows)]
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const std::ffi::c_void,
    security_quality_of_service: *const std::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
struct IoStatusBlock {
    status_or_pointer: *mut std::ffi::c_void,
    information: usize,
}

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const std::ffi::c_void,
        ea_length: u32,
    ) -> i32;
}

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{ResponseError, ResponseResult};
use crate::{normalize_path, ProtectedList};

#[cfg(target_os = "linux")]
const DEFAULT_QUARANTINE_DIR: &str = "/var/lib/eguard-agent/quarantine";

#[cfg(target_os = "macos")]
const DEFAULT_QUARANTINE_DIR: &str = "/Library/Application Support/eGuard/quarantine";

#[cfg(target_os = "windows")]
const DEFAULT_QUARANTINE_DIR: &str = r"C:\ProgramData\eGuard\quarantine";

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const DEFAULT_QUARANTINE_DIR: &str = "/var/lib/eguard-agent/quarantine";

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct QuarantineReport {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub sha256: String,
    pub file_size: u64,
    pub original_mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub restored_path: PathBuf,
    pub source_quarantine_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineManifest {
    version: u32,
    sha256: String,
    original_path: PathBuf,
    file_size: u64,
    original_mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    quarantined_at: u64,
}

pub fn quarantine_file(
    path: &Path,
    sha256: &str,
    protected: &ProtectedList,
) -> ResponseResult<QuarantineReport> {
    let quarantine_dir = resolve_default_quarantine_dir();
    quarantine_file_with_dir(path, sha256, protected, &quarantine_dir)
}

fn resolve_default_quarantine_dir() -> PathBuf {
    #[cfg(any(test, feature = "test-quarantine-dir"))]
    if let Some(dir) = std::env::var_os("EGUARD_TEST_QUARANTINE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }

    PathBuf::from(DEFAULT_QUARANTINE_DIR)
}

pub fn quarantine_file_with_dir(
    path: &Path,
    sha256: &str,
    protected: &ProtectedList,
    quarantine_dir: &Path,
) -> ResponseResult<QuarantineReport> {
    if protected.is_protected_path(path) {
        return Err(ResponseError::ProtectedPath(path.to_path_buf()));
    }

    let requested_sha256 = sha256.trim();
    if !requested_sha256.is_empty() && !is_valid_sha256(requested_sha256) {
        return Err(ResponseError::InvalidInput(
            "sha256 must contain exactly 64 hexadecimal characters".to_string(),
        ));
    }

    let canonical_path = fs::canonicalize(path)?;
    let effective_path = normalize_path(&canonical_path);
    if protected.is_protected_path(&effective_path) {
        return Err(ResponseError::ProtectedPath(effective_path));
    }
    let metadata = fs::metadata(&canonical_path)?;

    if !metadata.is_file() {
        return Err(ResponseError::InvalidInput(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    let actual_sha256 = hash_path(&canonical_path)?;
    if !requested_sha256.is_empty() && !actual_sha256.eq_ignore_ascii_case(requested_sha256) {
        return Err(ResponseError::InvalidInput(
            "sha256 does not match quarantine source content".to_string(),
        ));
    }

    fs::create_dir_all(quarantine_dir)?;
    apply_quarantine_dir_permissions(quarantine_dir)?;
    let quarantine_dir = fs::canonicalize(quarantine_dir)?;
    let quarantine_path = quarantine_dir.join(&actual_sha256);
    let manifest_path = quarantine_manifest_path(&quarantine_dir, &actual_sha256);
    ensure_artifact_absent(&quarantine_path)?;
    ensure_artifact_absent(&manifest_path)?;

    let (original_mode, owner_uid, owner_gid) = metadata_identity(&metadata);
    let manifest = QuarantineManifest {
        version: MANIFEST_VERSION,
        sha256: actual_sha256.clone(),
        original_path: effective_path.clone(),
        file_size: metadata.len(),
        original_mode,
        owner_uid,
        owner_gid,
        quarantined_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
    };

    let moved = match fs::rename(&canonical_path, &quarantine_path) {
        Ok(()) => true,
        Err(err) if err.kind() == ErrorKind::CrossesDevices => {
            fs::copy(&canonical_path, &quarantine_path)?;
            false
        }
        Err(err) => return Err(err.into()),
    };

    if let Err(err) = durable_restrict_payload(&quarantine_path)
        .and_then(|_| verify_quarantine_payload(&quarantine_path, &actual_sha256, metadata.len()))
        .and_then(|_| write_manifest_atomic(&manifest_path, &manifest))
    {
        let _ = fs::remove_file(&manifest_path);
        if moved {
            let _ = fs::rename(&quarantine_path, &canonical_path);
        } else {
            let _ = fs::remove_file(&quarantine_path);
        }
        return Err(err);
    }

    if !moved {
        let mut original = OpenOptions::new().write(true).open(&canonical_path)?;
        apply_restrictive_permissions(&canonical_path)?;
        overwrite_file_prefix_with_zeros_file(&mut original, metadata.len())?;
        fs::remove_file(&canonical_path)?;
    }

    sync_directory(&quarantine_dir)?;
    if let Some(parent) = canonical_path.parent() {
        sync_directory(parent)?;
    }

    Ok(QuarantineReport {
        original_path: effective_path,
        quarantine_path,
        sha256: actual_sha256,
        file_size: metadata.len(),
        original_mode,
        owner_uid,
        owner_gid,
    })
}

pub fn restore_quarantined(
    sha256: &str,
    quarantine_path: Option<&Path>,
    original_path: Option<&Path>,
) -> ResponseResult<RestoreReport> {
    restore_quarantined_with_dir(
        sha256,
        quarantine_path,
        original_path,
        &resolve_default_quarantine_dir(),
    )
}

pub fn restore_quarantined_with_dir(
    sha256: &str,
    quarantine_path: Option<&Path>,
    original_path: Option<&Path>,
    quarantine_dir: &Path,
) -> ResponseResult<RestoreReport> {
    if !is_valid_sha256(sha256.trim()) {
        return Err(ResponseError::InvalidInput(
            "sha256 must contain exactly 64 hexadecimal characters".to_string(),
        ));
    }
    let sha256 = sha256.trim().to_ascii_lowercase();
    let quarantine_dir = fs::canonicalize(quarantine_dir)?;
    let source = quarantine_dir.join(&sha256);
    let manifest_path = quarantine_manifest_path(&quarantine_dir, &sha256);

    if let Some(provided) = quarantine_path {
        if !provided.as_os_str().is_empty() && !paths_equal(provided, &source) {
            return Err(ResponseError::InvalidInput(
                "quarantine_path does not match sha256 quarantine artifact".to_string(),
            ));
        }
    }

    if !manifest_path.exists() {
        if source.exists() {
            return Err(ResponseError::InvalidInput(
                "legacy_quarantine_requires_manual_restore".to_string(),
            ));
        }
        return Err(ResponseError::InvalidInput(
            "quarantine artifact does not exist".to_string(),
        ));
    }

    let manifest_file = open_regular_no_follow(&manifest_path, "quarantine manifest")?;
    let manifest: QuarantineManifest = serde_json::from_reader(manifest_file).map_err(|err| {
        ResponseError::InvalidInput(format!("invalid quarantine manifest: {err}"))
    })?;
    validate_manifest(&manifest, &sha256)?;

    if let Some(provided) = original_path {
        if !provided.as_os_str().is_empty() && !paths_equal(provided, &manifest.original_path) {
            return Err(ResponseError::InvalidInput(
                "original_path does not match locally recorded quarantine provenance".to_string(),
            ));
        }
    }

    let parent = manifest.original_path.parent().ok_or_else(|| {
        ResponseError::InvalidInput("manifest original_path has no parent".to_string())
    })?;
    let file_name = manifest.original_path.file_name().ok_or_else(|| {
        ResponseError::InvalidInput("manifest original_path has no file name".to_string())
    })?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !paths_equal(parent, &canonical_parent) {
        return Err(ResponseError::InvalidInput(
            "restore parent no longer matches quarantined original parent".to_string(),
        ));
    }
    let destination = canonical_parent.join(file_name);
    let destination_parent = open_restore_parent(&canonical_parent)?;

    let mut source_file = open_regular_no_follow(&source, "quarantine payload")?;
    let source_metadata = source_file.metadata()?;
    if source_metadata.len() != manifest.file_size {
        return Err(ResponseError::InvalidInput(
            "quarantine payload size does not match manifest".to_string(),
        ));
    }
    if hash_file(&mut source_file)? != sha256 {
        return Err(ResponseError::InvalidInput(
            "quarantine payload hash does not match sha256".to_string(),
        ));
    }
    source_file.seek(SeekFrom::Start(0))?;

    let mut destination_file = None;
    let restore_result = (|| -> ResponseResult<()> {
        destination_file = Some(create_destination_exclusive(
            &destination_parent,
            file_name,
            &destination,
        )?);
        let destination_file = destination_file
            .as_mut()
            .expect("destination file was just created");
        validate_destination_handle(destination_file)?;
        std::io::copy(&mut source_file, destination_file)?;
        destination_file.sync_all()?;
        restore_identity(destination_file, &manifest)?;
        destination_file.sync_all()?;
        sync_restore_parent(&destination_parent, &canonical_parent)?;
        Ok(())
    })();

    if let Err(err) = restore_result {
        if let Some(destination_file) = destination_file.as_ref() {
            let _ = remove_created_destination(
                &destination_parent,
                file_name,
                &destination,
                destination_file,
            );
        }
        return Err(err);
    }

    drop(destination_file);
    drop(source_file);
    fs::remove_file(&source)?;
    fs::remove_file(&manifest_path)?;
    sync_directory(&quarantine_dir)?;

    Ok(RestoreReport {
        restored_path: destination,
        source_quarantine_path: source,
    })
}

fn validate_manifest(manifest: &QuarantineManifest, sha256: &str) -> ResponseResult<()> {
    if manifest.version != MANIFEST_VERSION
        || manifest.sha256 != sha256
        || !is_valid_sha256(&manifest.sha256)
        || !manifest.original_path.is_absolute()
    {
        return Err(ResponseError::InvalidInput(
            "quarantine manifest does not match restore request".to_string(),
        ));
    }
    Ok(())
}

fn quarantine_manifest_path(quarantine_dir: &Path, sha256: &str) -> PathBuf {
    quarantine_dir.join(format!("{sha256}.meta.json"))
}

fn write_manifest_atomic(path: &Path, manifest: &QuarantineManifest) -> ResponseResult<()> {
    let temp_path = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let result = (|| -> ResponseResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp_path)?;
        serde_json::to_writer(&mut file, manifest).map_err(|err| {
            ResponseError::InvalidInput(format!("failed serializing quarantine manifest: {err}"))
        })?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn hash_path(path: &Path) -> ResponseResult<String> {
    let mut file = File::open(path)?;
    hash_file(&mut file)
}

fn verify_quarantine_payload(path: &Path, sha256: &str, file_size: u64) -> ResponseResult<()> {
    let mut file = open_regular_no_follow(path, "quarantine payload")?;
    if file.metadata()?.len() != file_size || hash_file(&mut file)? != sha256 {
        return Err(ResponseError::InvalidInput(
            "quarantine payload changed before provenance was recorded".to_string(),
        ));
    }
    Ok(())
}

fn hash_file(file: &mut File) -> ResponseResult<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn ensure_artifact_absent(path: &Path) -> ResponseResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ResponseError::InvalidInput(format!(
            "refusing to replace existing path {}",
            path.display()
        ))),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn open_regular_no_follow(path: &Path, label: &str) -> ResponseResult<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ResponseError::InvalidInput(format!(
            "{label} is not a regular non-symlink file"
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(ResponseError::InvalidInput(format!(
            "{label} is not a regular file"
        )));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_restore_parent(path: &Path) -> ResponseResult<File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    let root = open_restore_root()?;
    let relative = path.strip_prefix(Path::new("/")).map_err(|_| {
        ResponseError::InvalidInput("restore parent must be an absolute path".to_string())
    })?;
    let relative = if relative.as_os_str().is_empty() {
        OsStr::new(".")
    } else {
        relative.as_os_str()
    };
    let relative = unix_name(relative)?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_BENEATH,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            relative.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if fd >= 0 {
        return Ok(unsafe { File::from_raw_fd(fd) });
    }

    let err = std::io::Error::last_os_error();
    if !matches!(err.raw_os_error(), Some(libc::ENOSYS) | Some(libc::E2BIG)) {
        return Err(err.into());
    }
    open_restore_parent_fallback(path)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_restore_parent(path: &Path) -> ResponseResult<File> {
    open_restore_parent_fallback(path)
}

#[cfg(unix)]
fn open_restore_root() -> ResponseResult<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    Ok(options.open("/")?)
}

#[cfg(unix)]
fn open_restore_parent_fallback(path: &Path) -> ResponseResult<File> {
    use std::path::Component;

    let mut directory = open_restore_root()?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(ResponseError::InvalidInput(
                "restore parent must be a canonical absolute path".to_string(),
            ));
        };
        let name = unix_name(name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

#[cfg(unix)]
fn unix_name(name: &OsStr) -> ResponseResult<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        ResponseError::InvalidInput("restore path contains an embedded NUL".to_string())
    })
}

#[cfg(windows)]
fn open_restore_parent(path: &Path) -> ResponseResult<File> {
    use std::path::Component;

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(ResponseError::InvalidInput(
            "restore parent must be a canonical absolute Windows path".to_string(),
        ));
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(ResponseError::InvalidInput(
            "restore parent must be a canonical absolute Windows path".to_string(),
        ));
    }

    let mut root = PathBuf::from(prefix.as_os_str());
    root.push(Path::new(r"\"));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);
    let mut directory = options.open(root)?;
    validate_windows_restore_directory(&directory)?;

    for component in components {
        let Component::Normal(name) = component else {
            return Err(ResponseError::InvalidInput(
                "restore parent must be a canonical absolute Windows path".to_string(),
            ));
        };
        directory = open_windows_restore_directory(&directory, name)?;
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_restore_directory(parent: &File, name: &std::ffi::OsStr) -> ResponseResult<File> {
    let mut name: Vec<u16> = name.encode_wide().collect();
    if name.is_empty()
        || name.iter().any(|character| *character == 0)
        || name.len() > (u16::MAX as usize / 2)
    {
        return Err(ResponseError::InvalidInput(
            "restore directory name is invalid for Windows".to_string(),
        ));
    }
    let object_name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: windows::core::PWSTR(name.as_mut_ptr()),
    };
    let object_attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE(parent.as_raw_handle()),
        object_name: &object_name,
        attributes: 0x40 | 0x1000, // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        security_descriptor: std::ptr::null(),
        security_quality_of_service: std::ptr::null(),
    };
    let mut io_status = IoStatusBlock {
        status_or_pointer: std::ptr::null_mut(),
        information: 0,
    };
    let mut handle = HANDLE::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ.0,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
            1,                     // FILE_OPEN
            0x1 | 0x20 | 0x200000, // directory, synchronous, open reparse point
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosError(NTSTATUS(status)) };
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    let directory = unsafe { File::from_raw_handle(handle.0) };
    validate_windows_restore_directory(&directory)?;
    Ok(directory)
}

#[cfg(windows)]
fn validate_windows_restore_directory(directory: &File) -> ResponseResult<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(ResponseError::InvalidInput(
            "restore parent component is not a non-reparse directory".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn open_restore_parent(_path: &Path) -> ResponseResult<()> {
    Ok(())
}

#[cfg(unix)]
fn create_destination_exclusive(
    parent: &File,
    file_name: &OsStr,
    _path: &Path,
) -> ResponseResult<File> {
    let file_name = unix_name(file_name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(windows)]
fn create_destination_exclusive(
    parent: &File,
    file_name: &std::ffi::OsStr,
    _path: &Path,
) -> ResponseResult<File> {
    let mut name: Vec<u16> = file_name.encode_wide().collect();
    if name.iter().any(|character| *character == 0) || name.len() > (u16::MAX as usize / 2) {
        return Err(ResponseError::InvalidInput(
            "restore file name is invalid for Windows".to_string(),
        ));
    }
    let object_name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: windows::core::PWSTR(name.as_mut_ptr()),
    };
    let object_attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE(parent.as_raw_handle()),
        object_name: &object_name,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security_descriptor: std::ptr::null(),
        security_quality_of_service: std::ptr::null(),
    };
    let mut io_status = IoStatusBlock {
        status_or_pointer: std::ptr::null_mut(),
        information: 0,
    };
    let mut handle = HANDLE::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_WRITE.0 | DELETE.0,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            0,
            2,                      // FILE_CREATE (CREATE_NEW)
            0x20 | 0x40 | 0x200000, // synchronous, non-directory, open reparse point
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosError(NTSTATUS(status)) };
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

#[cfg(not(any(unix, windows)))]
fn create_destination_exclusive(
    _parent: &(),
    _file_name: &std::ffi::OsStr,
    path: &Path,
) -> ResponseResult<File> {
    Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
}

#[cfg(windows)]
fn validate_destination_handle(file: &File) -> ResponseResult<()> {
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(ResponseError::InvalidInput(
            "refusing to restore to a Windows reparse point".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_destination_handle(_file: &File) -> ResponseResult<()> {
    Ok(())
}

#[cfg(unix)]
fn remove_created_destination(
    parent: &File,
    file_name: &OsStr,
    _path: &Path,
    file: &File,
) -> ResponseResult<()> {
    let file_name = unix_name(file_name)?;
    let mut created = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), created.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let created = unsafe { created.assume_init() };
    let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            file_name.as_ptr(),
            current.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let current = unsafe { current.assume_init() };
    if created.st_dev != current.st_dev || created.st_ino != current.st_ino {
        return Err(ResponseError::InvalidInput(
            "partial restore path no longer refers to the created file".to_string(),
        ));
    }
    // A same-name replacement remains theoretically possible between fstatat and unlinkat;
    // Unix has no portable unlink-by-handle operation, so keep this window minimal.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), file_name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(windows)]
fn remove_created_destination(
    _parent: &File,
    _file_name: &std::ffi::OsStr,
    _path: &Path,
    file: &File,
) -> ResponseResult<()> {
    let disposition = FILE_DISPOSITION_INFO {
        DeleteFile: BOOLEAN(1),
    };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            &disposition as *const FILE_DISPOSITION_INFO as *const std::ffi::c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|err| ResponseError::InvalidInput(format!("failed removing partial restore: {err}")))
}

#[cfg(not(any(unix, windows)))]
fn remove_created_destination(
    _parent: &(),
    _file_name: &std::ffi::OsStr,
    path: &Path,
    _file: &File,
) -> ResponseResult<()> {
    Ok(fs::remove_file(path)?)
}

#[cfg(unix)]
fn sync_restore_parent(parent: &File, _path: &Path) -> ResponseResult<()> {
    parent.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_restore_parent(_parent: &File, _path: &Path) -> ResponseResult<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_restore_parent(_parent: &(), path: &Path) -> ResponseResult<()> {
    sync_directory(path)
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    let left = normalize_path(left);
    let right = normalize_path(right);
    #[cfg(windows)]
    {
        left.components().count() == right.components().count()
            && left.components().zip(right.components()).all(|(a, b)| {
                a.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
            })
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[cfg(test)]
fn overwrite_file_prefix_with_zeros(path: &Path, file_size: u64) -> ResponseResult<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    overwrite_file_prefix_with_zeros_file(&mut file, file_size)
}

fn overwrite_file_prefix_with_zeros_file(file: &mut File, file_size: u64) -> ResponseResult<()> {
    let overwrite_len = file_size.min(4096) as usize;
    if overwrite_len == 0 {
        return Ok(());
    }

    let zeros = vec![0u8; overwrite_len];
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&zeros)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn durable_restrict_payload(path: &Path) -> ResponseResult<()> {
    let file = File::open(path)?;
    apply_restrictive_permissions(path)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn apply_quarantine_dir_permissions(path: &Path) -> ResponseResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_quarantine_dir_permissions(_path: &Path) -> ResponseResult<()> {
    Ok(())
}

#[cfg(unix)]
fn apply_restrictive_permissions(path: &Path) -> ResponseResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_restrictive_permissions(path: &Path) -> ResponseResult<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> (u32, u32, u32) {
    (metadata.mode(), metadata.uid(), metadata.gid())
}

#[cfg(not(unix))]
fn metadata_identity(_metadata: &fs::Metadata) -> (u32, u32, u32) {
    (0, 0, 0)
}

#[cfg(unix)]
fn restore_identity(file: &File, manifest: &QuarantineManifest) -> ResponseResult<()> {
    let current = file.metadata()?;
    if current.uid() != manifest.owner_uid || current.gid() != manifest.owner_gid {
        let result = unsafe {
            libc::fchown(
                file.as_raw_fd(),
                manifest.owner_uid as libc::uid_t,
                manifest.owner_gid as libc::gid_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    file.set_permissions(fs::Permissions::from_mode(manifest.original_mode & 0o7777))?;
    Ok(())
}

#[cfg(windows)]
fn restore_identity(_file: &File, _manifest: &QuarantineManifest) -> ResponseResult<()> {
    // Manifest v1 records Unix mode/uid/gid only; it contains no Windows owner or ACL to apply.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restore_identity(_file: &File, _manifest: &QuarantineManifest) -> ResponseResult<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> ResponseResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> ResponseResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests;
