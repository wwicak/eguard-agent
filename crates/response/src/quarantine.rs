use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

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
    ensure_artifact_absent(&destination)?;

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

    let restore_result = (|| -> ResponseResult<()> {
        let mut destination_file = create_destination_exclusive(&destination)?;
        std::io::copy(&mut source_file, &mut destination_file)?;
        destination_file.sync_all()?;
        restore_identity(&destination_file, &manifest)?;
        destination_file.sync_all()?;
        sync_directory(&canonical_parent)?;
        Ok(())
    })();

    if let Err(err) = restore_result {
        let _ = fs::remove_file(&destination);
        return Err(err);
    }

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

fn create_destination_exclusive(path: &Path) -> ResponseResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    Ok(options.open(path)?)
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

#[cfg(not(unix))]
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
