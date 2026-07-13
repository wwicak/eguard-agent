use super::*;
use crate::ResponseError;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Mutex;

fn test_base(label: &str) -> PathBuf {
    // The quarantine primitive reports normalize_path(fs::canonicalize())d paths, so
    // anchor the fixture on that same canonical temp root to keep expected==reported
    // on every platform:
    //  - macOS: the per-user temp dir is under /var/folders and /var is a symlink to
    //    /private/var, so the canonical form differs from the raw temp path.
    //  - Windows CI: TEMP is an 8.3 short name (e.g. C:\Users\RUNNER~1\...) that
    //    canonicalize resolves to the long name, and normalize_path deverbatimizes the
    //    \\?\ prefix (yielding C:/...); without this the reported long/deverbatim path
    //    never equals the raw short path.
    //  - Linux: effectively a no-op (/tmp is not a symlink).
    let root = std::env::temp_dir();
    let root = std::fs::canonicalize(&root).unwrap_or(root);
    #[cfg(windows)]
    let root = normalize_path(&root);
    root.join(format!(
        "eguard-{label}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ))
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(windows)]
fn cmd_path(path: &std::path::Path) -> String {
    // test_base anchors fixtures on normalize_path(canonicalize(..)), whose Windows
    // form uses the drive's forward-slash prefix (C:/...). cmd.exe parses a leading
    // "C:/" as a switch ("Invalid switch - ..."), so hand mklink a plain-backslash
    // path. Rust's own fs APIs accept either separator, so only cmd shell-outs need
    // this.
    path.to_string_lossy().replace('/', "\\")
}

fn quarantine_fixture(label: &str) -> (PathBuf, PathBuf, QuarantineReport, Vec<u8>) {
    let base = test_base(label);
    let original_dir = base.join("original");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&original_dir).expect("create original parent");
    let original = original_dir.join("payload.bin");
    let payload = b"provenance-bound payload".to_vec();
    fs::write(&original, &payload).expect("write original");
    #[cfg(unix)]
    fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).expect("set original mode");
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: Vec::new(),
    };
    let report =
        quarantine_file_with_dir(&original, &digest(&payload), &protected, &quarantine_dir)
            .expect("quarantine fixture");
    (base, quarantine_dir, report, payload)
}

fn assert_quarantine_retained(report: &QuarantineReport, quarantine_dir: &Path) {
    assert!(report.quarantine_path.exists(), "payload must be retained");
    assert!(
        quarantine_manifest_path(quarantine_dir, &report.sha256).exists(),
        "manifest must be retained"
    );
}

#[test]
// AC-RSP-032
fn restore_quarantined_round_trip_uses_manifest_and_removes_artifacts() {
    let (base, quarantine_dir, report, payload) = quarantine_fixture("restore-round-trip");
    let manifest_path = quarantine_manifest_path(&quarantine_dir, &report.sha256);

    let restored = restore_quarantined_with_dir(
        &report.sha256,
        Some(&report.quarantine_path),
        None,
        &quarantine_dir,
    )
    .expect("restore from local provenance");

    assert_eq!(restored.restored_path, report.original_path);
    assert_eq!(
        fs::read(&restored.restored_path).expect("read restored"),
        payload
    );
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&restored.restored_path).expect("stat restored");
        assert_eq!(metadata.mode() & 0o7777, report.original_mode & 0o7777);
        assert_eq!(metadata.uid(), report.owner_uid);
        assert_eq!(metadata.gid(), report.owner_gid);
    }
    assert!(!report.quarantine_path.exists());
    assert!(!manifest_path.exists());
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_rejects_server_controlled_source_path() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-source-reject");
    let arbitrary = base.join("arbitrary-source");
    fs::write(&arbitrary, b"attacker bytes").expect("write arbitrary source");

    let err = restore_quarantined_with_dir(&report.sha256, Some(&arbitrary), None, &quarantine_dir)
        .expect_err("arbitrary source rejected");

    assert!(
        matches!(err, ResponseError::InvalidInput(message) if message.contains("quarantine_path"))
    );
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_rejects_server_controlled_destination_path() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-destination-reject");
    let arbitrary = base.join("arbitrary-destination");

    let err = restore_quarantined_with_dir(&report.sha256, None, Some(&arbitrary), &quarantine_dir)
        .expect_err("arbitrary destination rejected");

    assert!(
        matches!(err, ResponseError::InvalidInput(message) if message.contains("original_path"))
    );
    assert!(!arbitrary.exists());
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_to_protected_style_path_requires_only_local_manifest_authority() {
    let base = test_base("restore-protected-provenance");
    let protected_dir = base.join("etc");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&protected_dir).expect("create protected-style parent");
    let original = protected_dir.join("critical.conf");
    let payload = b"locally proven bytes";
    fs::write(&original, payload).expect("write original");
    let unprotected_for_quarantine = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: Vec::new(),
    };
    let report = quarantine_file_with_dir(
        &original,
        &digest(payload),
        &unprotected_for_quarantine,
        &quarantine_dir,
    )
    .expect("quarantine locally proven protected-style path");

    let restored = restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect("manifest-authorized restore");
    assert_eq!(restored.restored_path, original);
    assert_eq!(fs::read(original).expect("read restored"), payload);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_rejects_hash_mismatch_and_retains_artifacts() {
    let (base, quarantine_dir, report, payload) = quarantine_fixture("restore-hash-mismatch");
    fs::write(&report.quarantine_path, vec![b'X'; payload.len()]).expect("tamper payload");

    let err = restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("hash mismatch rejected");

    assert!(matches!(err, ResponseError::InvalidInput(message) if message.contains("hash")));
    assert!(!report.original_path.exists());
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_rejects_manifest_mismatch_and_retains_artifacts() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-manifest-mismatch");
    let manifest_path = quarantine_manifest_path(&quarantine_dir, &report.sha256);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["file_size"] = serde_json::json!(report.file_size + 1);
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("tamper manifest");

    let err = restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("manifest mismatch rejected");

    assert!(matches!(err, ResponseError::InvalidInput(message) if message.contains("size")));
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_create_failure_never_deletes_preexisting_destination() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-existing-destination");
    fs::write(&report.original_path, b"existing bytes").expect("create existing destination");

    restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("exclusive create rejects existing destination");

    assert_eq!(
        fs::read(&report.original_path).expect("existing retained"),
        b"existing bytes"
    );
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn failed_restore_cleanup_only_unlinks_the_created_inode() {
    let base = test_base("restore-cleanup-identity");
    fs::create_dir_all(&base).expect("create restore parent");
    let parent = open_restore_parent(&fs::canonicalize(&base).expect("canonicalize parent"))
        .expect("open restore parent");

    let replaced_name = OsStr::new("replaced.bin");
    let replaced_path = base.join(replaced_name);
    let created = create_destination_exclusive(&parent, replaced_name, &replaced_path)
        .expect("create destination");
    let moved_path = base.join("created-moved.bin");
    fs::rename(&replaced_path, &moved_path).expect("move created inode");
    fs::write(&replaced_path, b"racer replacement").expect("replace path entry");

    remove_created_destination(&parent, replaced_name, &replaced_path, &created)
        .expect_err("inode mismatch must refuse cleanup");
    assert_eq!(
        fs::read(&replaced_path).expect("replacement retained"),
        b"racer replacement"
    );

    let matching_name = OsStr::new("matching.bin");
    let matching_path = base.join(matching_name);
    let matching = create_destination_exclusive(&parent, matching_name, &matching_path)
        .expect("create matching destination");
    remove_created_destination(&parent, matching_name, &matching_path, &matching)
        .expect("matching created inode cleaned");
    assert!(!matching_path.exists());

    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn open_restore_parent_refuses_intermediate_symlink_swap() {
    let base = test_base("restore-parent-swap");
    let original_ancestor = base.join("original");
    let original_parent = original_ancestor.join("nested");
    let moved_ancestor = base.join("original-moved");
    let attacker_ancestor = base.join("attacker");
    fs::create_dir_all(&original_parent).expect("create original parent");
    fs::create_dir_all(attacker_ancestor.join("nested")).expect("create attacker parent");
    let canonical_parent = fs::canonicalize(&original_parent).expect("canonicalize parent");

    fs::rename(&original_ancestor, &moved_ancestor).expect("swap original ancestor");
    std::os::unix::fs::symlink(&attacker_ancestor, &original_ancestor)
        .expect("replace ancestor with symlink");

    open_restore_parent(&canonical_parent).expect_err("parent-component symlink swap refused");
    assert!(!attacker_ancestor.join("nested/payload.bin").exists());
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn quarantine_move_cannot_be_redirected_by_intermediate_parent_symlink_swap() {
    let base = test_base("quarantine-parent-swap");
    let original_ancestor = base.join("original");
    let original_parent = original_ancestor.join("nested");
    let moved_ancestor = base.join("moved-original");
    let protected_ancestor = base.join("protected");
    let protected_parent = protected_ancestor.join("nested");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&original_parent).expect("create original parent");
    fs::create_dir_all(&protected_parent).expect("create protected parent");
    fs::create_dir_all(&quarantine_dir).expect("create quarantine parent");
    let source_path = original_parent.join("payload.bin");
    let protected_path = protected_parent.join("payload.bin");
    fs::write(&source_path, b"opened source").expect("write source");
    fs::write(&protected_path, b"protected bytes").expect("write protected source");

    let mut source = open_quarantine_source(&source_path).expect("open source securely");
    let quarantine_parent = open_restore_parent(
        &fs::canonicalize(&quarantine_dir).expect("canonical quarantine parent"),
    )
    .expect("open quarantine parent");
    fs::rename(&original_ancestor, &moved_ancestor).expect("move original ancestor");
    std::os::unix::fs::symlink(&protected_ancestor, &original_ancestor)
        .expect("replace ancestor with protected symlink");

    let moved = move_quarantine_source(
        &mut source,
        &quarantine_parent,
        OsStr::new("payload"),
        &quarantine_dir.join("payload"),
    )
    .expect("move remains bound to opened parent");

    assert!(moved);
    assert_eq!(
        fs::read(quarantine_dir.join("payload")).unwrap(),
        b"opened source"
    );
    assert_eq!(fs::read(&protected_path).unwrap(), b"protected bytes");
    let _ = fs::remove_file(&original_ancestor);
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn quarantine_move_refuses_replaced_source_leaf() {
    let base = test_base("quarantine-leaf-swap");
    let source_parent = base.join("source");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&source_parent).expect("create source parent");
    fs::create_dir_all(&quarantine_dir).expect("create quarantine parent");
    let source_path = source_parent.join("payload.bin");
    let original_path = source_parent.join("opened.bin");
    fs::write(&source_path, b"opened source").expect("write source");
    let mut source = open_quarantine_source(&source_path).expect("open source securely");
    let quarantine_parent = open_restore_parent(
        &fs::canonicalize(&quarantine_dir).expect("canonical quarantine parent"),
    )
    .expect("open quarantine parent");
    fs::rename(&source_path, &original_path).expect("replace source leaf");
    fs::write(&source_path, b"replacement bytes").expect("write replacement");

    move_quarantine_source(
        &mut source,
        &quarantine_parent,
        OsStr::new("payload"),
        &quarantine_dir.join("payload"),
    )
    .expect_err("replaced source leaf refused");

    assert_eq!(fs::read(&source_path).unwrap(), b"replacement bytes");
    assert_eq!(fs::read(&original_path).unwrap(), b"opened source");
    assert!(!quarantine_dir.join("payload").exists());
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
#[ignore = "setup renames a directory that has an open descendant handle, which \
            Windows forbids (ERROR_ACCESS_DENIED); the source-swap binding this \
            asserts is preserved by renaming the opened source handle and is \
            covered by the cross-platform move tests"]
fn quarantine_move_cannot_be_redirected_by_intermediate_parent_junction_swap() {
    let base = test_base("quarantine-parent-junction-swap");
    let original_ancestor = base.join("original");
    let original_parent = original_ancestor.join("nested");
    let moved_ancestor = base.join("moved-original");
    let protected_ancestor = base.join("protected");
    let protected_parent = protected_ancestor.join("nested");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&original_parent).expect("create original parent");
    fs::create_dir_all(&protected_parent).expect("create protected parent");
    fs::create_dir_all(&quarantine_dir).expect("create quarantine parent");
    let source_path = original_parent.join("payload.bin");
    let protected_path = protected_parent.join("payload.bin");
    fs::write(&source_path, b"opened source").expect("write source");
    fs::write(&protected_path, b"protected bytes").expect("write protected source");

    let mut source = open_quarantine_source(&source_path).expect("open source securely");
    let quarantine_parent = open_restore_parent(
        &fs::canonicalize(&quarantine_dir).expect("canonical quarantine parent"),
    )
    .expect("open quarantine parent");
    fs::rename(&original_ancestor, &moved_ancestor).expect("move original ancestor");
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(cmd_path(&original_ancestor))
        .arg(cmd_path(&protected_ancestor))
        .output()
        .expect("create replacement junction");
    assert!(output.status.success(), "mklink failed: {output:?}");

    let moved = move_quarantine_source(
        &mut source,
        &quarantine_parent,
        std::ffi::OsStr::new("payload"),
        &quarantine_dir.join("payload"),
    )
    .expect("move remains bound to opened handle");

    assert!(moved);
    assert_eq!(
        fs::read(quarantine_dir.join("payload")).unwrap(),
        b"opened source"
    );
    assert_eq!(fs::read(&protected_path).unwrap(), b"protected bytes");
    let _ = fs::remove_dir(&original_ancestor);
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
fn open_restore_parent_refuses_intermediate_junction_swap() {
    let base = test_base("restore-parent-junction-swap");
    let original_ancestor = base.join("original");
    let original_parent = original_ancestor.join("nested");
    let moved_ancestor = base.join("original-moved");
    let attacker_ancestor = base.join("attacker");
    fs::create_dir_all(&original_parent).expect("create original parent");
    fs::create_dir_all(attacker_ancestor.join("nested")).expect("create attacker parent");
    let canonical_parent = fs::canonicalize(&original_parent).expect("canonicalize parent");

    fs::rename(&original_ancestor, &moved_ancestor).expect("swap original ancestor");
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(cmd_path(&original_ancestor))
        .arg(cmd_path(&attacker_ancestor))
        .status()
        .expect("create intermediate junction");
    assert!(status.success(), "mklink /J must succeed");

    open_restore_parent(&canonical_parent).expect_err("parent-component junction swap refused");
    assert!(!attacker_ancestor.join("nested/payload.bin").exists());
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn restore_refuses_symlink_destination_and_retains_artifacts() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-symlink-destination");
    let symlink_target = base.join("symlink-target");
    fs::write(&symlink_target, b"do not overwrite").expect("write symlink target");
    std::os::unix::fs::symlink(&symlink_target, &report.original_path)
        .expect("create destination symlink");

    restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("symlink destination rejected");

    assert_eq!(
        fs::read(&symlink_target).expect("target retained"),
        b"do not overwrite"
    );
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_refuses_missing_parent_and_retains_artifacts() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-missing-parent");
    fs::remove_dir(report.original_path.parent().expect("original parent"))
        .expect("remove original parent");

    restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("missing parent rejected");

    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn restore_legacy_payload_without_manifest_fails_closed() {
    let base = test_base("restore-legacy");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
    let sha256 = digest(b"legacy payload");
    fs::write(quarantine_dir.join(&sha256), b"legacy payload").expect("write legacy payload");

    let err = restore_quarantined_with_dir(&sha256, None, None, &quarantine_dir)
        .expect_err("legacy restore rejected");

    assert!(
        matches!(err, ResponseError::InvalidInput(message) if message.contains("legacy_quarantine_requires_manual_restore"))
    );
    assert!(quarantine_dir.join(sha256).exists());
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn restore_refuses_symlink_quarantine_payload() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-symlink-source");
    fs::remove_file(&report.quarantine_path).expect("remove payload");
    let attacker_source = base.join("attacker-source");
    fs::write(&attacker_source, b"attacker bytes").expect("write attacker source");
    std::os::unix::fs::symlink(&attacker_source, &report.quarantine_path)
        .expect("create payload symlink");

    restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("symlink source rejected");

    assert!(quarantine_manifest_path(&quarantine_dir, &report.sha256).exists());
    assert_eq!(
        fs::read(attacker_source).expect("attacker source retained"),
        b"attacker bytes"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_writes_complete_restrictive_manifest_atomically() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("manifest-atomic");
    let manifest_path = quarantine_manifest_path(&quarantine_dir, &report.sha256);
    let manifest: QuarantineManifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");

    assert_eq!(manifest.version, MANIFEST_VERSION);
    assert_eq!(manifest.sha256, report.sha256);
    assert_eq!(manifest.original_path, report.original_path);
    assert_eq!(manifest.file_size, report.file_size);
    assert_eq!(manifest.original_mode, report.original_mode);
    assert_eq!(manifest.owner_uid, report.owner_uid);
    assert_eq!(manifest.owner_gid, report.owner_gid);
    assert!(manifest.quarantined_at > 0);
    assert!(!manifest_path
        .with_extension(format!("json.tmp-{}", std::process::id()))
        .exists());
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(manifest_path).expect("stat manifest").mode() & 0o777,
        0o600
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
fn restore_path_compatibility_is_case_insensitive_and_verbatim_aware_on_windows() {
    assert!(paths_equal(
        Path::new(r"C:\Temp\Payload.bin"),
        Path::new(r"\\?\c:\temp\payload.bin")
    ));
}

#[test]
#[cfg(windows)]
fn restore_refuses_windows_symlink_destination_and_retains_artifacts() {
    let (base, quarantine_dir, report, _) = quarantine_fixture("restore-windows-reparse");
    let target = base.join("reparse-target");
    fs::write(&target, b"do not overwrite").expect("write target");
    std::os::windows::fs::symlink_file(&target, &report.original_path)
        .expect("create destination file symlink");

    restore_quarantined_with_dir(&report.sha256, None, None, &quarantine_dir)
        .expect_err("reparse destination rejected");

    assert_eq!(
        fs::read(target).expect("target retained"),
        b"do not overwrite"
    );
    assert_quarantine_retained(&report, &quarantine_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RSP-024
fn protected_path_is_rejected_before_quarantine() {
    let protected = ProtectedList::default_linux();
    let path = Path::new("/usr/bin/ls");
    let err =
        quarantine_file(path, "sha256-test", &protected).expect_err("protected path rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == path));
}

#[test]
#[cfg(unix)]
fn quarantine_rejects_intermediate_symlink_into_protected_root() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-symlink-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let protected_dir = base.join("protected");
    let alias_dir = base.join("alias");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&protected_dir).expect("create protected dir");
    let protected_dir = fs::canonicalize(&protected_dir).expect("canonical protected dir");
    std::os::unix::fs::symlink(&protected_dir, &alias_dir).expect("create symlink dir");

    let target = protected_dir.join("payload.bin");
    let payload = b"protected payload";
    fs::write(&target, payload).expect("write protected target");
    let alias_path = alias_dir.join("payload.bin");
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![protected_dir.clone()],
    };

    let err = quarantine_file_with_dir(&alias_path, &digest(payload), &protected, &quarantine_dir)
        .expect_err("canonical protected path rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == target));
    assert_eq!(fs::read(&target).expect("target remains"), payload);
    assert!(!quarantine_dir.join(digest(payload)).exists());

    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
fn quarantine_rejects_junction_into_protected_root() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-junction-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let protected_dir = base.join("protected");
    let alias_dir = base.join("alias");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&protected_dir).expect("create protected dir");
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&alias_dir)
        .arg(&protected_dir)
        .output()
        .expect("run mklink");
    assert!(
        output.status.success(),
        "mklink failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let target = protected_dir.join("payload.bin");
    let payload = b"protected payload";
    fs::write(&target, payload).expect("write protected target");
    let expected_path = normalize_path(&fs::canonicalize(&target).expect("canonical target"));
    // Use the canonicalized protected root: on the Windows CI runner the raw base is
    // an 8.3 short-name path, but the quarantine primitive canonicalizes the target to
    // its long name before matching, so a raw short-name protected entry would never
    // match and the junction would (wrongly) be quarantined instead of rejected.
    let protected_root =
        normalize_path(&fs::canonicalize(&protected_dir).expect("canonical protected dir"));
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![protected_root],
    };

    let err = quarantine_file_with_dir(
        &alias_dir.join("payload.bin"),
        &digest(payload),
        &protected,
        &quarantine_dir,
    )
    .expect_err("junction target inside protected root rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == expected_path));
    assert_eq!(fs::read(&target).expect("target remains"), payload);
    assert!(!quarantine_dir.join(digest(payload)).exists());

    let _ = fs::remove_dir(&alias_dir);
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(windows)]
fn quarantine_report_uses_deverbatimized_canonical_original_path() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-windows-report-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");
    let original = base.join("payload.bin");
    fs::write(&original, b"payload").expect("write original");
    let expected_path = normalize_path(&fs::canonicalize(&original).expect("canonical original"));
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![base.join("different-protected-root")],
    };

    let report =
        quarantine_file_with_dir(&original, &digest(b"payload"), &protected, &quarantine_dir)
            .expect("quarantine unprotected file");

    assert_eq!(report.original_path, expected_path);
    assert!(!report.original_path.to_string_lossy().starts_with(r"\\?\"));

    let mut permissions = fs::metadata(&report.quarantine_path)
        .expect("stat quarantined file")
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&report.quarantine_path, permissions).expect("restore permissions");
    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(unix)]
fn quarantine_allows_intermediate_symlink_to_unprotected_target_and_reports_canonical_path() {
    let base = test_base("quarantine-symlink-happy");
    let target_dir = base.join("target");
    let alias_dir = base.join("alias");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&target_dir).expect("create target dir");
    let target_dir = fs::canonicalize(&target_dir).expect("canonical target dir");
    std::os::unix::fs::symlink(&target_dir, &alias_dir).expect("create symlink dir");

    let target = target_dir.join("payload.bin");
    let payload = b"unprotected payload";
    fs::write(&target, payload).expect("write target");
    let alias_path = alias_dir.join("payload.bin");
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![base.join("different-protected-root")],
    };

    let report =
        quarantine_file_with_dir(&alias_path, &digest(payload), &protected, &quarantine_dir)
            .expect("unprotected canonical target quarantined");

    assert_eq!(report.original_path, target);
    assert_eq!(report.quarantine_path, quarantine_dir.join(digest(payload)));
    assert!(!target.exists());
    assert!(!alias_path.exists());
    #[cfg(unix)]
    fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
        .expect("restore perms for readback");
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined"),
        payload
    );

    let _ = fs::remove_dir_all(base);
}

#[test]
fn macos_directory_services_record_is_rejected_before_quarantine() {
    let protected = ProtectedList::default_macos();
    let path = Path::new("/var/db/dslocal/nodes/Default/users/root.plist");
    let err = quarantine_file(path, "deadbeef", &protected).expect_err("protected path rejected");

    assert!(matches!(err, ResponseError::ProtectedPath(p) if p == path));
}

#[test]
fn quarantine_runtime_entrypoint_moves_file_and_reports_fields() {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    struct EnvVarReset;
    impl Drop for EnvVarReset {
        fn drop(&mut self) {
            std::env::remove_var("EGUARD_TEST_QUARANTINE_DIR");
        }
    }

    let base = test_base("quarantine-runtime");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("runtime.bin");
    let original_bytes = b"runtime quarantine payload".to_vec();
    fs::write(&original, &original_bytes).expect("write original");
    #[cfg(unix)]
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o640))
        .expect("chmod original");
    #[cfg(unix)]
    let metadata = fs::metadata(&original).expect("stat original");

    let protected = ProtectedList::default_linux();
    assert!(
        !protected.is_protected_path(&original),
        "test source must be outside protected paths"
    );

    let hash = digest(&original_bytes);
    std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_dir);
    let _env_reset = EnvVarReset;
    let report = quarantine_file(&original, &hash, &protected).expect("quarantine file");

    assert_eq!(report.original_path, original);
    assert!(!report.sha256.is_empty());
    assert_eq!(report.sha256, hash);
    assert_eq!(report.file_size, original_bytes.len() as u64);
    #[cfg(unix)]
    {
        assert_eq!(report.original_mode, metadata.mode());
        assert_eq!(report.owner_uid, metadata.uid());
        assert_eq!(report.owner_gid, metadata.gid());
    }
    assert_eq!(report.quarantine_path, quarantine_dir.join(&hash));
    assert!(report.quarantine_path.exists());
    #[cfg(unix)]
    fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
        .expect("restore perms for readback");
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined file"),
        original_bytes
    );
    assert!(!original.exists());

    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RSP-025 AC-RSP-026 AC-RSP-029 AC-RSP-030
fn quarantine_with_custom_dir_copies_metadata_and_removes_original() {
    let base = test_base("quarantine");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("sample.bin");
    let original_bytes = b"hello quarantine".to_vec();
    fs::write(&original, &original_bytes).expect("write original");
    #[cfg(unix)]
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o640))
        .expect("chmod original");

    let protected = ProtectedList::default_linux();
    let report = quarantine_file_with_dir(
        &original,
        &digest(&original_bytes),
        &protected,
        &quarantine_dir,
    )
    .expect("quarantine file");

    assert_eq!(report.original_path, original);
    assert_eq!(report.sha256, digest(&original_bytes));
    assert_eq!(report.file_size, original_bytes.len() as u64);
    #[cfg(unix)]
    assert!(report.original_mode & 0o777 != 0);
    assert!(!report.quarantine_path.as_os_str().is_empty());
    assert!(!original.exists());
    #[cfg(unix)]
    fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
        .expect("restore perms for readback");
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined copy"),
        original_bytes
    );

    let _ = fs::remove_file(report.quarantine_path);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_refuses_oversized_source_without_output() {
    let base = test_base("quarantine-oversized");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");
    let original = base.join("oversized.bin");
    let file = File::create(&original).expect("create sparse source");
    file.set_len(MAX_QUARANTINE_FILE_BYTES + 1)
        .expect("size sparse source above ceiling");
    drop(file);

    let err = quarantine_file_with_dir(
        &original,
        "",
        &ProtectedList {
            process_patterns: Vec::new(),
            protected_paths: Vec::new(),
        },
        &quarantine_dir,
    )
    .expect_err("oversized source refused");

    assert!(
        matches!(err, ResponseError::InvalidInput(message) if message.contains("exceeds maximum size"))
    );
    assert!(original.exists(), "source must remain untouched");
    assert!(!quarantine_dir.exists(), "refusal must not create output");
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_prefers_rename_within_same_filesystem() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-rename-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("sample.bin");
    let original_bytes = b"rename quarantine".to_vec();
    fs::write(&original, &original_bytes).expect("write original");

    let protected = ProtectedList::default_linux();
    let report = quarantine_file_with_dir(
        &original,
        &digest(&original_bytes),
        &protected,
        &quarantine_dir,
    )
    .expect("quarantine file");

    assert!(!original.exists());
    assert!(report.quarantine_path.exists());
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&report.quarantine_path)
                .expect("stat quarantined")
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(&report.quarantine_path, fs::Permissions::from_mode(0o600))
            .expect("restore perms for readback");
    }
    assert_eq!(
        fs::read(&report.quarantine_path).expect("read quarantined"),
        original_bytes
    );

    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(target_os = "linux")]
fn quarantine_cross_device_zeroes_and_unlinks_the_opened_source_inode() {
    let base = test_base("quarantine-cross-device");
    fs::create_dir_all(&base).expect("create source parent");
    let quarantine_dir = PathBuf::from("/dev/shm").join(format!(
        "eguard-quarantine-cross-device-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&quarantine_dir).expect("create cross-device quarantine parent");
    assert_ne!(
        fs::metadata(&base).unwrap().dev(),
        fs::metadata(&quarantine_dir).unwrap().dev(),
        "test requires /dev/shm on a different filesystem"
    );
    let original = base.join("source.bin");
    let witness = base.join("source-witness.bin");
    let payload = vec![0x5a; 5000];
    fs::write(&original, &payload).expect("write source");
    fs::hard_link(&original, &witness).expect("retain inode witness");

    TEST_DESTINATION_AVAILABLE_BYTES.with(|value| value.set(Some(u64::MAX)));
    let result = quarantine_file_with_dir(
        &original,
        &digest(&payload),
        &ProtectedList {
            process_patterns: Vec::new(),
            protected_paths: Vec::new(),
        },
        &quarantine_dir,
    );
    TEST_DESTINATION_AVAILABLE_BYTES.with(|value| value.set(None));
    let report = result.expect("cross-device quarantine");

    assert!(!original.exists());
    let witnessed = fs::read(&witness).expect("read retained source inode");
    assert!(witnessed[..4096].iter().all(|byte| *byte == 0));
    assert_eq!(&witnessed[4096..], &payload[4096..]);
    assert_eq!(fs::read(&report.quarantine_path).unwrap(), payload);
    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&quarantine_dir);
}

#[test]
#[cfg(target_os = "linux")]
fn quarantine_cross_device_refuses_low_free_space_without_payload() {
    let base = test_base("quarantine-low-space");
    fs::create_dir_all(&base).expect("create source parent");
    let quarantine_dir = PathBuf::from("/dev/shm").join(format!(
        "eguard-quarantine-low-space-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&quarantine_dir).expect("create cross-device quarantine parent");
    assert_ne!(
        fs::metadata(&base).unwrap().dev(),
        fs::metadata(&quarantine_dir).unwrap().dev(),
        "test requires /dev/shm on a different filesystem"
    );
    let original = base.join("source.bin");
    let payload = b"low-space admission";
    fs::write(&original, payload).expect("write source");
    let sha256 = digest(payload);

    TEST_DESTINATION_AVAILABLE_BYTES
        .with(|value| value.set(Some(QUARANTINE_FREE_SPACE_RESERVE_BYTES)));
    let result = quarantine_file_with_dir(
        &original,
        &sha256,
        &ProtectedList {
            process_patterns: Vec::new(),
            protected_paths: Vec::new(),
        },
        &quarantine_dir,
    );
    TEST_DESTINATION_AVAILABLE_BYTES.with(|value| value.set(None));
    let err = result.expect_err("low-space destination refused");

    assert!(
        matches!(err, ResponseError::InvalidInput(message) if message.contains("insufficient quarantine destination free space"))
    );
    assert_eq!(fs::read(&original).expect("source retained"), payload);
    assert!(!quarantine_dir.join(&sha256).exists());
    assert!(!quarantine_manifest_path(&quarantine_dir, &sha256).exists());
    let _ = fs::remove_dir_all(base);
    let _ = fs::remove_dir_all(quarantine_dir);
}

#[test]
// AC-RSP-028
fn overwrite_prefix_zeroes_only_first_four_kilobytes() {
    let base = std::env::temp_dir().join(format!(
        "eguard-overwrite-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create base");
    let file = base.join("payload.bin");

    let payload = vec![0xAB; 5000];
    fs::write(&file, &payload).expect("write payload");
    overwrite_file_prefix_with_zeros(&file, payload.len() as u64).expect("overwrite");
    let changed = fs::read(&file).expect("read changed payload");

    assert!(changed[..4096].iter().all(|b| *b == 0));
    assert!(changed[4096..].iter().all(|b| *b == 0xAB));

    let _ = fs::remove_file(file);
    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RSP-027
fn missing_sha256_is_computed_locally() {
    let base = std::env::temp_dir().join(format!(
        "eguard-quarantine-invalid-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create base");
    let original = base.join("sample.bin");
    fs::write(&original, b"x").expect("write file");

    let protected = ProtectedList::default_linux();
    let report = quarantine_file_with_dir(&original, "  ", &protected, &base)
        .expect("missing hash should be computed");
    assert_eq!(report.sha256, digest(b"x"));

    let _ = fs::remove_file(report.quarantine_path);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_rejects_mismatched_content_hash_without_moving_source() {
    let base = test_base("quarantine-hash-mismatch");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");
    let original = base.join("sample.bin");
    fs::write(&original, b"actual content").expect("write original");
    let protected = ProtectedList::default_linux();

    let err = quarantine_file_with_dir(
        &original,
        &digest(b"different content"),
        &protected,
        &quarantine_dir,
    )
    .expect_err("mismatched hash rejected");

    assert!(
        matches!(err, ResponseError::InvalidInput(message) if message.contains("does not match"))
    );
    assert_eq!(
        fs::read(&original).expect("source retained"),
        b"actual content"
    );
    assert!(!quarantine_dir.exists());
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quarantine_normalizes_uppercase_sha256_ids() {
    let base = test_base("quarantine-normalize");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&base).expect("create base");

    let original = base.join("sample.bin");
    fs::write(&original, b"normalize me").expect("write original");

    let protected = ProtectedList::default_linux();
    let expected = digest(b"normalize me");
    let uppercase = expected.to_ascii_uppercase();
    let report = quarantine_file_with_dir(&original, &uppercase, &protected, &quarantine_dir)
        .expect("quarantine file with uppercase sha");

    assert_eq!(report.sha256, expected);
    assert_eq!(report.quarantine_path, quarantine_dir.join(&report.sha256));

    let _ = fs::remove_dir_all(base);
}

#[test]
#[cfg(target_os = "linux")]
// AC-RSP-031
fn default_quarantine_dir_matches_contract() {
    assert_eq!(DEFAULT_QUARANTINE_DIR, "/var/lib/eguard-agent/quarantine");
}

#[test]
// Regression: hardening (restrict_payload_handle, which resets the payload's
// owner/permissions) must run only AFTER verification and manifest write, so any
// post-move failure rolls the source back with its original owner/permissions
// intact. A post-move manifest-write failure is injected via the thread-local
// FAIL_MANIFEST_WRITE seam (the pre-move ensure_artifact_absent checks make a
// planted-path failure unreachable after the move). Previously the source was
// restored but with hardened metadata (Unix: chmod 0o600; Windows:
// owner=Administrators + owner-only DACL), locking out its legitimate, possibly
// unprivileged, owner.
fn quarantine_rollback_preserves_source_when_manifest_write_fails() {
    let base = test_base("rollback-manifest-fail");
    let original_dir = base.join("original");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&original_dir).expect("create original parent");
    let original = original_dir.join("legit.bin");
    let payload = b"legitimate user data".to_vec();
    fs::write(&original, &payload).expect("write original");
    #[cfg(unix)]
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).expect("set original mode");
    let sha = digest(&payload);

    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: Vec::new(),
    };

    // Force write_manifest_atomic to fail AFTER the payload has been moved and
    // verified (a post-move failure the pre-move ensure_artifact_absent checks
    // cannot cover). The flag is thread-local, so it only affects this test's
    // quarantine call on this thread.
    FAIL_MANIFEST_WRITE.with(|flag| flag.set(true));
    let result = quarantine_file_with_dir(&original, &sha, &protected, &quarantine_dir);
    FAIL_MANIFEST_WRITE.with(|flag| flag.set(false));
    let err = result.expect_err("quarantine must fail when the manifest write fails");
    assert!(
        err.to_string()
            .contains("test-injected manifest write failure"),
        "failure must be the injected post-move manifest write error, got: {err}"
    );

    // Rollback must restore the source unchanged: hardening (owner/DACL on Windows,
    // 0o600 on Unix) must NOT have run, since it is ordered strictly after the
    // (failed) manifest write.
    assert!(original.exists(), "source must be restored on rollback");
    assert_eq!(
        fs::read(&original).expect("read restored source"),
        payload,
        "restored source content must be byte-identical"
    );
    #[cfg(unix)]
    {
        let mode = fs::metadata(&original)
            .expect("stat restored source")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "rollback must preserve the original mode, not the hardened 0o600"
        );
    }

    // The moved payload must not linger in quarantine.
    let qdir_canon = fs::canonicalize(&quarantine_dir).unwrap_or_else(|_| quarantine_dir.clone());
    assert!(
        !qdir_canon.join(&sha).exists(),
        "payload must be rolled back out of quarantine"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
#[cfg(windows)]
// The quarantine source must be opened with exclusive sharing (share mode 0), so a
// file currently held open by ANY other handle -- including an attacker's durable
// read/execute handle to the predictably (sha-)named payload -- cannot be
// quarantined; quarantine fails closed instead. This guards against reintroducing
// FILE_SHARE_READ/WRITE/DELETE on the source open, which would let such a handle
// survive the post-move DACL hardening.
fn quarantine_fails_closed_when_source_is_held_open() {
    let base = test_base("share-deny");
    let original_dir = base.join("original");
    let quarantine_dir = base.join("quarantine");
    fs::create_dir_all(&original_dir).expect("create original parent");
    let original = original_dir.join("held.bin");
    let payload = b"held-open payload".to_vec();
    fs::write(&original, &payload).expect("write original");
    let sha = digest(&payload);
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: Vec::new(),
    };

    // Hold a read handle with permissive sharing (Rust's File::open uses
    // FILE_SHARE_READ|WRITE|DELETE). An exclusive (share 0) source open conflicts
    // with this and fails; any FILE_SHARE_READ on the source open would instead
    // (wrongly) succeed, which is exactly the regression this test detects.
    let guard = fs::File::open(&original).expect("hold read handle");
    let result = quarantine_file_with_dir(&original, &sha, &protected, &quarantine_dir);
    // Assert the specific failure -- the exclusive source open colliding with the
    // held handle (ERROR_SHARING_VIOLATION == 32) -- so an unrelated environmental
    // error can't satisfy the test and mask a share-mode regression.
    match result {
        Err(ResponseError::Io(err)) => assert_eq!(
            err.raw_os_error(),
            Some(32),
            "expected ERROR_SHARING_VIOLATION from the exclusive source open, got: {err}"
        ),
        other => panic!("expected an I/O sharing violation, got: {other:?}"),
    }

    // The source must be untouched: never moved, scrubbed, or hardened.
    drop(guard);
    assert!(original.exists(), "source must remain in place");
    assert_eq!(
        fs::read(&original).expect("read source"),
        payload,
        "source content must be unchanged"
    );

    let _ = fs::remove_dir_all(&base);
}
