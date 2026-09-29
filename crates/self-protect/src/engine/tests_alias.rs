use super::*;

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "eguard-alias-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn check_alias(kind: &str) {
    let fixture = Fixture::new();
    let path = fixture.0.join("agent.conf");
    std::fs::write(&path, b"old").unwrap();
    let alias = match kind {
        "duplicate" => path.clone(),
        "lexical" => {
            std::fs::create_dir(fixture.0.join("sub")).unwrap();
            fixture.0.join("sub/../agent.conf")
        }
        #[cfg(unix)]
        "symlink" => {
            let alias = fixture.0.join("alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            alias
        }
        "hardlink" => {
            let alias = fixture.0.join("alias");
            std::fs::hard_link(&path, &alias).unwrap();
            alias
        }
        _ => unreachable!(),
    };
    let mut config = tests::config_without_runtime_paths();
    config.runtime_config_paths = vec![
        path.to_string_lossy().into_owned(),
        alias.to_string_lossy().into_owned(),
    ];
    let mut engine = SelfProtectEngine::new(config);
    engine
        .authorized_config_write(&alias, |_| {
            std::fs::write(&alias, b"authorized").unwrap();
            Ok(b"authorized".to_vec())
        })
        .unwrap();
    // Every alias must advance together; a stale duplicate falsely signals tamper.
    assert!(
        engine.evaluate().is_clean(),
        "authorized alias write left stale baseline"
    );
    std::fs::write(&alias, b"external").unwrap();
    assert!(
        engine
            .evaluate()
            .violation_codes()
            .contains(&"runtime_config_tamper".to_string()),
        "alias edits must remain protected"
    );
    let report = engine.evaluate();
    assert_eq!(
        report.violations.len(),
        1,
        "alias findings must deduplicate"
    );
    assert!(report.violations[0]
        .detail()
        .contains(&alias.to_string_lossy().to_string()));
    assert!(engine
        .authorized_config_write(&path, |_| panic!("must reject prior tamper"))
        .is_err());
}

#[cfg(unix)]
fn check_atomic_alias(authorized: bool) {
    let fixture = Fixture::new();
    let target = fixture.0.join("target");
    let alias = fixture.0.join("alias");
    let temporary = fixture.0.join("temporary");
    std::fs::write(&target, b"old").unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let mut config = tests::config_without_runtime_paths();
    config.runtime_config_paths = vec![
        target.to_string_lossy().into_owned(),
        alias.to_string_lossy().into_owned(),
        alias.to_string_lossy().into_owned(),
    ];
    let mut engine = SelfProtectEngine::new(config);
    let replace = |_: &[u8]| -> Result<Vec<u8>, String> {
        std::fs::write(&temporary, b"replacement").unwrap();
        std::fs::rename(&temporary, &alias).unwrap();
        Ok(b"replacement".to_vec())
    };
    if authorized {
        engine.authorized_config_write(&alias, replace).unwrap();
        // Production persistence renames over the symlink, leaving its target unchanged.
        assert!(
            engine.evaluate().is_clean(),
            "replacement must not advance the unchanged target"
        );
        std::fs::write(&alias, b"external").unwrap();
    } else {
        replace(&[]).unwrap();
    }
    assert!(
        engine
            .evaluate()
            .violation_codes()
            .contains(&"runtime_config_tamper".to_string()),
        "the configured pathname must remain monitored after symlink replacement"
    );
}

#[cfg(unix)]
#[test]
fn authorized_atomic_alias_replacement() {
    check_atomic_alias(true);
}

#[cfg(unix)]
#[test]
fn external_atomic_alias_replacement() {
    check_atomic_alias(false);
}

#[test]
fn duplicate_authorized_write() {
    check_alias("duplicate");
}
#[test]
fn lexical_authorized_write() {
    check_alias("lexical");
}
#[cfg(unix)]
#[test]
fn symlink_authorized_write() {
    check_alias("symlink");
}
#[cfg(unix)]
#[test]
fn hardlink_authorized_write() {
    check_alias("hardlink");
}

#[test]
fn missing_lexical_path_is_protected_after_creation() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.0.join("sub")).unwrap();
    let path = fixture.0.join("agent.conf");
    let mut config = tests::config_without_runtime_paths();
    config.runtime_config_paths = vec![
        fixture
            .0
            .join("sub/../agent.conf")
            .to_string_lossy()
            .into_owned(),
        path.to_string_lossy().into_owned(),
    ];
    let mut engine = SelfProtectEngine::new(config);
    assert_eq!(
        engine.config().runtime_config_paths,
        config_paths(&[fixture.0.join("sub/../agent.conf"), path.clone()])
    );
    engine
        .authorized_config_write(&path, |_| {
            std::fs::write(&path, b"new").unwrap();
            Ok(b"new".to_vec())
        })
        .unwrap();
    assert!(engine.evaluate().is_clean());
    assert_eq!(
        engine.runtime_baseline().config.len(),
        2,
        "both original missing paths must gain baselines"
    );
    std::fs::write(&path, b"external").unwrap();
    assert_eq!(
        engine.evaluate().violation_codes(),
        vec!["runtime_config_tamper"]
    );
}

fn config_paths(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

#[cfg(unix)]
#[test]
fn symlink_parent_external_edit() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.0.join("real/child")).unwrap();
    std::os::unix::fs::symlink(fixture.0.join("real/child"), fixture.0.join("link")).unwrap();
    let path = fixture.0.join("link/../agent.conf");
    std::fs::write(&path, b"old").unwrap();
    let mut config = tests::config_without_runtime_paths();
    config.runtime_config_paths = config_paths(&[path.clone()]);
    let engine = SelfProtectEngine::new(config);
    std::fs::write(&path, b"external").unwrap();
    assert_eq!(
        engine.evaluate().violation_codes(),
        vec!["runtime_config_tamper"]
    );
}

#[cfg(unix)]
#[test]
fn atomic_split_keeps_both_paths_monitored() {
    let fixture = Fixture::new();
    let target = fixture.0.join("target");
    let alias = fixture.0.join("alias");
    let temp = fixture.0.join("temporary");
    std::fs::write(&target, b"old").unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let mut config = tests::config_without_runtime_paths();
    config.runtime_config_paths = config_paths(&[target.clone(), alias.clone()]);
    let mut engine = SelfProtectEngine::new(config);
    engine
        .authorized_config_write(&alias, |_| {
            std::fs::write(&temp, b"new").unwrap();
            std::fs::rename(&temp, &alias).unwrap();
            Ok(b"new".to_vec())
        })
        .unwrap();
    assert!(engine.evaluate().is_clean());
    for (changed, original) in [(&target, b"old".as_slice()), (&alias, b"new".as_slice())] {
        std::fs::write(changed, b"external").unwrap();
        let report = engine.evaluate();
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.tampered_paths(), config_paths(&[changed.clone()]));
        std::fs::write(changed, original).unwrap();
    }
}
