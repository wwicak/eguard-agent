/// Restores every listed variable before releasing the shared environment lock,
/// including when a test assertion unwinds. Preserve non-UTF-8 values too.
pub(crate) struct TestEnvGuard {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl TestEnvGuard {
    pub(crate) fn new(names: &[&'static str]) -> Self {
        let lock = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        Self {
            previous: names
                .iter()
                .map(|&name| (name, std::env::var_os(name)))
                .collect(),
            _lock: lock,
        }
    }
}

impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.previous {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{env_lock, TestEnvGuard};

    #[test]
    fn scoped_environment_restores_values_during_unwind() {
        let names = ["HOSTNAME", "EGUARD_TEST_SCOPED_ENV_ABSENT"];
        let guard = TestEnvGuard::new(&names);
        let previous = guard.previous.clone();
        let result = std::panic::catch_unwind(move || {
            let _guard = guard;
            std::env::set_var("HOSTNAME", "changed-hostname");
            std::env::set_var("EGUARD_TEST_SCOPED_ENV_ABSENT", "changed");
            panic!("exercise unwinding cleanup");
        });
        assert!(result.is_err());
        let _lock = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        for (name, expected) in previous {
            assert_eq!(std::env::var_os(name), expected, "restore {name}");
        }
    }
}

pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let lock = LOCK.get_or_init(|| std::sync::Mutex::new(()));
    if lock.is_poisoned() {
        lock.clear_poison();
    }
    lock
}
