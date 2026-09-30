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

pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let lock = LOCK.get_or_init(|| std::sync::Mutex::new(()));
    if lock.is_poisoned() {
        lock.clear_poison();
    }
    lock
}
