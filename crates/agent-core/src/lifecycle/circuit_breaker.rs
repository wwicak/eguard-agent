use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{error, warn};

pub(super) const BREAKER_WINDOW_SECS: u64 = 60;
pub(super) const BREAKER_MAX_BLAST_UNITS: u64 = 128;
pub(super) const BREAKER_COOLDOWN_SECS: u64 = 300;
const STATE_FILENAME: &str = "breaker_state.json";

#[derive(Debug, Clone, Copy)]
pub(super) enum DestructiveKind {
    Kill,
    Quarantine,
    IsolationApply,
    DeviceWipe,
    AppRemove,
    RestartOrUpdate,
    ProtectedGuardViolation,
}

impl DestructiveKind {
    fn label(self) -> &'static str {
        match self {
            Self::Kill => "kill",
            Self::Quarantine => "quarantine",
            Self::IsolationApply => "isolation_apply",
            Self::DeviceWipe => "device_wipe",
            Self::AppRemove => "app_remove",
            Self::RestartOrUpdate => "restart_or_update",
            Self::ProtectedGuardViolation => "protected_guard_violation",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BreakerDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BreakerState {
    window_start_unix: u64,
    #[serde(default)]
    window_active: bool,
    blast_units: u64,
    tripped: bool,
    tripped_at_unix: u64,
    trip_reason: String,
    alerted: bool,
}

impl Default for BreakerState {
    fn default() -> Self {
        Self {
            window_start_unix: 0,
            window_active: false,
            blast_units: 0,
            tripped: false,
            tripped_at_unix: 0,
            trip_reason: String::new(),
            alerted: false,
        }
    }
}

#[derive(Debug)]
pub(super) struct CircuitBreaker {
    state: BreakerState,
    max_blast_units: u64,
    path: PathBuf,
}

impl CircuitBreaker {
    pub(super) fn load(max_blast_units: u64) -> Self {
        Self::load_from_path(breaker_state_path(), max_blast_units)
    }

    pub(super) fn load_from_path(path: PathBuf, max_blast_units: u64) -> Self {
        let mut state = match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(state) => state,
                Err(err) => {
                    warn!(
                        target: "eguard::circuit_breaker",
                        path = %path.display(),
                        error = %err,
                        "ignoring corrupt circuit breaker state"
                    );
                    BreakerState::default()
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => BreakerState::default(),
            Err(err) => {
                warn!(
                    target: "eguard::circuit_breaker",
                    path = %path.display(),
                    error = %err,
                    "failed to read circuit breaker state"
                );
                BreakerState::default()
            }
        };
        // State written before `window_active` existed is active whenever it
        // contains accounting, including conservative epoch-zero accounting.
        if !state.window_active && (state.window_start_unix != 0 || state.blast_units != 0) {
            state.window_active = true;
        }
        Self {
            state,
            max_blast_units: max_blast_units.min(BREAKER_MAX_BLAST_UNITS),
            path,
        }
    }

    pub(super) fn check_and_charge(
        &mut self,
        kind: DestructiveKind,
        units: u64,
        now_unix: u64,
    ) -> BreakerDecision {
        self.maybe_half_open(now_unix);
        if self.state.tripped {
            return BreakerDecision::Deny {
                reason: self.state.trip_reason.clone(),
            };
        }

        if !self.state.window_active {
            self.state.window_active = true;
            self.state.window_start_unix = now_unix;
        } else if now_unix > 0
            && now_unix
                >= self
                    .state
                    .window_start_unix
                    .saturating_add(BREAKER_WINDOW_SECS)
        {
            self.state.window_start_unix = now_unix;
            self.state.blast_units = 0;
        }

        if self.state.blast_units.saturating_add(units) > self.max_blast_units {
            self.trip(kind, units, now_unix);
            return BreakerDecision::Deny {
                reason: self.state.trip_reason.clone(),
            };
        }

        self.state.blast_units = self.state.blast_units.saturating_add(units);
        if let Err(err) = self.persist() {
            self.trip_without_persist(kind, now_unix, format!("state persistence failed: {err}"));
            return BreakerDecision::Deny {
                reason: self.state.trip_reason.clone(),
            };
        }
        BreakerDecision::Allow
    }

    pub(super) fn record_units(&mut self, kind: DestructiveKind, units: u64, now_unix: u64) {
        // Post-hoc storm evidence cannot undo an already refused or completed
        // action; a denial here intentionally affects subsequent actions.
        let _ = self.check_and_charge(kind, units, now_unix);
    }

    pub(super) const fn allow_recovery(&self) -> BreakerDecision {
        BreakerDecision::Allow
    }

    #[allow(dead_code)]
    pub(super) fn reset(&mut self) {
        self.state = BreakerState::default();
        if let Err(err) = self.persist() {
            self.trip_without_persist(
                DestructiveKind::ProtectedGuardViolation,
                0,
                format!("explicit reset persistence failed: {err}"),
            );
            error!(
                target: "eguard::circuit_breaker",
                error = %err,
                "failed to persist explicit circuit breaker reset"
            );
        }
    }

    pub(super) fn maybe_half_open(&mut self, now_unix: u64) {
        if self.state.tripped
            && now_unix.saturating_sub(self.state.tripped_at_unix) >= BREAKER_COOLDOWN_SECS
        {
            self.state = BreakerState {
                window_start_unix: now_unix,
                window_active: true,
                ..BreakerState::default()
            };
            if let Err(err) = self.persist() {
                self.trip_without_persist(
                    DestructiveKind::ProtectedGuardViolation,
                    now_unix,
                    format!("half-open state persistence failed: {err}"),
                );
            }
        }
    }

    fn trip(&mut self, kind: DestructiveKind, units: u64, now_unix: u64) {
        let reason = format!(
            "{} would raise blast units from {} to {} (maximum {})",
            kind.label(),
            self.state.blast_units,
            self.state.blast_units.saturating_add(units),
            self.max_blast_units
        );
        self.trip_without_persist(kind, now_unix, reason);
        if let Err(err) = self.persist() {
            error!(
                target: "eguard::circuit_breaker",
                error = %err,
                "failed to persist tripped circuit breaker"
            );
        }
    }

    fn trip_without_persist(&mut self, kind: DestructiveKind, now_unix: u64, reason: String) {
        self.state.tripped = true;
        self.state.tripped_at_unix = now_unix;
        self.state.trip_reason = reason;
        if !self.state.alerted {
            error!(
                target: "eguard::circuit_breaker",
                destructive_kind = kind.label(),
                trip_reason = %self.state.trip_reason,
                blast_units = self.state.blast_units,
                window = BREAKER_WINDOW_SECS,
                ceiling = self.max_blast_units,
                "global destructive-action circuit breaker tripped; entering detect/report-only mode"
            );
            self.state.alerted = true;
        }
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create breaker state dir {}: {err}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(&self.state)
            .map_err(|err| format!("serialize breaker state: {err}"))?;
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        let write_result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&json)?;
            file.sync_all()
        })();
        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp);
            return Err(format!("write breaker state temp {}: {err}", tmp.display()));
        }
        if let Err(err) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "rename breaker state {}: {err}",
                self.path.display()
            ));
        }
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            let dir = fs::File::open(parent)
                .map_err(|err| format!("open breaker state dir {}: {err}", parent.display()))?;
            dir.sync_all()
                .map_err(|err| format!("fsync breaker state dir {}: {err}", parent.display()))?;
        }
        Ok(())
    }
}

fn breaker_state_path() -> PathBuf {
    if let Ok(dir) = std::env::var("EGUARD_AGENT_DATA_DIR") {
        return PathBuf::from(dir).join(STATE_FILENAME);
    }
    #[cfg(test)]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_STATE: AtomicU64 = AtomicU64::new(0);
        return std::env::temp_dir().join(format!(
            "eguard-breaker-test-{}-{}.json",
            std::process::id(),
            NEXT_TEST_STATE.fetch_add(1, Ordering::Relaxed)
        ));
    }
    #[cfg(all(not(test), target_os = "windows"))]
    {
        PathBuf::from(r"C:\ProgramData\eGuard").join(STATE_FILENAME)
    }
    #[cfg(all(not(test), target_os = "macos"))]
    {
        PathBuf::from("/Library/Application Support/eGuard").join(STATE_FILENAME)
    }
    #[cfg(all(not(test), not(any(target_os = "windows", target_os = "macos"))))]
    {
        PathBuf::from("/var/lib/eguard-agent").join(STATE_FILENAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::field::{Field, Visit};
    use tracing::subscriber::Interest;
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::{Layer, Registry};

    #[derive(Clone, Default)]
    struct CapturedEvents(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    struct FieldVisitor(BTreeMap<String, String>);

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
    }

    impl Layer<Registry> for CapturedEvents {
        fn register_callsite(&self, _metadata: &'static tracing::Metadata<'static>) -> Interest {
            Interest::always()
        }

        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, Registry>) {
            let mut visitor = FieldVisitor(BTreeMap::new());
            event.record(&mut visitor);
            self.0.lock().expect("capture lock").push(visitor.0);
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "eguard-breaker-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
            .join(STATE_FILENAME)
    }

    fn breaker(label: &str) -> CircuitBreaker {
        CircuitBreaker::load_from_path(temp_path(label), BREAKER_MAX_BLAST_UNITS)
    }

    #[test]
    fn circuit_breaker_accumulates_and_rolls_window() {
        let mut breaker = breaker("window");
        assert_eq!(
            breaker.check_and_charge(DestructiveKind::Kill, 40, 1_000),
            BreakerDecision::Allow
        );
        assert_eq!(
            breaker.check_and_charge(DestructiveKind::Quarantine, 80, 1_059),
            BreakerDecision::Allow
        );
        assert_eq!(breaker.state.blast_units, 120);
        assert_eq!(
            breaker.check_and_charge(DestructiveKind::IsolationApply, 8, 1_060),
            BreakerDecision::Allow
        );
        assert_eq!(breaker.state.blast_units, 8);
    }

    #[test]
    fn circuit_breaker_accumulates_when_clock_is_stuck_at_epoch_zero() {
        let mut breaker = breaker("epoch-zero");
        for _ in 0..8 {
            assert_eq!(
                breaker.check_and_charge(DestructiveKind::Kill, 16, 0),
                BreakerDecision::Allow
            );
        }
        assert_eq!(breaker.state.blast_units, BREAKER_MAX_BLAST_UNITS);
        assert!(matches!(
            breaker.check_and_charge(DestructiveKind::Kill, 1, 0),
            BreakerDecision::Deny { .. }
        ));
        assert!(breaker.state.tripped);
    }

    #[test]
    fn circuit_breaker_denies_threshold_crossing_before_charge() {
        let mut breaker = breaker("crossing");
        assert_eq!(
            breaker.check_and_charge(DestructiveKind::Kill, 128, 2_000),
            BreakerDecision::Allow
        );
        assert!(matches!(
            breaker.check_and_charge(DestructiveKind::Kill, 1, 2_001),
            BreakerDecision::Deny { .. }
        ));
        assert!(breaker.state.tripped);
        assert_eq!(breaker.state.blast_units, 128);
    }

    #[test]
    fn circuit_breaker_denies_destructive_kinds_but_allows_recovery() {
        let mut breaker = breaker("kinds");
        breaker.check_and_charge(DestructiveKind::Kill, 128, 3_000);
        breaker.check_and_charge(DestructiveKind::Kill, 1, 3_001);
        for kind in [
            DestructiveKind::Kill,
            DestructiveKind::Quarantine,
            DestructiveKind::IsolationApply,
        ] {
            assert!(matches!(
                breaker.check_and_charge(kind, 1, 3_002),
                BreakerDecision::Deny { .. }
            ));
        }
        assert_eq!(breaker.allow_recovery(), BreakerDecision::Allow);
    }

    #[test]
    fn circuit_breaker_durability_and_corrupt_state_safe_default() {
        let path = temp_path("durability");
        let mut breaker = CircuitBreaker::load_from_path(path.clone(), 128);
        breaker.check_and_charge(DestructiveKind::Kill, 128, 4_000);
        breaker.check_and_charge(DestructiveKind::Kill, 1, 4_001);
        let loaded = CircuitBreaker::load_from_path(path.clone(), 128);
        assert!(loaded.state.tripped);
        assert_eq!(loaded.state.blast_units, 128);

        fs::write(&path, b"not json").expect("write corrupt state");
        let corrupt = CircuitBreaker::load_from_path(path.clone(), 128);
        assert!(!corrupt.state.tripped);
        assert_eq!(corrupt.state.blast_units, 0);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn circuit_breaker_cooldown_and_explicit_reset_clear_trip() {
        let mut breaker = breaker("recovery");
        breaker.check_and_charge(DestructiveKind::Kill, 128, 5_000);
        breaker.check_and_charge(DestructiveKind::Kill, 1, 5_001);
        breaker.maybe_half_open(5_300);
        assert!(breaker.state.tripped);
        breaker.maybe_half_open(5_301);
        assert!(!breaker.state.tripped);
        assert_eq!(breaker.state.blast_units, 0);

        breaker.check_and_charge(DestructiveKind::Kill, 128, 6_000);
        breaker.check_and_charge(DestructiveKind::Kill, 1, 6_001);
        breaker.reset();
        assert!(!breaker.state.tripped);
        assert_eq!(breaker.state.blast_units, 0);
    }

    #[test]
    fn circuit_breaker_trip_audit_fires_once_across_persisted_reloads() {
        const AUDIT_MESSAGE: &str =
            "global destructive-action circuit breaker tripped; entering detect/report-only mode";
        let path = temp_path("alert-one-shot");
        let captured = CapturedEvents::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        tracing::subscriber::set_global_default(subscriber).expect("install tracing capture");
        let is_test_audit = |fields: &&BTreeMap<String, String>| {
            fields
                .get("message")
                .is_some_and(|message| message.contains(AUDIT_MESSAGE))
                && fields
                    .get("destructive_kind")
                    .is_some_and(|kind| kind.contains("restart_or_update"))
        };

        let mut breaker = CircuitBreaker::load_from_path(path.clone(), 128);
        breaker.check_and_charge(DestructiveKind::RestartOrUpdate, 128, 7_000);
        breaker.check_and_charge(DestructiveKind::RestartOrUpdate, 4, 7_001);
        assert!(breaker.state.tripped);
        assert!(breaker.state.alerted);

        let events = captured.0.lock().expect("capture lock");
        let audits: Vec<_> = events.iter().filter(is_test_audit).collect();
        assert_eq!(audits.len(), 1);
        let audit = audits[0];
        assert!(audit.contains_key("trip_reason"), "{audit:?}");
        assert_eq!(audit.get("blast_units").map(String::as_str), Some("128"));
        assert_eq!(audit.get("window").map(String::as_str), Some("60"));
        assert_eq!(audit.get("ceiling").map(String::as_str), Some("128"));
        drop(events);

        let mut reloaded = CircuitBreaker::load_from_path(path.clone(), 128);
        assert!(reloaded.state.alerted);
        for _ in 0..5 {
            assert!(matches!(
                reloaded.check_and_charge(DestructiveKind::RestartOrUpdate, 1, 7_002),
                BreakerDecision::Deny { .. }
            ));
        }

        let final_audit_count = captured
            .0
            .lock()
            .expect("capture lock")
            .iter()
            .filter(is_test_audit)
            .count();
        assert_eq!(final_audit_count, 1);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn circuit_breaker_compiled_ceiling_clamps_configuration() {
        let breaker = CircuitBreaker::load_from_path(temp_path("clamp"), u64::MAX);
        assert_eq!(breaker.max_blast_units, BREAKER_MAX_BLAST_UNITS);
    }
}
