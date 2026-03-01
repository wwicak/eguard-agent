use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};

const LEARNING_WINDOW_SECS: u64 = 7 * 24 * 3600;
const STALE_WINDOW_SECS: u64 = 30 * 24 * 3600;
const MAX_PROFILE_COUNT_DEFAULT: usize = 4096;
const JOURNAL_COMPACTION_INTERVAL_SECS: u64 = 6 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, SchemaWrite, SchemaRead)]
pub struct ProcessBaseline {
    pub process_key: String,
    pub counts: HashMap<String, u64>,
}

impl ProcessBaseline {
    pub fn new(process_key: String) -> Self {
        Self {
            process_key,
            counts: HashMap::new(),
        }
    }

    pub fn observe(&mut self, event_type: &str) {
        let c = self.counts.entry(event_type.to_string()).or_insert(0);
        *c += 1;
    }

    pub fn sample_count(&self) -> u64 {
        self.counts.values().sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SchemaWrite, SchemaRead)]
pub enum BaselineStatus {
    Learning,
    Active,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineTransition {
    LearningComplete,
    BecameStale,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BaselineStorageStats {
    pub snapshot_size_bytes: u64,
    pub journal_size_bytes: u64,
    pub compaction_count: u64,
    pub last_compaction_reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, SchemaWrite, SchemaRead)]
pub struct ProcessKey {
    pub comm: String,
    pub parent_comm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SchemaWrite, SchemaRead)]
pub struct ProcessProfile {
    pub event_distribution: HashMap<String, u64>,
    pub sample_count: u64,
    pub entropy_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalDeltaRecord {
    seq: u64,
    process_key: String,
    event_type: String,
    count: u64,
    observed_at_unix: u64,
    checksum: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct JournalMeta {
    snapshot_seq: u64,
    updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SchemaWrite, SchemaRead)]
pub struct BaselineStore {
    pub status: BaselineStatus,
    pub learning_started_unix: u64,
    pub learning_completed_unix: Option<u64>,
    pub last_refresh_unix: u64,
    pub baselines: HashMap<ProcessKey, ProcessProfile>,
    #[serde(skip)]
    #[wincode(skip)]
    path: PathBuf,
    #[serde(skip)]
    #[wincode(skip)]
    journal_path: PathBuf,
    #[serde(skip)]
    #[wincode(skip)]
    journal_meta_path: PathBuf,
    #[serde(skip)]
    #[wincode(skip)]
    journal_next_seq: u64,
    #[serde(skip)]
    #[wincode(skip)]
    snapshot_seq: u64,
    #[serde(skip)]
    #[wincode(skip)]
    learning_window_secs: u64,
    #[serde(skip)]
    #[wincode(skip)]
    stale_window_secs: u64,
    #[serde(skip)]
    #[wincode(skip)]
    max_profile_count: usize,
    #[serde(skip)]
    #[wincode(skip)]
    profile_last_seen_unix: HashMap<ProcessKey, u64>,
    #[serde(skip)]
    #[wincode(skip)]
    last_compaction_unix: u64,
    #[serde(skip)]
    #[wincode(skip)]
    compaction_count: u64,
    #[serde(skip)]
    #[wincode(skip)]
    last_compaction_reclaimed_bytes: u64,
}

#[derive(Debug)]
pub enum BaselineStoreError {
    Io(std::io::Error),
    Serialize(String),
    Deserialize(String),
    Time(String),
}

impl fmt::Display for BaselineStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {}", err),
            Self::Serialize(msg) => write!(f, "serialize error: {}", msg),
            Self::Deserialize(msg) => write!(f, "deserialize error: {}", msg),
            Self::Time(msg) => write!(f, "time error: {}", msg),
        }
    }
}

impl std::error::Error for BaselineStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BaselineStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type BaselineStoreResult<T> = std::result::Result<T, BaselineStoreError>;

impl BaselineStore {
    pub fn new(path: impl Into<PathBuf>) -> BaselineStoreResult<Self> {
        let now = now_unix()?;
        let path = path.into();
        let journal_path = journal_path_for(&path);
        let journal_meta_path = journal_meta_path_for(&path);
        Ok(Self {
            status: BaselineStatus::Learning,
            learning_started_unix: now,
            learning_completed_unix: None,
            last_refresh_unix: now,
            baselines: HashMap::new(),
            path,
            journal_path,
            journal_meta_path,
            journal_next_seq: 1,
            snapshot_seq: 0,
            learning_window_secs: LEARNING_WINDOW_SECS,
            stale_window_secs: STALE_WINDOW_SECS,
            max_profile_count: MAX_PROFILE_COUNT_DEFAULT,
            profile_last_seen_unix: HashMap::new(),
            last_compaction_unix: now,
            compaction_count: 0,
            last_compaction_reclaimed_bytes: 0,
        })
    }

    pub fn load_or_new(path: impl Into<PathBuf>) -> BaselineStoreResult<Self> {
        let path = path.into();
        if path.exists() {
            return Self::load(&path);
        }
        Self::new(path)
    }

    pub fn load(path: impl AsRef<Path>) -> BaselineStoreResult<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let mut store: BaselineStore = wincode::deserialize(&bytes)
            .map_err(|err| BaselineStoreError::Deserialize(err.to_string()))?;

        let now = now_unix().unwrap_or(0);
        store.path = path.to_path_buf();
        store.journal_path = journal_path_for(path);
        store.journal_meta_path = journal_meta_path_for(path);
        store.learning_window_secs = LEARNING_WINDOW_SECS;
        store.stale_window_secs = STALE_WINDOW_SECS;
        store.max_profile_count = MAX_PROFILE_COUNT_DEFAULT;
        store.profile_last_seen_unix = HashMap::new();
        for key in store.baselines.keys() {
            store
                .profile_last_seen_unix
                .insert(key.clone(), store.last_refresh_unix);
        }

        let meta = load_journal_meta(&store.journal_meta_path).unwrap_or_default();
        store.snapshot_seq = meta.snapshot_seq;
        store.journal_next_seq = store.snapshot_seq.saturating_add(1);
        store.last_compaction_unix = if meta.updated_at_unix > 0 {
            meta.updated_at_unix
        } else {
            now
        };
        store.compaction_count = 0;
        store.last_compaction_reclaimed_bytes = 0;

        store.replay_journal_tail()?;
        Ok(store)
    }

    pub fn save(&mut self) -> BaselineStoreResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = wincode::serialize(self)
            .map_err(|err| BaselineStoreError::Serialize(err.to_string()))?;
        std::fs::write(&self.path, &bytes)?;

        let current_seq = self.journal_next_seq.saturating_sub(1);
        self.snapshot_seq = current_seq;
        let meta = JournalMeta {
            snapshot_seq: current_seq,
            updated_at_unix: now_unix().unwrap_or(self.last_refresh_unix),
        };
        write_journal_meta(&self.journal_meta_path, &meta)?;

        if self.should_compact_journal(bytes.len()) {
            let reclaimed = self.compact_journal()?;
            self.last_compaction_unix = meta.updated_at_unix;
            self.compaction_count = self.compaction_count.saturating_add(1);
            self.last_compaction_reclaimed_bytes = reclaimed;
        }

        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn storage_stats(&self) -> BaselineStorageStats {
        let snapshot_size_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let journal_size_bytes = std::fs::metadata(&self.journal_path)
            .map(|m| m.len())
            .unwrap_or(0);
        BaselineStorageStats {
            snapshot_size_bytes,
            journal_size_bytes,
            compaction_count: self.compaction_count,
            last_compaction_reclaimed_bytes: self.last_compaction_reclaimed_bytes,
        }
    }

    pub fn configure_windows(&mut self, learning_period_days: u64, stale_after_days: u64) {
        self.learning_window_secs = learning_period_days.max(1).saturating_mul(24 * 3600);
        self.stale_window_secs = stale_after_days.max(1).saturating_mul(24 * 3600);
    }

    pub fn configure_limits(&mut self, max_profile_count: usize) {
        self.max_profile_count = max_profile_count.max(64);
    }

    pub fn learn_event(&mut self, key: ProcessKey, event_type: &str) {
        let now = now_unix().unwrap_or(self.last_refresh_unix);
        if !self.baselines.contains_key(&key) && self.baselines.len() >= self.max_profile_count {
            self.evict_oldest_profile();
        }

        let profile = self.baselines.entry(key.clone()).or_default();
        *profile
            .event_distribution
            .entry(event_type.to_string())
            .or_insert(0) += 1;
        profile.sample_count = profile.sample_count.saturating_add(1);

        self.profile_last_seen_unix.insert(key.clone(), now);
        self.last_refresh_unix = now;

        let record = JournalDeltaRecord::new(
            self.journal_next_seq,
            process_key_to_string(&key),
            event_type.to_string(),
            1,
            now,
        );
        self.journal_next_seq = self.journal_next_seq.saturating_add(1);
        let _ = self.append_journal_record(&record);
    }

    pub fn init_entropy_baselines(&self) -> HashMap<(String, String), HashMap<String, f64>> {
        let mut out = HashMap::new();
        for (key, profile) in &self.baselines {
            let total = profile.sample_count.max(1) as f64;
            let mut dist = HashMap::new();
            for (event, count) in &profile.event_distribution {
                dist.insert(event.clone(), (*count as f64) / total);
            }
            out.insert((key.comm.clone(), key.parent_comm.clone()), dist);
        }
        out
    }

    pub fn check_transition_with_now(&mut self, now_unix: u64) -> Option<BaselineTransition> {
        match self.status {
            BaselineStatus::Learning => {
                if now_unix.saturating_sub(self.learning_started_unix) >= self.learning_window_secs
                {
                    self.status = BaselineStatus::Active;
                    self.learning_completed_unix = Some(now_unix);
                    for profile in self.baselines.values_mut() {
                        profile.entropy_threshold = derive_entropy_threshold(profile.sample_count);
                    }
                    self.last_refresh_unix = now_unix;
                    return Some(BaselineTransition::LearningComplete);
                }
            }
            BaselineStatus::Active => {
                if now_unix.saturating_sub(self.last_refresh_unix) >= self.stale_window_secs {
                    self.status = BaselineStatus::Stale;
                    return Some(BaselineTransition::BecameStale);
                }
            }
            BaselineStatus::Stale => {}
        }
        None
    }

    pub fn check_transition(&mut self) -> BaselineStoreResult<Option<BaselineTransition>> {
        Ok(self.check_transition_with_now(now_unix()?))
    }

    /// Force the baseline into Active status, bypassing the natural learning window.
    /// Used when server pushes `baseline_mode: "force_active"` or `"skip_learning"` via policy.
    pub fn force_active(&mut self, now_unix: u64) {
        self.status = BaselineStatus::Active;
        self.learning_completed_unix = Some(now_unix);
        self.last_refresh_unix = now_unix;
        for profile in self.baselines.values_mut() {
            profile.entropy_threshold = derive_entropy_threshold(profile.sample_count);
        }
    }

    pub fn seed_with_defaults_if_empty(&mut self) -> usize {
        if !self.baselines.is_empty() {
            return 0;
        }

        let now = now_unix().unwrap_or(self.last_refresh_unix);
        for (key, profile) in default_seed_profiles() {
            self.profile_last_seen_unix.insert(key.clone(), now);
            self.baselines.insert(key, profile);
        }
        self.last_refresh_unix = now;
        self.baselines.len()
    }

    pub fn seed_from_fleet_baseline(
        &mut self,
        process_key: &str,
        median_distribution: &HashMap<String, f64>,
        sample_count_hint: u64,
    ) -> bool {
        let Some(key) = parse_process_key(process_key) else {
            return false;
        };

        let existing_profile = self.baselines.get(&key).cloned();
        if let Some(existing) = existing_profile.as_ref() {
            // Mature local profiles must not be overwritten by fleet defaults.
            if existing.sample_count >= 1000 || existing.entropy_threshold > 0.0 {
                return false;
            }
        }

        let normalized = normalize_fleet_distribution(median_distribution);
        if normalized.is_empty() {
            return false;
        }

        let seed_sample_count = sample_count_hint.clamp(100, 5000).max(1000);

        // Bayesian Dirichlet-Multinomial conjugate prior merge.
        // The fleet distribution forms a Dirichlet prior with concentration parameter
        // that decays as local observations grow, letting local data dominate naturally.
        let local_sample_count = existing_profile
            .as_ref()
            .map(|p| p.sample_count)
            .unwrap_or(0);
        let decay_factor = (1.0 - (local_sample_count as f64 / 1000.0)).max(0.01);
        let concentration = seed_sample_count as f64 * decay_factor;

        // Posterior = Dirichlet prior (fleet alpha) + observed counts (local).
        let mut posterior: HashMap<String, f64> = HashMap::new();
        for (event_name, probability) in &normalized {
            posterior.insert(event_name.clone(), probability * concentration);
        }
        if let Some(existing) = &existing_profile {
            for (event_name, count) in &existing.event_distribution {
                *posterior.entry(event_name.clone()).or_insert(0.0) += *count as f64;
            }
        }

        // Convert posterior to integer counts for storage.
        let mut profile = ProcessProfile {
            event_distribution: HashMap::new(),
            sample_count: 0,
            entropy_threshold: 0.0,
        };
        for (event_name, value) in posterior {
            let count = (value.round() as u64).max(1);
            profile.event_distribution.insert(event_name, count);
            profile.sample_count = profile.sample_count.saturating_add(count);
        }
        if profile.sample_count == 0 {
            return false;
        }

        profile.entropy_threshold = derive_entropy_threshold(profile.sample_count);
        let now = now_unix().unwrap_or(self.last_refresh_unix);
        self.profile_last_seen_unix.insert(key.clone(), now);
        self.baselines.insert(key, profile);
        self.last_refresh_unix = now;
        true
    }

    fn evict_oldest_profile(&mut self) {
        let oldest_key = self
            .profile_last_seen_unix
            .iter()
            .min_by_key(|(_, ts)| **ts)
            .map(|(key, _)| key.clone())
            .or_else(|| self.baselines.keys().next().cloned());

        if let Some(key) = oldest_key {
            self.baselines.remove(&key);
            self.profile_last_seen_unix.remove(&key);
        }
    }

    fn append_journal_record(&self, record: &JournalDeltaRecord) -> BaselineStoreResult<()> {
        if let Some(parent) = self.journal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)?;
        serde_json::to_writer(&mut file, record)
            .map_err(|err| BaselineStoreError::Serialize(err.to_string()))?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    fn replay_journal_tail(&mut self) -> BaselineStoreResult<()> {
        if !self.journal_path.exists() {
            return Ok(());
        }

        let file = std::fs::File::open(&self.journal_path)?;
        let reader = BufReader::new(file);
        let mut latest_seq = self.snapshot_seq;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let record: JournalDeltaRecord = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => break,
            };
            if !record.verify() {
                break;
            }
            if record.seq <= self.snapshot_seq {
                latest_seq = latest_seq.max(record.seq);
                continue;
            }

            self.apply_journal_delta(&record);
            latest_seq = latest_seq.max(record.seq);
        }

        self.journal_next_seq = latest_seq.saturating_add(1);
        Ok(())
    }

    fn apply_journal_delta(&mut self, record: &JournalDeltaRecord) {
        let Some(key) = parse_process_key(&record.process_key) else {
            return;
        };
        if !self.baselines.contains_key(&key) && self.baselines.len() >= self.max_profile_count {
            self.evict_oldest_profile();
        }

        let profile = self.baselines.entry(key.clone()).or_default();
        let count = record.count.max(1);
        let entry = profile
            .event_distribution
            .entry(record.event_type.clone())
            .or_insert(0);
        *entry = entry.saturating_add(count);
        profile.sample_count = profile.sample_count.saturating_add(count);
        let observed_at = record.observed_at_unix.max(self.learning_started_unix);
        self.profile_last_seen_unix.insert(key, observed_at);
        self.last_refresh_unix = self.last_refresh_unix.max(observed_at);
    }

    fn should_compact_journal(&self, snapshot_size_bytes: usize) -> bool {
        let now = now_unix().unwrap_or(self.last_compaction_unix);
        if now.saturating_sub(self.last_compaction_unix) >= JOURNAL_COMPACTION_INTERVAL_SECS {
            return true;
        }

        let journal_size = std::fs::metadata(&self.journal_path)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        if snapshot_size_bytes == 0 {
            return journal_size > 0;
        }
        journal_size > (snapshot_size_bytes / 4)
    }

    fn compact_journal(&self) -> BaselineStoreResult<u64> {
        if let Some(parent) = self.journal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let before = std::fs::metadata(&self.journal_path)
            .map(|m| m.len())
            .unwrap_or(0);
        std::fs::write(&self.journal_path, b"")?;
        Ok(before)
    }
}

impl JournalDeltaRecord {
    fn new(
        seq: u64,
        process_key: String,
        event_type: String,
        count: u64,
        observed_at_unix: u64,
    ) -> Self {
        let count = count.max(1);
        let checksum = journal_checksum(seq, &process_key, &event_type, count, observed_at_unix);
        Self {
            seq,
            process_key,
            event_type,
            count,
            observed_at_unix,
            checksum,
        }
    }

    fn verify(&self) -> bool {
        self.checksum
            == journal_checksum(
                self.seq,
                &self.process_key,
                &self.event_type,
                self.count.max(1),
                self.observed_at_unix,
            )
    }
}

fn journal_checksum(
    seq: u64,
    process_key: &str,
    event_type: &str,
    count: u64,
    observed_at_unix: u64,
) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seq.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for byte in process_key.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0xff;
    hash = hash.wrapping_mul(0x100000001b3);
    for byte in event_type.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0xee;
    hash = hash.wrapping_mul(0x100000001b3);
    for byte in count.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0xdd;
    hash = hash.wrapping_mul(0x100000001b3);
    for byte in observed_at_unix.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn process_key_to_string(key: &ProcessKey) -> String {
    format!("{}:{}", key.comm, key.parent_comm)
}

fn journal_path_for(path: &Path) -> PathBuf {
    let mut out = path.to_path_buf();
    out.set_extension("journal");
    out
}

fn journal_meta_path_for(path: &Path) -> PathBuf {
    let mut out = path.to_path_buf();
    out.set_extension("journal.meta");
    out
}

fn load_journal_meta(path: &Path) -> BaselineStoreResult<JournalMeta> {
    if !path.exists() {
        return Ok(JournalMeta::default());
    }

    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|err| BaselineStoreError::Deserialize(err.to_string()))
}

fn write_journal_meta(path: &Path, meta: &JournalMeta) -> BaselineStoreResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes =
        serde_json::to_vec(meta).map_err(|err| BaselineStoreError::Serialize(err.to_string()))?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn now_unix() -> BaselineStoreResult<u64> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| BaselineStoreError::Time(err.to_string()))?;
    Ok(dur.as_secs())
}

fn derive_entropy_threshold(sample_count: u64) -> f64 {
    let x = (sample_count as f64).max(1.0);
    1.0 + x.log10()
}

fn default_seed_profiles() -> Vec<(ProcessKey, ProcessProfile)> {
    vec![
        seed_profile(
            "bash",
            "sshd",
            &[
                ("process_exec", 30),
                ("file_open", 25),
                ("network_connect", 5),
                ("dns_query", 2),
                ("alert", 1),
            ],
        ),
        seed_profile(
            "nginx",
            "systemd",
            &[
                ("process_exec", 1),
                ("file_open", 15),
                ("network_connect", 60),
                ("dns_query", 10),
                ("module_load", 5),
            ],
        ),
        seed_profile(
            "python3",
            "bash",
            &[
                ("process_exec", 10),
                ("file_open", 30),
                ("network_connect", 20),
                ("dns_query", 5),
                ("module_load", 10),
            ],
        ),
        seed_profile(
            "apt",
            "systemd",
            &[
                ("process_exec", 5),
                ("file_open", 45),
                ("network_connect", 15),
                ("dns_query", 10),
                ("module_load", 5),
            ],
        ),
        seed_profile(
            "systemd",
            "kernel",
            &[
                ("process_exec", 20),
                ("file_open", 20),
                ("network_connect", 8),
                ("dns_query", 1),
                ("module_load", 12),
            ],
        ),
    ]
}

fn parse_process_key(raw: &str) -> Option<ProcessKey> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }

    if let Some((comm, parent)) = value.split_once(':') {
        let comm = comm.trim();
        let parent = parent.trim();
        if !comm.is_empty() && !parent.is_empty() {
            return Some(ProcessKey {
                comm: comm.to_string(),
                parent_comm: parent.to_string(),
            });
        }
    }

    let comm = Path::new(value)
        .file_name()
        .and_then(|v| v.to_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(value)
        .to_string();

    if comm.is_empty() {
        return None;
    }

    Some(ProcessKey {
        comm,
        parent_comm: "fleet".to_string(),
    })
}

fn normalize_fleet_distribution(input: &HashMap<String, f64>) -> HashMap<String, f64> {
    let mut non_negative = HashMap::new();
    let mut total = 0.0;
    for (event_name, probability) in input {
        if !probability.is_finite() || *probability <= 0.0 {
            continue;
        }
        non_negative.insert(event_name.clone(), *probability);
        total += *probability;
    }

    if total <= f64::EPSILON {
        return HashMap::new();
    }

    for probability in non_negative.values_mut() {
        *probability /= total;
    }
    non_negative
}

fn seed_profile(
    comm: &str,
    parent_comm: &str,
    counts: &[(&str, u64)],
) -> (ProcessKey, ProcessProfile) {
    let mut event_distribution = HashMap::new();
    for (event, count) in counts {
        event_distribution.insert((*event).to_string(), *count);
    }

    let sample_count = event_distribution.values().sum();
    (
        ProcessKey {
            comm: comm.to_string(),
            parent_comm: parent_comm.to_string(),
        },
        ProcessProfile {
            event_distribution,
            sample_count,
            entropy_threshold: derive_entropy_threshold(sample_count),
        },
    )
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_seed;
