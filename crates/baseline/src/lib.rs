use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const LEARNING_WINDOW_SECS: u64 = 7 * 24 * 3600;
const STALE_WINDOW_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessKey {
    pub comm: String,
    pub parent_comm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessProfile {
    pub event_distribution: HashMap<String, u64>,
    pub sample_count: u64,
    pub entropy_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStore {
    pub status: BaselineStatus,
    pub learning_started_unix: u64,
    pub learning_completed_unix: Option<u64>,
    pub last_refresh_unix: u64,
    pub baselines: HashMap<ProcessKey, ProcessProfile>,
    #[serde(skip)]
    path: PathBuf,
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
        Ok(Self {
            status: BaselineStatus::Learning,
            learning_started_unix: now,
            learning_completed_unix: None,
            last_refresh_unix: now,
            baselines: HashMap::new(),
            path: path.into(),
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
        let mut store: BaselineStore = bincode::deserialize(&bytes)
            .map_err(|err| BaselineStoreError::Deserialize(err.to_string()))?;
        store.path = path.to_path_buf();
        Ok(store)
    }

    pub fn save(&self) -> BaselineStoreResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = bincode::serialize(self)
            .map_err(|err| BaselineStoreError::Serialize(err.to_string()))?;
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn learn_event(&mut self, key: ProcessKey, event_type: &str) {
        let profile = self.baselines.entry(key).or_default();
        *profile
            .event_distribution
            .entry(event_type.to_string())
            .or_insert(0) += 1;
        profile.sample_count = profile.sample_count.saturating_add(1);
        self.last_refresh_unix = now_unix().unwrap_or(self.last_refresh_unix);
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
                if now_unix.saturating_sub(self.learning_started_unix) >= LEARNING_WINDOW_SECS {
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
                if now_unix.saturating_sub(self.last_refresh_unix) >= STALE_WINDOW_SECS {
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

    pub fn seed_with_defaults_if_empty(&mut self) -> usize {
        if !self.baselines.is_empty() {
            return 0;
        }

        for (key, profile) in default_seed_profiles() {
            self.baselines.insert(key, profile);
        }
        self.last_refresh_unix = now_unix().unwrap_or(self.last_refresh_unix);
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
        if self.baselines.contains_key(&key) {
            return false;
        }

        let normalized = normalize_fleet_distribution(median_distribution);
        if normalized.is_empty() {
            return false;
        }

        let seed_sample_count = sample_count_hint.clamp(100, 5000).max(1000);
        let mut profile = ProcessProfile {
            event_distribution: HashMap::new(),
            sample_count: 0,
            entropy_threshold: 0.0,
        };

        for (event_name, probability) in normalized {
            let count = ((probability * seed_sample_count as f64).round() as u64).max(1);
            profile.event_distribution.insert(event_name, count);
            profile.sample_count = profile.sample_count.saturating_add(count);
        }
        if profile.sample_count == 0 {
            return false;
        }

        profile.entropy_threshold = derive_entropy_threshold(profile.sample_count);
        self.baselines.insert(key, profile);
        self.last_refresh_unix = now_unix().unwrap_or(self.last_refresh_unix);
        true
    }
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
