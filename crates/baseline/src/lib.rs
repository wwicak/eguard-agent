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

#[cfg(test)]
mod tests;
