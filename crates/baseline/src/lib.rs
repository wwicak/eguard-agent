use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
