use std::time::Duration;

use super::types::{PollBatch, Result};

pub(super) trait RingBufferBackend {
    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch>;

    fn reclaim_raw_records(&mut self, _records: Vec<Vec<u8>>) {}

    #[allow(dead_code)]
    fn failed_probes(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Default)]
pub(super) struct NoopRingBufferBackend;

impl RingBufferBackend for NoopRingBufferBackend {
    fn poll_raw_events(&mut self, _timeout: Duration) -> Result<PollBatch> {
        Ok(PollBatch::default())
    }
}
