//! One bounded, alert-only file scanner shared by an agent's detection shards.
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::time::Instant;

pub const QUEUE_CAPACITY: usize = 64;
const BYTES_PER_SECOND: u64 = 16 * 1024 * 1024;

#[derive(Default)]
struct Counters {
    depth: AtomicU64,
    high_water: AtomicU64,
    queue_full: AtomicU64,
    byte_skips: AtomicU64,
    time_skips: AtomicU64,
    cap_skips: AtomicU64,
    stale: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    overflow: AtomicU64,
}
impl Counters {
    fn health(&self) -> String {
        format!("yara_queue_depth={} yara_queue_high_water={} yara_queue_full_skips={} yara_byte_budget_skips={} yara_time_budget_skips={} yara_cap_skips={} yara_stale_pack_discards={} yara_first_hits={} yara_first_misses={} yara_result_overflow={}",
            self.depth.load(Ordering::Relaxed), self.high_water.load(Ordering::Relaxed),
            self.queue_full.load(Ordering::Relaxed), self.byte_skips.load(Ordering::Relaxed),
            self.time_skips.load(Ordering::Relaxed), self.cap_skips.load(Ordering::Relaxed),
            self.stale.load(Ordering::Relaxed), self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed), self.overflow.load(Ordering::Relaxed))
    }
}

pub struct YaraScanResult {
    pub event: TelemetryEvent,
    pub observation_id: Option<String>,
    pub hits: Vec<YaraHit>,
    pub incomplete: Vec<YaraIncomplete>,
    pub pack_hash: String,
    pub sha256: String,
    pub scan_latency_ms: u64,
    active: Arc<AtomicBool>,
}
struct Request {
    engine: Arc<YaraEngine>,
    active: Arc<AtomicBool>,
    event: TelemetryEvent,
    observation_id: Option<String>,
    key: FileKey,
    queued: Instant,
}
enum Command {
    Scan(Request),
    Drain(mpsc::Sender<()>),
    #[cfg(test)]
    Hold(mpsc::Receiver<()>, mpsc::Sender<()>),
}
struct Inner {
    tx: Option<mpsc::SyncSender<Command>>,
    results: Mutex<mpsc::Receiver<YaraScanResult>>,
    result_tx: mpsc::SyncSender<YaraScanResult>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.tx.take();
        // Only final shutdown joins; pack swaps never wait for a scanner.
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
#[derive(Clone)]
pub struct YaraWorker {
    inner: Arc<Inner>,
}
impl Default for YaraWorker {
    fn default() -> Self {
        Self::new()
    }
}
impl YaraWorker {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (result_tx, results) = mpsc::sync_channel(QUEUE_CAPACITY);
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_counters, worker_stop, worker_results) =
            (counters.clone(), stop.clone(), result_tx.clone());
        let join = std::thread::Builder::new()
            .name("eguard-yara-scan".into())
            .spawn(move || {
                let mut budget = ByteBudget {
                    available: BYTES_PER_SECOND,
                    updated: Instant::now(),
                };
                while let Ok(command) = rx.recv() {
                    #[cfg(test)]
                    if let Command::Hold(release, entered) = command {
                        let _ = entered.send(());
                        let _ = release.recv();
                        continue;
                    }
                    if let Command::Drain(done) = command {
                        let _ = done.send(());
                        continue;
                    }
                    let Command::Scan(request) = command else {
                        continue;
                    };
                    worker_counters.depth.fetch_sub(1, Ordering::Relaxed);
                    if worker_stop.load(Ordering::Acquire) {
                        continue;
                    }
                    if !request.active.load(Ordering::Acquire) {
                        worker_counters.stale.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if !budget.take(request.key.size, Instant::now()) {
                        worker_counters.byte_skips.fetch_add(1, Ordering::Relaxed);
                        request
                            .engine
                            .status
                            .budget_skip(request.event.event_class == EventClass::ProcessExec);
                        continue;
                    }
                    let before_budget = budget_skips(&request.engine.status);
                    let before_cap = cap_skips(&request.engine.status);
                    let hits = request
                        .engine
                        .scan_file_event(&request.event, Some(&request.key));
                    worker_counters.time_skips.fetch_add(
                        budget_skips(&request.engine.status).saturating_sub(before_budget),
                        Ordering::Relaxed,
                    );
                    worker_counters.cap_skips.fetch_add(
                        cap_skips(&request.engine.status).saturating_sub(before_cap),
                        Ordering::Relaxed,
                    );
                    let incomplete = request.engine.take_incomplete();
                    if !request.active.load(Ordering::Acquire) {
                        worker_counters.stale.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    emit(
                        &worker_results,
                        &worker_counters,
                        YaraScanResult {
                            sha256: cached_digest(&request.engine, &request.key),
                            pack_hash: digest_hex(&request.engine.backend.pack_hash()),
                            scan_latency_ms: request
                                .queued
                                .elapsed()
                                .as_millis()
                                .min(u64::MAX as u128)
                                as u64,
                            event: request.event,
                            observation_id: request.observation_id,
                            hits,
                            incomplete,
                            active: request.active,
                        },
                    );
                }
            })
            .expect("spawn YARA file worker");
        Self {
            inner: Arc::new(Inner {
                tx: Some(tx),
                results: Mutex::new(results),
                result_tx,
                counters,
                stop,
                join: Some(join),
            }),
        }
    }
    pub fn shutdown(&self) {
        self.inner.stop.store(true, Ordering::Release);
    }
    pub fn health(&self) -> String {
        self.inner.counters.health()
    }
    pub fn submit(
        &self,
        engine: Arc<YaraEngine>,
        active: Arc<AtomicBool>,
        event: &TelemetryEvent,
        observation_id: Option<String>,
    ) {
        if self.inner.stop.load(Ordering::Acquire) {
            return;
        }
        let Some(path) = engine.eligible_path(event) else {
            return;
        };
        if event.event_class == EventClass::FileOpen && event.file_write {
            engine
                .verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|(key, _, _), _| key.path != path);
        }
        let Some(key) = FileKey::at_path(path) else {
            return;
        };
        if key.size > MAX_EXECUTABLE_SCAN_BYTES as u64 {
            self.inner
                .counters
                .cap_skips
                .fetch_add(1, Ordering::Relaxed);
            engine
                .status
                .size_skip(event.event_class == EventClass::ProcessExec);
            return;
        }
        if let Some(hits) = engine.cached_metadata(&key) {
            self.inner.counters.hits.fetch_add(1, Ordering::Relaxed);
            // A warm exec never consumes a request slot or a byte/CPU permit.
            emit(
                &self.inner.result_tx,
                &self.inner.counters,
                YaraScanResult {
                    sha256: cached_digest(&engine, &key),
                    pack_hash: digest_hex(&engine.backend.pack_hash()),
                    scan_latency_ms: 0,
                    event: event.clone(),
                    observation_id,
                    hits,
                    incomplete: Vec::new(),
                    active,
                },
            );
            return;
        }
        self.inner.counters.misses.fetch_add(1, Ordering::Relaxed);
        let depth = self.inner.counters.depth.fetch_add(1, Ordering::Relaxed) + 1;
        let request = Command::Scan(Request {
            engine: engine.clone(),
            active,
            event: event.clone(),
            observation_id,
            key,
            queued: Instant::now(),
        });
        if self.inner.tx.as_ref().unwrap().try_send(request).is_err() {
            self.inner.counters.depth.fetch_sub(1, Ordering::Relaxed);
            self.inner
                .counters
                .queue_full
                .fetch_add(1, Ordering::Relaxed);
            engine
                .status
                .budget_skip(event.event_class == EventClass::ProcessExec);
        } else {
            self.inner
                .counters
                .high_water
                .fetch_max(depth.min(QUEUE_CAPACITY as u64), Ordering::Relaxed);
        }
    }
    pub fn take_results(&self) -> Vec<YaraScanResult> {
        let mut out = Vec::new();
        for result in self
            .inner
            .results
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .try_iter()
            .take(QUEUE_CAPACITY)
        {
            if result.active.load(Ordering::Acquire) {
                out.push(result);
            } else {
                self.inner.counters.stale.fetch_add(1, Ordering::Relaxed);
            }
        }
        out
    }
    #[doc(hidden)]
    pub fn drain_for_tests(&self) {
        let (tx, rx) = mpsc::channel();
        self.inner
            .tx
            .as_ref()
            .unwrap()
            .send(Command::Drain(tx))
            .unwrap();
        rx.recv().unwrap();
    }
}
fn budget_skips(status: &YaraStatus) -> u64 {
    status.budget_executable.load(Ordering::Relaxed) + status.budget_other.load(Ordering::Relaxed)
}
fn cap_skips(status: &YaraStatus) -> u64 {
    status.size_executable.load(Ordering::Relaxed) + status.size_other.load(Ordering::Relaxed)
}
fn emit(tx: &mpsc::SyncSender<YaraScanResult>, counters: &Counters, result: YaraScanResult) {
    if result.hits.is_empty() && result.incomplete.is_empty() {
        return;
    }
    if tx.try_send(result).is_err() {
        counters.overflow.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;

fn cached_digest(engine: &YaraEngine, key: &FileKey) -> String {
    let pack = engine.backend.pack_hash();
    engine
        .verdicts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .keys()
        .find(|(cached, _, hash)| cached == key && *hash == pack)
        .map(|(_, digest, _)| digest_hex(digest))
        .unwrap_or_default()
}

struct ByteBudget {
    available: u64,
    updated: Instant,
}
impl ByteBudget {
    fn take(&mut self, size: u64, now: Instant) -> bool {
        let refill = (now.duration_since(self.updated).as_nanos() * BYTES_PER_SECOND as u128
            / 1_000_000_000)
            .min(u64::MAX as u128) as u64;
        self.available = self.available.saturating_add(refill).min(BYTES_PER_SECOND);
        self.updated = now;
        if size > self.available {
            return false;
        }
        self.available -= size;
        true
    }
}
