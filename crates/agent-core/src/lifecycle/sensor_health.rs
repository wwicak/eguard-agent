use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

use aes_gcm::aead::{rand_core::RngCore, OsRng};
use grpc_client::pb::{SensorHealthReport, SensorProbe};
use platform_linux::EbpfEngine;

struct SensorHealthSequence {
    epoch: String,
    sequence: AtomicU64,
}

impl SensorHealthSequence {
    fn new() -> Option<Self> {
        let mut bytes = [0u8; 16];
        if let Err(err) = OsRng.try_fill_bytes(&mut bytes) {
            tracing::warn!(%err, "unable to generate sensor-health epoch");
            return None;
        }
        Some(Self {
            epoch: format!("{:032x}", u128::from_be_bytes(bytes)),
            sequence: AtomicU64::new(0),
        })
    }

    fn report(&self, engine: &EbpfEngine, now_unix: i64) -> SensorHealthReport {
        let (transport, probes, loss) = engine.sensor_health();
        let mut bounded = Vec::new();
        let mut incomplete = false;
        for probe in probes {
            if bounded.len() >= 63
                || probe.name.is_empty()
                || probe.name.len() > 96
                || !probe
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                incomplete = true;
                continue;
            }
            if !bounded.iter().any(|p: &SensorProbe| p.name == probe.name) {
                bounded.push(SensorProbe {
                    name: probe.name,
                    status: probe.status.to_string(),
                    reason: probe.reason.to_string(),
                });
            }
        }
        if incomplete {
            bounded.push(SensorProbe {
                name: "sensor_health.inventory".to_string(),
                status: "failed".to_string(),
                reason: "probe_inventory_incomplete".to_string(),
            });
        }
        SensorHealthReport {
            epoch: self.epoch.clone(),
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            observed_at_unix: now_unix,
            transport: transport.to_string(),
            probes: bounded,
            // Use integers that can be compared exactly by JSON readers, including JavaScript.
            kernel_drops: loss.kernel_drops.min((1 << 53) - 1),
            perf_lost_samples: loss.perf_lost_samples.min((1 << 53) - 1),
            pending_queue_evictions: loss.pending_queue_evictions.min((1 << 53) - 1),
        }
    }
}

pub(super) fn sensor_health_report(
    engine: &EbpfEngine,
    now_unix: i64,
) -> Option<SensorHealthReport> {
    static SEQUENCE: OnceLock<Option<SensorHealthSequence>> = OnceLock::new();
    SEQUENCE
        .get_or_init(SensorHealthSequence::new)
        .as_ref()
        .map(|s| s.report(engine, now_unix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensor_health_epoch_and_sequence_are_process_scoped() {
        let first = SensorHealthSequence::new().unwrap();
        let restarted = SensorHealthSequence::new().unwrap();
        let mut engine = EbpfEngine::disabled();
        engine.record_skipped_lsm(true);
        let initial = first.report(&engine, 10);
        let next = first.report(&engine, 11);
        let after_restart = restarted.report(&engine, 12);
        assert_eq!(
            (initial.sequence, next.sequence, after_restart.sequence),
            (1, 2, 1)
        );
        assert_eq!(initial.epoch, next.epoch);
        assert_ne!(initial.epoch, after_restart.epoch);
        assert_eq!(initial.epoch.len(), 32);
        assert_eq!(next.observed_at_unix, 11);
        assert_eq!(next.transport, "none");
        assert!(next
            .probes
            .iter()
            .any(|p| p.name == "eguard_bprm_check" && p.status == "unsupported"));
        assert!(next
            .probes
            .iter()
            .any(|p| p.name == "ebpf_backend" && p.status == "failed"));
    }
}
