use std::time::Instant;

use anyhow::Result;
use tracing::{info, warn};

use super::{
    compute_poll_timeout, compute_sampling_stride, elapsed_micros, AgentRuntime, DegradedCause,
    EventEnvelope, RawEvent, TickEvaluation, DEGRADE_AFTER_SEND_FAILURES, EVENT_BATCH_SIZE,
};

impl AgentRuntime {
    pub(super) async fn run_connected_telemetry_stage(
        &mut self,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let Some(evaluation) = evaluation else {
            return Ok(());
        };

        let send_batch_started = Instant::now();
        self.send_event_batch(evaluation.event_envelope.clone())
            .await?;
        self.metrics.last_send_event_batch_micros = elapsed_micros(send_batch_started);
        Ok(())
    }

    pub(super) async fn send_event_batch(&mut self, envelope: EventEnvelope) -> Result<()> {
        let send_started = Instant::now();
        let pending_before = self.buffer.pending_count();
        let mut batch = self.buffer.drain_batch(EVENT_BATCH_SIZE)?;
        batch.push(envelope);

        if let Err(err) = self.client.send_events(&batch).await {
            for ev in batch {
                self.buffer.enqueue(ev)?;
            }

            self.consecutive_send_failures = self.consecutive_send_failures.saturating_add(1);
            if self.consecutive_send_failures >= DEGRADE_AFTER_SEND_FAILURES {
                self.transition_to_degraded(DegradedCause::SendFailures);
            }

            warn!(
                error = %err,
                pending = self.buffer.pending_count(),
                "send failed, events re-buffered"
            );
        } else {
            self.consecutive_send_failures = 0;
            if std::env::var("EGUARD_DEBUG_OFFLINE_LOG")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some()
            {
                info!(
                    pending_before,
                    pending_after = self.buffer.pending_count(),
                    sent = batch.len(),
                    "offline buffer flushed"
                );
            }
        }

        self.metrics.last_send_event_batch_micros = elapsed_micros(send_started);
        Ok(())
    }

    pub(super) fn next_raw_event(&mut self) -> Option<RawEvent> {
        let timeout = self.adaptive_poll_timeout();
        let sampling_stride =
            compute_sampling_stride(self.buffer.pending_count(), self.recent_ebpf_drops);
        let polled = self.ebpf_engine.poll_once(timeout);
        self.observe_ebpf_stats();

        match polled {
            Ok(events) => {
                if sampling_stride > 1 {
                    info!(
                        sampling_stride,
                        backlog = self.buffer.pending_count(),
                        recent_ebpf_drops = self.recent_ebpf_drops,
                        "applying statistical sampling due to backpressure"
                    );
                }
                events.into_iter().step_by(sampling_stride).next()
            }
            Err(err) => {
                warn!(error = %err, "eBPF poll failed; skipping telemetry event for this tick");
                None
            }
        }
    }

    fn adaptive_poll_timeout(&self) -> std::time::Duration {
        compute_poll_timeout(self.buffer.pending_count(), self.recent_ebpf_drops)
    }

    fn observe_ebpf_stats(&mut self) {
        let stats = self.ebpf_engine.stats();
        self.recent_ebpf_drops = stats
            .events_dropped
            .saturating_sub(self.last_ebpf_stats.events_dropped);
        self.last_ebpf_stats = stats;
    }
}
