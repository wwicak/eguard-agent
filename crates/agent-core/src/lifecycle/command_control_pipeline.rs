use std::time::{Duration, Instant};

use tokio::time::timeout;
use tracing::{debug, warn};

use super::{
    elapsed_micros, interval_due, AgentRuntime, PendingCommand, COMMAND_BACKLOG_CAPACITY,
    COMMAND_EXECUTION_BUDGET_PER_TICK, COMMAND_FETCH_INTERVAL_SECS, COMMAND_FETCH_LIMIT,
};

const COMMAND_FETCH_TIMEOUT_MS: u64 = 2_000;

impl AgentRuntime {
    pub(super) async fn run_connected_command_stage(&mut self, now_unix: i64) {
        let command_sync_started = Instant::now();
        debug!(now_unix, pending_commands = self.pending_commands.len(), "command sync stage start");
        self.flush_update_outcome_reports().await;
        debug!(now_unix, pending_commands = self.pending_commands.len(), "command outcome flush complete");
        self.sync_pending_commands(now_unix).await;
        debug!(now_unix, pending_commands = self.pending_commands.len(), "command sync stage complete");
        self.metrics.last_command_sync_micros = elapsed_micros(command_sync_started);
    }

    async fn sync_pending_commands(&mut self, now_unix: i64) {
        let fetched = self.fetch_command_backlog_batch(now_unix).await;
        let executed = self.execute_command_backlog_budget(now_unix).await;
        let oldest_age_secs = self.command_backlog_oldest_age_secs(now_unix);

        self.metrics.last_command_fetch_count = fetched;
        self.metrics.last_command_execute_count = executed;
        self.metrics.last_command_backlog_depth = self.pending_commands.len();
        self.metrics.max_command_backlog_depth = self
            .metrics
            .max_command_backlog_depth
            .max(self.pending_commands.len());
        self.metrics.last_command_backlog_oldest_age_secs = oldest_age_secs;
        self.metrics.max_command_backlog_oldest_age_secs = self
            .metrics
            .max_command_backlog_oldest_age_secs
            .max(oldest_age_secs);
    }

    async fn fetch_command_backlog_batch(&mut self, now_unix: i64) -> usize {
        if !self.pending_commands.is_empty() {
            return 0;
        }

        if !interval_due(
            self.last_command_fetch_attempt_unix,
            now_unix,
            COMMAND_FETCH_INTERVAL_SECS,
        ) {
            return 0;
        }
        self.last_command_fetch_attempt_unix = Some(now_unix);

        if self.pending_commands.len() >= COMMAND_BACKLOG_CAPACITY {
            warn!(
                backlog = self.pending_commands.len(),
                capacity = COMMAND_BACKLOG_CAPACITY,
                "command backlog reached capacity; deferring command fetch"
            );
            return 0;
        }

        let available_capacity = COMMAND_BACKLOG_CAPACITY - self.pending_commands.len();
        let fetch_limit = COMMAND_FETCH_LIMIT.min(available_capacity);
        if fetch_limit == 0 {
            return 0;
        }

        let completed_cursor = self.completed_command_cursor();
        debug!(
            now_unix,
            fetch_limit,
            completed_cursor_len = completed_cursor.len(),
            "fetching command backlog"
        );
        match timeout(
            Duration::from_millis(COMMAND_FETCH_TIMEOUT_MS),
            self.client
                .fetch_commands(&self.config.agent_id, &completed_cursor, fetch_limit),
        )
        .await
        {
            Ok(Ok(commands)) => {
                let fetched = commands.len();
                debug!(now_unix, fetched, "command fetch returned");
                self.pending_commands
                    .extend(commands.into_iter().map(|envelope| PendingCommand {
                        envelope,
                        enqueued_at_unix: now_unix,
                    }));
                fetched
            }
            Ok(Err(err)) => {
                warn!(error = %err, "command fetch failed");
                0
            }
            Err(_) => {
                warn!(timeout_ms = COMMAND_FETCH_TIMEOUT_MS, "command fetch timed out");
                0
            }
        }
    }

    async fn execute_command_backlog_budget(&mut self, now_unix: i64) -> usize {
        let mut executed = 0usize;
        while executed < COMMAND_EXECUTION_BUDGET_PER_TICK {
            let Some(command) = self.pending_commands.pop_front() else {
                break;
            };

            self.handle_command(command.envelope, now_unix).await;
            executed = executed.saturating_add(1);
        }

        executed
    }

    fn command_backlog_oldest_age_secs(&self, now_unix: i64) -> u64 {
        let Some(oldest) = self.pending_commands.front() else {
            return 0;
        };

        now_unix.saturating_sub(oldest.enqueued_at_unix).max(0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;

    #[tokio::test]
    async fn fetch_command_backlog_batch_times_out_without_wedging_runtime() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock command server");
        let addr = listener.local_addr().expect("mock server addr");

        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept client");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut cfg = AgentConfig::default();
        cfg.transport_mode = "http".to_string();
        cfg.server_addr = addr.to_string();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;

        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        let started = Instant::now();
        let fetched = runtime.fetch_command_backlog_batch(1_700_000_000).await;
        let elapsed = started.elapsed();

        assert_eq!(fetched, 0);
        assert!(runtime.pending_commands.is_empty());
        assert!(
            elapsed < Duration::from_secs(4),
            "command fetch should time out promptly, elapsed={elapsed:?}"
        );

        server.abort();
    }
}
