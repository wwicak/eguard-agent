use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use tracing::{info, warn};

use baseline::{BaselineStatus, BaselineStore};
use detection::EventClass;

use crate::detection_state::SharedDetectionState;

pub(super) fn load_baseline_store() -> Result<BaselineStore> {
    let default_path = "/var/lib/eguard-agent/baselines.bin".to_string();
    let configured_path = std::env::var("EGUARD_BASELINE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(default_path);
    let path = PathBuf::from(configured_path);

    let skip_learning = std::env::var("EGUARD_BASELINE_SKIP_LEARNING")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    match BaselineStore::load_or_new(path.clone()) {
        Ok(mut store) => {
            seed_default_baselines_if_needed(&mut store, &path);
            if skip_learning && matches!(store.status, BaselineStatus::Learning) {
                store.status = BaselineStatus::Active;
                info!("baseline learning skipped via EGUARD_BASELINE_SKIP_LEARNING");
            }
            Ok(store)
        }
        Err(err) => {
            warn!(error = %err, path = %path.display(), "failed loading baseline store, using temp fallback");
            let fallback = std::env::temp_dir().join("eguard-agent-baselines.bin");
            let mut store =
                BaselineStore::load_or_new(fallback.clone()).map_err(|fallback_err| {
                    anyhow!(
                        "failed to initialize baseline store at {} and fallback {}: {} / {}",
                        path.display(),
                        fallback.display(),
                        err,
                        fallback_err
                    )
                })?;
            seed_default_baselines_if_needed(&mut store, &fallback);
            Ok(store)
        }
    }
}

fn seed_default_baselines_if_needed(store: &mut BaselineStore, path: &Path) {
    let seeded = store.seed_with_defaults_if_empty();
    if seeded == 0 {
        return;
    }

    info!(
        seeded_profiles = seeded,
        path = %path.display(),
        "initialized baseline store with built-in seed baselines"
    );
    if let Err(err) = store.save() {
        warn!(
            error = %err,
            path = %path.display(),
            "failed to persist seeded baseline store"
        );
    }
}

pub(super) fn seed_anomaly_baselines(
    detection_state: &SharedDetectionState,
    baseline_store: &BaselineStore,
) -> Result<()> {
    let mut seeded = 0usize;
    for ((comm, parent), distribution) in baseline_store.init_entropy_baselines() {
        let mut parsed = HashMap::new();
        for (event_name, probability) in distribution {
            if let Some(event_class) = parse_event_class_name(&event_name) {
                parsed.insert(event_class, probability);
            }
        }
        if parsed.is_empty() {
            continue;
        }

        detection_state.set_anomaly_baseline(format!("{}:{}", comm, parent), parsed)?;
        seeded += 1;
    }

    if seeded > 0 {
        info!(
            seeded_baselines = seeded,
            "initialized anomaly baselines from baseline store"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn apply_fleet_baseline_seeds(
    baseline_store: &mut BaselineStore,
    fleet_baselines: &[grpc_client::FleetBaselineEnvelope],
) -> usize {
    let mut seeded = 0usize;
    for baseline in fleet_baselines {
        let sample_hint = (baseline.agent_count.max(1) as u64).saturating_mul(100);
        if baseline_store.seed_from_fleet_baseline(
            &baseline.process_key,
            &baseline.median_distribution,
            sample_hint,
        ) {
            seeded = seeded.saturating_add(1);
        }
    }
    seeded
}

fn parse_event_class_name(raw: &str) -> Option<EventClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "process_exec" => Some(EventClass::ProcessExec),
        "process_exit" => Some(EventClass::ProcessExit),
        "file_open" => Some(EventClass::FileOpen),
        "network_connect" | "tcp_connect" => Some(EventClass::NetworkConnect),
        "dns_query" => Some(EventClass::DnsQuery),
        "module_load" => Some(EventClass::ModuleLoad),
        "login" => Some(EventClass::Login),
        "alert" => Some(EventClass::Alert),
        _ => None,
    }
}
