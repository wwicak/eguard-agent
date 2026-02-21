mod async_workers;
mod baseline;
mod bundle_support;
mod compliance;
mod constants;
mod detection_event;
mod ebpf_support;
mod emergency_rule;
mod enrollment;
mod inventory;
mod kernel_integrity_scan;
mod memory_scan;
mod policy;
mod response_actions;
mod runtime;
mod runtime_mode;
mod self_protect;
mod telemetry;
mod tick;
mod timing;
mod types;

mod bundle_path;
mod command_control_pipeline;
mod command_pipeline;
mod control_plane_pipeline;
mod detection_bootstrap;
mod ebpf_bootstrap;
mod response_pipeline;
mod rule_bundle_loader;
mod rule_bundle_verify;
mod telemetry_pipeline;
mod threat_intel_pipeline;

pub use runtime::AgentRuntime;
pub use types::RuntimeObservabilitySnapshot;

#[allow(unused_imports)]
use constants::*;
#[allow(unused_imports)]
use types::{
    AsyncWorkerResult, ControlPlaneTaskKind, DegradedCause, EmergencyRulePayload,
    LocalActionResult, PendingCommand, PendingControlPlaneSend, PendingControlPlaneTask,
    PendingResponseAction, PendingResponseReport, ReloadReport, RuntimeMetrics, TickEvaluation,
};

#[allow(unused_imports)]
use crate::platform::RawEvent;
#[allow(unused_imports)]
use ::compliance::ComplianceResult;
#[allow(unused_imports)]
use ::detection::{
    Confidence, DetectionEngine, DetectionOutcome, EventClass, RansomwarePolicy, TelemetryEvent,
};
#[allow(unused_imports)]
use ::grpc_client::{ComplianceEnvelope, EventEnvelope, ResponseEnvelope};
#[allow(unused_imports)]
use ::response::{
    evaluate_auto_isolation, execute_server_command_with_state, PlannedAction, ServerCommand,
};

#[allow(unused_imports)]
use timing::{
    compute_poll_timeout, compute_sampling_stride, elapsed_micros, interval_due, now_unix,
    resolve_detection_shard_count,
};

#[allow(unused_imports)]
use detection_event::{
    confidence_label, confidence_to_severity, map_event_class, to_detection_event,
};

#[cfg(test)]
#[allow(unused_imports)]
use baseline::apply_fleet_baseline_seeds;
#[allow(unused_imports)]
use baseline::{load_baseline_store, seed_anomaly_baselines};

#[cfg(test)]
#[allow(unused_imports)]
use policy::{days_until_certificate_expiry, parse_certificate_not_after_unix};
#[allow(unused_imports)]
use policy::{load_compliance_policy, update_tls_policy_from_server};

#[allow(unused_imports)]
use runtime_mode::{derive_runtime_mode, runtime_mode_label};

#[allow(unused_imports)]
use ebpf_support::init_ebpf_engine;
#[cfg(test)]
#[allow(unused_imports)]
use ebpf_support::{candidate_ebpf_object_paths, default_ebpf_objects_dirs};

#[allow(unused_imports)]
use bundle_path::resolve_rules_staging_root;
#[allow(unused_imports)]
use bundle_support::{
    build_ransomware_policy, is_signed_bundle_archive, load_bundle_full, verify_bundle_signature,
};
#[cfg(test)]
#[allow(unused_imports)]
use bundle_support::{
    load_bundle_rules, sanitize_archive_relative_path, verify_bundle_signature_with_material,
};

#[allow(unused_imports)]
use emergency_rule::parse_emergency_rule_type;

#[allow(unused_imports)]
use response_actions::remediation_check_type;

#[cfg(test)]
pub(crate) fn shared_env_var_lock() -> &'static std::sync::Mutex<()> {
    crate::test_support::env_lock()
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_ebpf_policy;

#[cfg(test)]
mod tests_baseline_seed_policy;

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_det_stub_completion;
#[cfg(test)]
mod tests_ebpf_memory;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_observability;
#[cfg(test)]
mod tests_pkg_contract;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_resource_policy;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_self_protect_hardening;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_self_protect_policy;
