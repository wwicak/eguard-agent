mod bootstrap;
mod bundle_guard;
mod download;
mod refresh;
mod reload;
mod state;
mod version;

#[cfg(test)]
mod tests;

const THREAT_INTEL_REPLAY_FLOOR_FILENAME: &str = "threat-intel-replay-floor.v1.json";
const THREAT_INTEL_REPLAY_FLOOR_PATH_ENV: &str = "EGUARD_THREAT_INTEL_REPLAY_FLOOR_PATH";
const THREAT_INTEL_REPLAY_FLOOR_SIG_CONTEXT: &str = "eguard-threat-intel-replay-floor-v1";
const THREAT_INTEL_LAST_KNOWN_GOOD_FILENAME: &str = "threat-intel-last-known-good.v1.json";
const THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV: &str = "EGUARD_THREAT_INTEL_LAST_KNOWN_GOOD_PATH";
const THREAT_INTEL_LAST_KNOWN_GOOD_SIG_CONTEXT: &str = "eguard-threat-intel-last-known-good-v1";
const MACHINE_ID_PATH_ENV: &str = "EGUARD_MACHINE_ID_PATH";
const DEFAULT_MACHINE_ID_PATH: &str = "/etc/machine-id";
const RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV: &str = "EGUARD_RULE_BUNDLE_MIN_SIGNATURE_TOTAL";
const DEFAULT_RULE_BUNDLE_MIN_SIGNATURE_TOTAL: usize = 1;
const RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV: &str = "EGUARD_RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT";
