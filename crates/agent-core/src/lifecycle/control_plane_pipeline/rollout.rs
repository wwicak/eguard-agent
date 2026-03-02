use super::super::BASELINE_UPLOAD_MAX_BYTES;

pub(super) fn baseline_upload_max_bytes() -> usize {
    std::env::var("EGUARD_BASELINE_UPLOAD_MAX_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(BASELINE_UPLOAD_MAX_BYTES)
}

fn rollout_bucket(agent_id: &str) -> u8 {
    let mut hash = 0xcbf29ce484222325u64;
    for b in agent_id.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash % 100) as u8
}

pub(super) fn rollout_allows(agent_id: &str, canary_percent: u8) -> bool {
    if canary_percent >= 100 {
        return true;
    }
    if canary_percent == 0 {
        return false;
    }
    rollout_bucket(agent_id) < canary_percent
}
