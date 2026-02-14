use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub multiplier: u32,
    pub max_attempts: u32,
    /// Symmetric jitter percentage around exponential backoff base delay.
    /// Example: 20 => delay in [0.8x, 1.2x] of base delay.
    pub jitter_percent: u8,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            multiplier: 2,
            max_attempts: 3,
            jitter_percent: 20,
        }
    }
}

impl RetryPolicy {
    pub fn next_delay(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.saturating_pow(attempt);
        let delay = self.min_backoff.saturating_mul(factor);
        delay.min(self.max_backoff)
    }

    pub fn next_delay_with_jitter(&self, attempt: u32) -> Duration {
        self.next_delay_with_jitter_seed(attempt, jitter_entropy(attempt))
    }

    pub fn next_delay_with_jitter_seed(&self, attempt: u32, entropy: u64) -> Duration {
        let base = self.next_delay(attempt);
        let jitter_percent = self.jitter_percent.min(100) as u128;
        if jitter_percent == 0 {
            return base;
        }

        let base_ns = base.as_nanos();
        let max_delta_ns = base_ns.saturating_mul(jitter_percent) / 100;
        if max_delta_ns == 0 {
            return base;
        }

        let modulus = max_delta_ns.saturating_mul(2).saturating_add(1);
        let offset_ns = (entropy as u128 % modulus) as i128 - max_delta_ns as i128;

        let lower_ns = base_ns.saturating_sub(max_delta_ns) as i128;
        let upper_ns = base_ns.saturating_add(max_delta_ns) as i128;
        let candidate_ns = (base_ns as i128 + offset_ns).clamp(lower_ns, upper_ns) as u128;

        duration_from_nanos(candidate_ns)
    }
}

fn duration_from_nanos(nanos: u128) -> Duration {
    let capped = nanos.min(u64::MAX as u128) as u64;
    Duration::from_nanos(capped)
}

fn jitter_entropy(attempt: u32) -> u64 {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default();
    let pid = std::process::id() as u64;

    let mut x = now_nanos ^ (pid.rotate_left(17)) ^ (attempt as u64).rotate_left(9);
    x ^= x << 13;
    x ^= x >> 7;
    x ^ (x << 17)
}

#[cfg(test)]
mod tests;
