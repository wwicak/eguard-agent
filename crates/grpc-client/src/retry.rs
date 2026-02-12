use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub multiplier: u32,
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            multiplier: 2,
            max_attempts: 3,
        }
    }
}

impl RetryPolicy {
    pub fn next_delay(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.saturating_pow(attempt);
        let delay = self.min_backoff.saturating_mul(factor);
        delay.min(self.max_backoff)
    }
}

#[cfg(test)]
mod tests;
