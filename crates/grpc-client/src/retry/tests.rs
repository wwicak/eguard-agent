use super::*;

#[test]
// AC-GRP-080
fn next_delay_starts_from_min_backoff() {
    let policy = RetryPolicy::default();
    assert_eq!(policy.next_delay(0), policy.min_backoff);
}

#[test]
// AC-GRP-080
fn next_delay_grows_and_caps_at_max_backoff() {
    let policy = RetryPolicy {
        min_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(350),
        multiplier: 2,
        max_attempts: 5,
        jitter_percent: 20,
    };

    assert_eq!(policy.next_delay(1), Duration::from_millis(200));
    assert_eq!(policy.next_delay(2), Duration::from_millis(350));
    assert_eq!(policy.next_delay(10), Duration::from_millis(350));
}

#[test]
// AC-OPT-001 AC-OPT-002
fn next_delay_with_jitter_seed_stays_within_configured_bounds() {
    let policy = RetryPolicy {
        min_backoff: Duration::from_secs(2),
        max_backoff: Duration::from_secs(30),
        multiplier: 2,
        max_attempts: 5,
        jitter_percent: 20,
    };

    let base = policy.next_delay(2); // 8s
    let jittered_low = policy.next_delay_with_jitter_seed(2, 0);
    let jittered_high = policy.next_delay_with_jitter_seed(2, u64::MAX);

    let lower = base.as_nanos() * 80 / 100;
    let upper = base.as_nanos() * 120 / 100;

    assert!(jittered_low.as_nanos() >= lower);
    assert!(jittered_low.as_nanos() <= upper);
    assert!(jittered_high.as_nanos() >= lower);
    assert!(jittered_high.as_nanos() <= upper);
}

#[test]
// AC-OPT-001
fn next_delay_with_jitter_seed_varies_for_distinct_entropy() {
    let policy = RetryPolicy {
        min_backoff: Duration::from_millis(500),
        max_backoff: Duration::from_secs(5),
        multiplier: 2,
        max_attempts: 5,
        jitter_percent: 20,
    };

    let a = policy.next_delay_with_jitter_seed(1, 11);
    let b = policy.next_delay_with_jitter_seed(1, 22);
    assert_ne!(a, b);
}

#[test]
// AC-OPT-002
fn zero_jitter_percent_preserves_base_backoff_delay() {
    let policy = RetryPolicy {
        min_backoff: Duration::from_millis(250),
        max_backoff: Duration::from_secs(2),
        multiplier: 2,
        max_attempts: 4,
        jitter_percent: 0,
    };

    assert_eq!(
        policy.next_delay_with_jitter_seed(2, 12345),
        policy.next_delay(2)
    );
}
