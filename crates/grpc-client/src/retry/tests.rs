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
    };

    assert_eq!(policy.next_delay(1), Duration::from_millis(200));
    assert_eq!(policy.next_delay(2), Duration::from_millis(350));
    assert_eq!(policy.next_delay(10), Duration::from_millis(350));
}
