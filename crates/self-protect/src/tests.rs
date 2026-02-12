
use super::*;

#[test]
// AC-ATP-001
fn integrity_probe_returns_true() {
    assert!(integrity_ok());
}
