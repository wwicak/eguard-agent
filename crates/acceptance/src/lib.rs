//! Acceptance criteria test harness crate.
//!
//! This crate intentionally keeps runtime code minimal and hosts generated
//! criterion-level tests in `tests/`.

pub fn criteria_harness_ready() -> bool {
    true
}

#[cfg(test)]
mod tests;
