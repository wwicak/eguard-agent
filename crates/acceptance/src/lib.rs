//! Acceptance criteria test harness crate.
//!
//! This crate intentionally keeps runtime code minimal and hosts generated
//! criterion-level tests in `tests/`.

pub fn criteria_harness_ready() -> bool {
    true
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_atp_contract;
#[cfg(test)]
mod tests_bsl_contract;
#[cfg(test)]
mod tests_rsp_contract;
#[cfg(test)]
mod tests_tst_ver_contract;
