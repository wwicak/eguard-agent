use std::cmp::Ordering;

use anyhow::{anyhow, Result};

pub(super) fn ensure_version_monotonicity(
    current_version: Option<&str>,
    incoming_version: &str,
) -> Result<()> {
    let incoming_version = incoming_version.trim();
    let Some(current_version) = current_version else {
        return Ok(());
    };
    let current_version = current_version.trim();

    if current_version.is_empty() || incoming_version.is_empty() || current_version == incoming_version {
        return Ok(());
    }

    let current_family = version_family_prefix(current_version);
    let incoming_family = version_family_prefix(incoming_version);
    if !current_family.is_empty() && !incoming_family.is_empty() && current_family != incoming_family {
        return Ok(());
    }

    if compare_version_natural(incoming_version, current_version) != Ordering::Greater {
        return Err(anyhow!(
            "threat-intel version replay detected: incoming '{}' is not newer than current '{}'",
            incoming_version,
            current_version
        ));
    }

    Ok(())
}

pub(super) fn ensure_publish_timestamp_floor(
    publish_floor_unix: Option<i64>,
    incoming_published_at_unix: i64,
) -> Result<()> {
    if incoming_published_at_unix <= 0 {
        return Ok(());
    }

    let Some(floor_unix) = publish_floor_unix else {
        return Ok(());
    };
    if floor_unix <= 0 {
        return Ok(());
    }

    if incoming_published_at_unix < floor_unix {
        return Err(anyhow!(
            "threat-intel publish timestamp replay detected: incoming {} is below floor {}",
            incoming_published_at_unix,
            floor_unix
        ));
    }

    Ok(())
}

fn version_family_prefix(raw: &str) -> String {
    raw.chars()
        .take_while(|ch| !ch.is_ascii_digit())
        .filter(|ch| ch.is_ascii_alphabetic())
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>()
}

pub(super) fn compare_version_natural(lhs: &str, rhs: &str) -> Ordering {
    let lhs = lhs.as_bytes();
    let rhs = rhs.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;

    while i < lhs.len() && j < rhs.len() {
        let l = lhs[i];
        let r = rhs[j];

        if l.is_ascii_digit() && r.is_ascii_digit() {
            let lhs_start = i;
            while i < lhs.len() && lhs[i].is_ascii_digit() {
                i += 1;
            }
            let rhs_start = j;
            while j < rhs.len() && rhs[j].is_ascii_digit() {
                j += 1;
            }

            let lhs_digits = &lhs[lhs_start..i];
            let rhs_digits = &rhs[rhs_start..j];
            let lhs_trimmed = trim_leading_zeroes(lhs_digits);
            let rhs_trimmed = trim_leading_zeroes(rhs_digits);

            match lhs_trimmed.len().cmp(&rhs_trimmed.len()) {
                Ordering::Equal => match lhs_trimmed.cmp(rhs_trimmed) {
                    Ordering::Equal => continue,
                    non_eq => return non_eq,
                },
                non_eq => return non_eq,
            }
        }

        match normalize_version_byte(l).cmp(&normalize_version_byte(r)) {
            Ordering::Equal => {
                i += 1;
                j += 1;
            }
            non_eq => return non_eq,
        }
    }

    match (i == lhs.len(), j == rhs.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => Ordering::Equal,
    }
}

fn trim_leading_zeroes(raw: &[u8]) -> &[u8] {
    let mut idx = 0usize;
    while idx + 1 < raw.len() && raw[idx] == b'0' {
        idx += 1;
    }
    &raw[idx..]
}

fn normalize_version_byte(raw: u8) -> u8 {
    raw.to_ascii_lowercase()
}
