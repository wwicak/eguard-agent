use std::collections::HashSet;

pub(crate) fn set_of<const N: usize>(values: [&str; N]) -> HashSet<String> {
    let mut out = HashSet::new();
    for v in values {
        out.insert(v.to_string());
    }
    out
}

pub(crate) fn set_u16<const N: usize>(values: [u16; N]) -> HashSet<u16> {
    let mut out = HashSet::new();
    for v in values {
        out.insert(v);
    }
    out
}
