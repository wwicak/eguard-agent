//! Internal sensor k=v transport. Decode only after splitting fields.
//! Shared as source by platform crates to avoid adding a dependency.
pub fn escape_payload_value(raw: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, '%' | ';' | ',' | '=') || ch.is_control() {
            write!(&mut out, "%{:02X}", ch as u32).expect("writing to String");
        } else {
            out.push(ch);
        }
    }
    out
}
