use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Posture {
    Compliant,
    NonCompliant,
    Unknown,
}

pub fn posture_from_compliance(status: &str) -> Posture {
    match status {
        "pass" | "compliant" => Posture::Compliant,
        "fail" | "non_compliant" => Posture::NonCompliant,
        _ => Posture::Unknown,
    }
}

#[cfg(test)]
mod tests;
