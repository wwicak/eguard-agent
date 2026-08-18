//! Local-only DLP classification primitives.
//!
//! Platform adapters may provide MIP/Office labels only after they verify the
//! platform source. This module deliberately does not read arbitrary sidecar
//! files, filenames, or user-supplied labels.

use std::collections::BTreeSet;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelSource {
    MicrosoftInformationProtection,
    OfficeDocumentProperty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLabel {
    pub source: LabelSource,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredRecord<'a> {
    pub fields: Vec<(&'a str, &'a str)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationPolicy {
    pub accepted_label_ids: BTreeSet<String>,
    pub structured_fingerprints: BTreeSet<String>,
    pub document_fingerprints: Vec<BTreeSet<String>>,
    pub minimum_shared_shingles: usize,
}

impl Default for ClassificationPolicy {
    fn default() -> Self {
        Self {
            accepted_label_ids: BTreeSet::new(),
            structured_fingerprints: BTreeSet::new(),
            document_fingerprints: Vec::new(),
            minimum_shared_shingles: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FingerprintPack {
    pub schema_version: String,
    pub key_id: String,
    #[serde(default)]
    pub trusted_label_ids: BTreeSet<String>,
    #[serde(default)]
    pub structured_fingerprints: BTreeSet<String>,
    #[serde(default)]
    pub document_fingerprints: Vec<BTreeSet<String>>,
    #[serde(default = "default_minimum_shared_shingles")]
    pub minimum_shared_shingles: usize,
}

impl FingerprintPack {
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let pack: Self = serde_json::from_str(raw)
            .map_err(|error| format!("invalid DLP fingerprint pack JSON: {error}"))?;
        if pack.schema_version != "1" || pack.key_id.trim().is_empty() {
            return Err("unsupported DLP fingerprint pack".to_string());
        }
        if pack.minimum_shared_shingles == 0 || pack.minimum_shared_shingles > 128 {
            return Err("DLP fingerprint minimum_shared_shingles must be 1..=128".to_string());
        }
        if pack
            .document_fingerprints
            .iter()
            .any(|set| set.len() > 2_048)
        {
            return Err("DLP document fingerprint set exceeds 2048 shingles".to_string());
        }
        Ok(pack)
    }

    pub fn policy(&self) -> ClassificationPolicy {
        ClassificationPolicy {
            accepted_label_ids: self.trusted_label_ids.clone(),
            structured_fingerprints: self.structured_fingerprints.clone(),
            document_fingerprints: self.document_fingerprints.clone(),
            minimum_shared_shingles: self.minimum_shared_shingles,
        }
    }
}

fn default_minimum_shared_shingles() -> usize {
    3
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationMatch {
    TrustedLabel {
        id: String,
        source: LabelSource,
    },
    StructuredFingerprint,
    UnstructuredFingerprint {
        reference_index: usize,
        shared_shingles: usize,
    },
}

/// Produces a deterministic local identifier for a canonical structured record.
///
/// This is a lookup fingerprint, not a signature. The tenant key must stay
/// local and be rotated with the corresponding fingerprint pack.
pub fn structured_fingerprint(key: &[u8], record: &StructuredRecord<'_>) -> String {
    let mut fields: Vec<(String, String)> = record
        .fields
        .iter()
        .map(|(name, value)| (normalize(name), normalize(value)))
        .collect();
    fields.sort();
    let canonical = fields
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    keyed_digest(key, canonical.as_bytes())
}

/// Produces bounded, keyed word-shingle fingerprints for a reference document.
pub fn document_fingerprints(key: &[u8], text: &str) -> BTreeSet<String> {
    const SHINGLE_WORDS: usize = 5;
    const MAX_WORDS: usize = 4_096;
    const MAX_SHINGLES: usize = 2_048;

    let words: Vec<String> = text
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .take(MAX_WORDS)
        .map(normalize)
        .collect();
    if words.len() < SHINGLE_WORDS {
        return BTreeSet::new();
    }

    words
        .windows(SHINGLE_WORDS)
        .take(MAX_SHINGLES)
        .map(|window| keyed_digest(key, window.join(" ").as_bytes()))
        .collect()
}

pub fn classify(
    policy: &ClassificationPolicy,
    label: Option<&TrustedLabel>,
    structured: Option<(&[u8], &StructuredRecord<'_>)>,
    document: Option<(&[u8], &str)>,
) -> Vec<ClassificationMatch> {
    let mut matches = Vec::new();

    if let Some(label) = label.filter(|label| policy.accepted_label_ids.contains(&label.id)) {
        matches.push(ClassificationMatch::TrustedLabel {
            id: label.id.clone(),
            source: label.source,
        });
    }

    if let Some((key, record)) = structured {
        let fingerprint = structured_fingerprint(key, record);
        if policy.structured_fingerprints.contains(&fingerprint) {
            matches.push(ClassificationMatch::StructuredFingerprint);
        }
    }

    if let Some((key, text)) = document {
        let observed = document_fingerprints(key, text);
        if !observed.is_empty() {
            for (reference_index, reference) in policy.document_fingerprints.iter().enumerate() {
                let shared_shingles = observed.intersection(reference).count();
                if shared_shingles >= policy.minimum_shared_shingles {
                    matches.push(ClassificationMatch::UnstructuredFingerprint {
                        reference_index,
                        shared_shingles,
                    });
                }
            }
        }
    }

    matches
}

fn keyed_digest(key: &[u8], value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"eguard-dlp-classification-v1\0");
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key);
    hasher.update(value);
    hasher.update(key);
    format!("{:x}", hasher.finalize())
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_pack_rejects_invalid_limits_and_preserves_opaque_values() {
        let raw = r#"{
            "schema_version":"1",
            "key_id":"tenant-key-id",
            "trusted_label_ids":["mip-confidential"],
            "structured_fingerprints":["abc"],
            "document_fingerprints":[["one","two","three"]]
        }"#;
        let pack = FingerprintPack::from_json(raw).expect("valid pack");
        assert_eq!(pack.key_id, "tenant-key-id");
        assert!(pack
            .policy()
            .accepted_label_ids
            .contains("mip-confidential"));
        assert!(FingerprintPack::from_json(
            r#"{"schema_version":"1","key_id":"x","minimum_shared_shingles":0}"#
        )
        .is_err());
    }

    #[test]
    fn accepts_only_configured_trusted_label() {
        let policy = ClassificationPolicy {
            accepted_label_ids: ["mip-confidential".to_string()].into_iter().collect(),
            ..ClassificationPolicy::default()
        };
        let trusted = TrustedLabel {
            source: LabelSource::MicrosoftInformationProtection,
            id: "mip-confidential".to_string(),
        };
        let untrusted = TrustedLabel {
            source: LabelSource::OfficeDocumentProperty,
            id: "public".to_string(),
        };
        assert!(matches!(
            classify(&policy, Some(&trusted), None, None).as_slice(),
            [ClassificationMatch::TrustedLabel { .. }]
        ));
        assert!(classify(&policy, Some(&untrusted), None, None).is_empty());
    }

    #[test]
    fn structured_fingerprint_is_order_and_whitespace_stable_but_keyed() {
        let left = StructuredRecord {
            fields: vec![("Customer ID", "  ACME-001 "), ("Region", "Jakarta")],
        };
        let right = StructuredRecord {
            fields: vec![("region", "jakarta"), ("customer id", "ACME-001")],
        };
        assert_eq!(
            structured_fingerprint(b"tenant-a", &left),
            structured_fingerprint(b"tenant-a", &right)
        );
        assert_ne!(
            structured_fingerprint(b"tenant-a", &left),
            structured_fingerprint(b"tenant-b", &left)
        );
    }

    #[test]
    fn finds_structured_and_unstructured_fingerprints_without_raw_output() {
        let record = StructuredRecord {
            fields: vec![("account", "ACME-001"), ("country", "ID")],
        };
        let reference =
            "confidential merger plan covers acme revenue projection and customer pricing";
        let policy = ClassificationPolicy {
            structured_fingerprints: [structured_fingerprint(b"tenant-key", &record)]
                .into_iter()
                .collect(),
            document_fingerprints: vec![document_fingerprints(b"tenant-key", reference)],
            minimum_shared_shingles: 3,
            ..ClassificationPolicy::default()
        };
        let text = "The confidential merger plan covers ACME revenue projection and customer pricing for 2027.";
        let matches = classify(
            &policy,
            None,
            Some((b"tenant-key", &record)),
            Some((b"tenant-key", text)),
        );
        assert!(matches.contains(&ClassificationMatch::StructuredFingerprint));
        assert!(matches.iter().any(|item| matches!(
            item,
            ClassificationMatch::UnstructuredFingerprint { shared_shingles, .. } if *shared_shingles >= 3
        )));
        assert!(!format!("{matches:?}").contains("ACME-001"));
        assert!(!format!("{matches:?}").contains("confidential merger"));
    }

    #[test]
    fn canonical_classification_fixture_exercises_all_three_methods() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../dlp/fixtures/classification.json"))
                .expect("classification fixture");
        let fields = fixture["structured_record"]["fields"]
            .as_object()
            .expect("structured fields");
        let record = StructuredRecord {
            fields: fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str().expect("field value")))
                .collect(),
        };
        let key_id = fixture["structured_record"]["key_id"]
            .as_str()
            .expect("key id");
        let key = format!("fixture:{key_id}");
        let reference = fixture["unstructured"]["reference"]
            .as_str()
            .expect("reference");
        let policy = ClassificationPolicy {
            accepted_label_ids: fixture["trusted_labels"]["accepted"]
                .as_array()
                .expect("accepted labels")
                .iter()
                .map(|item| item.as_str().expect("label").to_string())
                .collect(),
            structured_fingerprints: [structured_fingerprint(key.as_bytes(), &record)]
                .into_iter()
                .collect(),
            document_fingerprints: vec![document_fingerprints(key.as_bytes(), reference)],
            minimum_shared_shingles: 3,
        };
        let accepted = TrustedLabel {
            source: LabelSource::MicrosoftInformationProtection,
            id: fixture["trusted_labels"]["accepted"][0]
                .as_str()
                .expect("accepted label")
                .to_string(),
        };
        let positive = fixture["unstructured"]["positive"]
            .as_str()
            .expect("positive text");
        let matched = classify(
            &policy,
            Some(&accepted),
            Some((key.as_bytes(), &record)),
            Some((key.as_bytes(), positive)),
        );
        assert!(matched
            .iter()
            .any(|item| matches!(item, ClassificationMatch::TrustedLabel { .. })));
        assert!(matched.contains(&ClassificationMatch::StructuredFingerprint));
        assert!(matched
            .iter()
            .any(|item| matches!(item, ClassificationMatch::UnstructuredFingerprint { .. })));

        let rejected = TrustedLabel {
            source: LabelSource::OfficeDocumentProperty,
            id: fixture["trusted_labels"]["rejected"][0]
                .as_str()
                .expect("rejected label")
                .to_string(),
        };
        let negative = fixture["unstructured"]["negative"]
            .as_str()
            .expect("negative text");
        assert!(classify(
            &policy,
            Some(&rejected),
            None,
            Some((key.as_bytes(), negative)),
        )
        .is_empty());
    }

    #[test]
    fn unrelated_document_does_not_match() {
        let policy = ClassificationPolicy {
            document_fingerprints: vec![document_fingerprints(
                b"tenant-key",
                "confidential merger plan covers acme revenue projection and customer pricing",
            )],
            minimum_shared_shingles: 3,
            ..ClassificationPolicy::default()
        };
        assert!(classify(
            &policy,
            None,
            None,
            Some((
                b"tenant-key",
                "cafeteria menu changes for the quarterly town hall"
            )),
        )
        .is_empty());
    }
}
