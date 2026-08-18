use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DlpRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub validator: String,
    pub context: Vec<String>,
    pub severity: String,
    pub default_action: String,
    pub regulations: Vec<String>,
    pub redaction: String,
    pub max_matches: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DlpRulePack {
    pub schema_version: String,
    pub pack_id: String,
    pub version: String,
    pub rules: Vec<DlpRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpMatch {
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub start: usize,
    pub end: usize,
    pub redacted_evidence: String,
}

#[derive(Clone)]
struct CompiledRule {
    rule: DlpRule,
    regex: Regex,
}

#[derive(Clone)]
pub struct DlpScanner {
    rules: Vec<CompiledRule>,
}

impl DlpScanner {
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let pack: DlpRulePack = serde_json::from_str(raw)
            .map_err(|err| format!("invalid DLP rule pack JSON: {err}"))?;
        Self::from_pack(pack)
    }

    pub fn from_pack(pack: DlpRulePack) -> Result<Self, String> {
        if pack.schema_version != "1" || pack.rules.is_empty() {
            return Err("unsupported or empty DLP rule pack".to_string());
        }
        let mut rules = Vec::with_capacity(pack.rules.len());
        for rule in pack.rules {
            let regex = Regex::new(&rule.pattern)
                .map_err(|err| format!("{}: invalid regex: {err}", rule.id))?;
            rules.push(CompiledRule { rule, regex });
        }
        Ok(Self { rules })
    }

    pub fn scan(&self, text: &str) -> Vec<DlpMatch> {
        let mut matches = Vec::new();
        for compiled in &self.rules {
            let rule = &compiled.rule;
            let context = text.to_lowercase();
            let has_context = rule
                .context
                .iter()
                .any(|term| context.contains(&term.to_lowercase()));
            for found in compiled.regex.find_iter(text).take(rule.max_matches) {
                let value = found.as_str();
                if !validator_accepts(&rule.validator, value, has_context) {
                    continue;
                }
                matches.push(DlpMatch {
                    rule_id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    action: rule.default_action.clone(),
                    start: found.start(),
                    end: found.end(),
                    redacted_evidence: redact(value, &rule.redaction),
                });
            }
        }
        matches
    }

    pub fn scan_file(&self, path: &std::path::Path, max_bytes: u64) -> Result<Vec<DlpMatch>, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|err| format!("stat {}: {err}", path.display()))?;
        if metadata.len() > max_bytes {
            return Err(format!("file exceeds DLP scan limit: {} > {max_bytes}", metadata.len()));
        }
        let bytes = std::fs::read(path)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| format!("file is not UTF-8 text: {}", path.display()))?;
        Ok(self.scan(text))
    }
}

fn validator_accepts(validator: &str, value: &str, has_context: bool) -> bool {
    match validator {
        "context_only" | "context_cluster" | "nik_indonesia" | "npwp_indonesia"
        | "phone_indonesia" => has_context,
        "luhn" => has_context && luhn(value),
        _ => false,
    }
}

fn luhn(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|ch| ch.to_digit(10)).collect();
    if digits.len() < 12 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                *digit
            }
        })
        .sum();
    sum % 10 == 0
}

fn redact(value: &str, mode: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    match mode {
        "last4" if chars.len() > 4 => format!("{}{}", "*".repeat(chars.len() - 4), chars[chars.len() - 4..].iter().collect::<String>()),
        "mask_middle" if chars.len() > 4 => {
            let visible = (chars.len() / 4).max(1);
            format!("{}{}{}", chars[..visible].iter().collect::<String>(), "*".repeat(chars.len() - (visible * 2)), chars[chars.len() - visible..].iter().collect::<String>())
        }
        _ => "[REDACTED]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> DlpScanner {
        DlpScanner::from_pack(DlpRulePack {
            schema_version: "1".to_string(),
            pack_id: "indonesia".to_string(),
            version: "1.0.0".to_string(),
            rules: vec![DlpRule {
                id: "id.nik".to_string(),
                name: "NIK".to_string(),
                pattern: r"\b\d{16}\b".to_string(),
                validator: "context_only".to_string(),
                context: vec!["nik".to_string()],
                severity: "high".to_string(),
                default_action: "alert".to_string(),
                regulations: vec!["UU PDP".to_string()],
                redaction: "mask_middle".to_string(),
                max_matches: 2,
            }],
        })
        .expect("valid pack")
    }

    #[test]
    fn context_match_is_redacted() {
        let found = scanner().scan("NIK: 3174012301900001");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "id.nik");
        assert_eq!(found[0].redacted_evidence, "3174********0001");
    }

    #[test]
    fn same_shape_without_context_is_ignored() {
        assert!(scanner().scan("invoice: 3174012301900001").is_empty());
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let mut pack = scanner();
        pack.rules.clear();
        assert!(DlpScanner::from_pack(DlpRulePack {
            schema_version: "1".to_string(),
            pack_id: "indonesia".to_string(),
            version: "1.0.0".to_string(),
            rules: vec![DlpRule {
                id: "id.bad".to_string(), name: "bad".to_string(), pattern: "(".to_string(),
                validator: "context_only".to_string(), context: vec!["x".to_string()],
                severity: "low".to_string(), default_action: "audit".to_string(),
                regulations: vec!["test".to_string()], redaction: "last4".to_string(), max_matches: 1,
            }],
        }).is_err());
    }

    #[test]
    fn json_pack_and_scan_file_respect_size_and_utf8_limits() {
        let raw = r#"{"schema_version":"1","pack_id":"indonesia","version":"1.0.0","rules":[{"id":"id.nik","name":"NIK","pattern":"\\b\\d{16}\\b","validator":"context_only","context":["nik"],"severity":"high","default_action":"alert","regulations":["UU PDP"],"redaction":"mask_middle","max_matches":1}]}"#;
        let scanner = DlpScanner::from_json(raw).expect("JSON pack");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.txt");
        std::fs::write(&path, "NIK: 3174012301900001").expect("write sample");
        assert_eq!(scanner.scan_file(&path, 1024).expect("scan").len(), 1);
        assert!(scanner.scan_file(&path, 4).is_err());
        std::fs::write(&path, [0xff, 0xfe]).expect("write binary");
        assert!(scanner.scan_file(&path, 1024).is_err());
    }

    #[test]
    fn scenario04_05_fixtures_detect_nik() {
        // Scenario 04 (removable media) and 05 (file share) fixtures must be
        // detected by the NIK regex classifier (16-digit + context term).
        let scanner = scanner();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap(); // workspace root (repo top-level)
        for fixture in [
            "fixtures/dlp-scenario04-nik-on-usb.txt",
            "fixtures/dlp-scenario05-nik-on-share.txt",
        ] {
            let path = root.join(fixture);
            let found = scanner
                .scan_file(&path, 1024 * 1024)
                .expect("scan fixture");
            assert!(
                !found.is_empty(),
                "fixture {fixture} should trigger the NIK classifier"
            );
            assert!(found.iter().all(|m| m.redacted_evidence.contains('*')));
        }
    }

    #[test]
    fn scenario04_negative_control_ignored() {
        // A file with the same numeric shape but no NIK context must NOT match.
        assert!(scanner().scan("invoice no: 3174012301900001").is_empty());
    }
}
