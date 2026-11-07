use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::sigma_expr::{SigmaExpr, SigmaField};
use regex::RegexBuilder;

use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};

use crate::layer2::{RuleLevel, TemporalPredicate, TemporalRule, TemporalStage};
use crate::types::EventClass;

#[derive(Debug, Clone)]
pub struct BoundedTemporalAst {
    pub level: RuleLevel,
    pub any_order: bool,
    pub name: String,
    pub stages: Vec<AstStage>,
    pub root: TemporalExpr,
}

#[derive(Debug, Clone)]
pub struct AstStage {
    pub predicate: TemporalPredicate,
    pub within_secs: u64,
}

#[derive(Debug, Clone)]
pub enum TemporalExpr {
    Stage(usize),
    And(Box<TemporalExpr>, Box<TemporalExpr>),
    EventuallyWithin {
        within_secs: u64,
        expr: Box<TemporalExpr>,
    },
}

#[derive(Debug)]
pub enum SigmaCompileError {
    ParseYaml(String),
    MissingDetectionSequence,
    MissingStageWindow {
        stage_index: usize,
    },
    UnsupportedEventClass(String),
    Unsupported {
        reason: &'static str,
        detail: String,
    },
}

impl fmt::Display for SigmaCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseYaml(msg) => write!(f, "invalid sigma yaml: {}", msg),
            Self::MissingDetectionSequence => {
                write!(
                    f,
                    "sigma rule must define detection.sequence with at least one stage"
                )
            }
            Self::MissingStageWindow { stage_index } => {
                write!(f, "sigma stage {} must define within_secs", stage_index)
            }
            Self::Unsupported { reason, detail } => write!(f, "{}: {}", reason, detail),
            Self::UnsupportedEventClass(value) => {
                write!(f, "unsupported sigma event_class: {}", value)
            }
        }
    }
}

impl std::error::Error for SigmaCompileError {}

pub type Result<T> = std::result::Result<T, SigmaCompileError>;

#[derive(Debug, Deserialize)]
struct SigmaRuleDoc {
    #[serde(default)]
    level: RuleLevel,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    logsource: SigmaLogSource,
    detection: SigmaDetection,
}

#[derive(Debug, Default, Deserialize)]
struct SigmaLogSource {
    #[serde(default)]
    category: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    service: String,
}

#[derive(Debug, Deserialize)]
struct SigmaDetection {
    #[serde(default)]
    sequence: Vec<SigmaStage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigmaStage {
    event_class: String,
    #[serde(default, deserialize_with = "deserialize_string_vec_lenient")]
    process_any_of: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec_lenient")]
    parent_any_of: Vec<String>,
    #[serde(default)]
    uid_eq: Option<u32>,
    #[serde(default)]
    uid_ne: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_u16_vec_lenient")]
    dst_port_not_in: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_u16_vec_lenient")]
    dst_port_any_of: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_string_vec_lenient")]
    file_path_any_of: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec_lenient")]
    file_path_contains: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec_lenient")]
    command_line_contains: Vec<String>,
    #[serde(default)]
    require_file_write: bool,
    #[serde(default)]
    command_line_all_groups: Vec<Vec<String>>,
    #[serde(default)]
    command_line_not_contains: Vec<String>,
    #[serde(default)]
    process_not_any_of: Vec<String>,
    #[serde(default)]
    parent_not_any_of: Vec<String>,
    #[serde(default)]
    file_path_not_contains: Vec<String>,
    #[serde(default)]
    process_starts_with: Vec<String>,
    #[serde(default)]
    within_secs: Option<u64>,
}

pub fn compile_sigma_rule(yaml: &str) -> Result<TemporalRule> {
    let ast = compile_sigma_ast(yaml)?;
    Ok(temporal_rule_from_ast(&ast))
}

pub fn compile_sigma_ast(yaml: &str) -> Result<BoundedTemporalAst> {
    if yaml.len() > 256 * 1024 {
        return Err(unsupported("resource_limit", "rule exceeds 256 KiB"));
    }
    let raw: Value =
        serde_yaml::from_str(yaml).map_err(|err| SigmaCompileError::ParseYaml(err.to_string()))?;
    let root = raw
        .as_mapping()
        .ok_or_else(|| unsupported("unsupported_document", "mapping required"))?;
    for key in root.keys() {
        if !key.as_str().is_some_and(|k| {
            matches!(
                k,
                "title"
                    | "id"
                    | "status"
                    | "description"
                    | "references"
                    | "author"
                    | "date"
                    | "modified"
                    | "tags"
                    | "logsource"
                    | "detection"
                    | "falsepositives"
                    | "level"
                    | "license"
                    | "related"
                    | "fields"
                    | "scope"
                    | "mitre_techniques"
                    | "simulation"
            )
        }) {
            return Err(unsupported("unsupported_document", "unknown root key"));
        }
    }
    if let Some(detection) = mapping_get(root, "detection").and_then(Value::as_mapping) {
        if mapping_get(detection, "sequence").is_some() && detection.len() != 1 {
            return Err(unsupported(
                "unsupported_condition",
                "mixed sequence and selectors",
            ));
        }
    }
    let doc: SigmaRuleDoc =
        serde_yaml::from_value(raw).map_err(|err| SigmaCompileError::ParseYaml(err.to_string()))?;

    validate_platform(&doc.logsource)?;
    if !doc.detection.sequence.is_empty() {
        return compile_sequence_sigma_ast(doc);
    }

    compile_legacy_sigma_ast(yaml, &doc)
}

fn compile_sequence_sigma_ast(doc: SigmaRuleDoc) -> Result<BoundedTemporalAst> {
    let mut stages = Vec::with_capacity(doc.detection.sequence.len());
    for (idx, stage) in doc.detection.sequence.into_iter().enumerate() {
        let event_class = parse_event_class(&stage.event_class)?;
        let within_secs = stage
            .within_secs
            .ok_or(SigmaCompileError::MissingStageWindow { stage_index: idx })?;

        stages.push(AstStage {
            predicate: TemporalPredicate {
                // RAFIX shared: retain pack semantics alongside core grading and schema.
                sigma: Some(Arc::new(sequence_expr(&stage)?)),
                event_class,
                process_any_of: into_set(stage.process_any_of),
                process_starts_with: if stage.process_starts_with.is_empty() {
                    None
                } else {
                    Some(stage.process_starts_with)
                },
                parent_any_of: into_set(stage.parent_any_of),
                uid_eq: stage.uid_eq,
                uid_ne: stage.uid_ne,
                dst_port_not_in: into_u16_set(stage.dst_port_not_in),
                dst_port_any_of: into_u16_set(stage.dst_port_any_of),
                file_path_any_of: into_set(stage.file_path_any_of),
                file_path_contains: into_set(stage.file_path_contains),
                command_line_contains: into_set(stage.command_line_contains),
                require_file_write: stage.require_file_write,
                require_credential_source: false,
                ..Default::default()
            },
            within_secs,
        });
    }

    let name = doc
        .title
        .and_then(non_empty)
        .or_else(|| doc.id.and_then(non_empty))
        .unwrap_or_else(|| "sigma_unnamed_rule".to_string());

    let root = build_bounded_expr(&stages);
    Ok(BoundedTemporalAst {
        level: doc.level,
        any_order: false,
        name,
        stages,
        root,
    })
}

fn unsupported(reason: &'static str, detail: impl Into<String>) -> SigmaCompileError {
    SigmaCompileError::Unsupported {
        reason,
        detail: detail.into(),
    }
}

fn validate_platform(ls: &SigmaLogSource) -> Result<()> {
    if !ls.service.is_empty()
        || (!ls.category.is_empty()
            && !matches!(
                ls.category.as_str(),
                "process_creation" | "file_event" | "network_connection" | "dns"
            ))
    {
        return Err(unsupported(
            "unsupported_logsource",
            format!("{}/{}", ls.category, ls.service),
        ));
    }
    let product = ls.product.to_ascii_lowercase();
    if !product.is_empty() && product != std::env::consts::OS {
        return Err(unsupported("unsupported_platform", product));
    }
    Ok(())
}

// RAFIX shared: retain pack semantics alongside core grading and schema.
fn compile_legacy_sigma_ast(yaml: &str, doc: &SigmaRuleDoc) -> Result<BoundedTemporalAst> {
    let event_class = match (
        doc.logsource.category.as_str(),
        doc.logsource.service.as_str(),
    ) {
        ("process_creation", "") => EventClass::ProcessExec,
        ("file_event", "") => EventClass::FileOpen,
        ("network_connection", "") => EventClass::NetworkConnect,
        ("dns", "") => EventClass::DnsQuery,
        _ => {
            return Err(unsupported(
                "unsupported_logsource",
                format!("{}/{}", doc.logsource.category, doc.logsource.service),
            ))
        }
    };
    let root: Value =
        serde_yaml::from_str(yaml).map_err(|err| SigmaCompileError::ParseYaml(err.to_string()))?;
    let detection = root
        .as_mapping()
        .and_then(|r| mapping_get(r, "detection"))
        .and_then(Value::as_mapping)
        .ok_or(SigmaCompileError::MissingDetectionSequence)?;
    if mapping_get(detection, "timeframe").is_some() {
        return Err(unsupported("unsupported_condition", "timeframe"));
    }
    let condition = mapping_get(detection, "condition")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("unsupported_condition", "condition must be a string"))?;
    let mut selections = HashMap::new();
    for (key, value) in detection {
        let name = key
            .as_str()
            .ok_or_else(|| unsupported("unsupported_selection", "non-string selector"))?;
        if name == "condition" {
            continue;
        }
        if selections.len() >= 128 {
            return Err(unsupported("resource_limit", "too many selectors"));
        }
        selections.insert(name.to_string(), compile_selection(value, event_class)?);
    }
    let tokens = tokenize(condition)?;
    let mut parser = ConditionParser {
        tokens: &tokens,
        pos: 0,
        selections: &selections,
        depth: 0,
        nodes: 0,
    };
    let expr = parser.or()?;
    if parser.pos != tokens.len() {
        return Err(unsupported("unsupported_condition", "trailing tokens"));
    }
    let predicate = TemporalPredicate {
        sigma: Some(Arc::new(expr)),
        event_class,
        process_any_of: None,
        process_starts_with: None,
        parent_any_of: None,
        uid_eq: None,
        uid_ne: None,
        dst_port_not_in: None,
        dst_port_any_of: None,
        file_path_any_of: None,
        file_path_contains: None,
        command_line_contains: None,
        require_file_write: false,
        require_credential_source: false,
        ..Default::default()
    };
    Ok(BoundedTemporalAst {
        // RAFIX shared: boolean compilation preserves declared runtime severity.
        level: doc.level,
        any_order: false,
        name: doc
            .title
            .clone()
            .and_then(non_empty)
            .or_else(|| doc.id.clone().and_then(non_empty))
            .unwrap_or_else(|| "sigma_unnamed_rule".into()),
        stages: vec![AstStage {
            predicate,
            within_secs: 30,
        }],
        root: TemporalExpr::Stage(0),
    })
}

fn compile_selection(value: &Value, event_class: EventClass) -> Result<SigmaExpr> {
    if let Value::Sequence(items) = value {
        if items.is_empty() || !items.iter().all(|v| v.is_mapping()) {
            return Err(unsupported(
                "unsupported_selection",
                "keyword or empty selection",
            ));
        }
        return Ok(SigmaExpr::Any(
            items
                .iter()
                .map(|v| compile_selection(v, event_class))
                .collect::<Result<_>>()?,
        ));
    }
    let map = value
        .as_mapping()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| unsupported("unsupported_selection", "selection must contain fields"))?;
    let mut fields = Vec::new();
    for (key, value) in map {
        let key = key
            .as_str()
            .ok_or_else(|| unsupported("unsupported_field", "non-string field"))?;
        fields.push(compile_field(key, value, event_class)?);
    }
    Ok(SigmaExpr::All(fields))
}

fn compile_field(key: &str, value: &Value, event_class: EventClass) -> Result<SigmaExpr> {
    let mut parts = key.split('|');
    let field_name = parts.next().unwrap_or("");
    let modifiers: Vec<_> = parts.collect();
    let mut mode = "exact";
    let mut all = false;
    for m in modifiers {
        match m {
            "all" if !all => all = true,
            "contains" | "startswith" | "endswith" | "re" | "cidr" if mode == "exact" => mode = m,
            _ => return Err(unsupported("unsupported_modifier", key)),
        }
    }
    let values = match value {
        Value::Sequence(items) if !items.is_empty() => items.clone(),
        Value::String(_) | Value::Number(_) => vec![value.clone()],
        _ => return Err(unsupported("unsupported_value", key)),
    };
    let mut exprs = Vec::new();
    for value in values {
        let mut mode = mode;
        let pattern = match value {
            Value::String(s) if !s.is_empty() => s,
            Value::Number(n) => n.to_string(),
            _ => return Err(unsupported("unsupported_value", key)),
        };
        let mut pattern = pattern.as_str();
        let field = match field_name.to_ascii_lowercase().as_str() {
            "commandline" => SigmaField::CommandLine,
            "image" if event_class == EventClass::ProcessExec => SigmaField::ProcessPath,
            "image"
                if mode == "endswith"
                    && (pattern.starts_with('/') || pattern.starts_with('\\'))
                    && !pattern[1..].contains(['/', '\\']) =>
            {
                // On file/network events only the executable basename is available.
                pattern = &pattern[1..];
                mode = "exact";
                SigmaField::Process
            }
            "parentimage" => {
                // Telemetry has a parent basename, not a parent image path.
                if pattern.contains(['/', '\\']) {
                    if mode == "endswith"
                        && (pattern.starts_with('/') || pattern.starts_with('\\'))
                        && !pattern[1..].contains(['/', '\\'])
                    {
                        pattern = &pattern[1..];
                        mode = "exact";
                    } else {
                        return Err(unsupported(
                            "unsupported_field",
                            "ParentImage path unavailable",
                        ));
                    }
                }
                SigmaField::Parent
            }
            "targetfilename" if event_class == EventClass::FileOpen => SigmaField::FilePath,
            "destinationhostname" if event_class == EventClass::NetworkConnect => {
                SigmaField::Domain
            }
            "query" if event_class == EventClass::DnsQuery => SigmaField::Domain,
            "destinationip" if event_class == EventClass::NetworkConnect => SigmaField::Ip,
            "destinationport" if event_class == EventClass::NetworkConnect => SigmaField::Port,
            "uid" | "euid" => SigmaField::Uid,
            _ => return Err(unsupported("unsupported_field", field_name)),
        };
        let expr = if matches!(field, SigmaField::Uid | SigmaField::Port) {
            if mode != "exact" {
                return Err(unsupported("unsupported_modifier", key));
            }
            let number = pattern
                .parse::<u32>()
                .map_err(|_| unsupported("unsupported_value", key))?;
            if matches!(field, SigmaField::Port) && number > u16::MAX as u32 {
                return Err(unsupported("unsupported_value", key));
            }
            SigmaExpr::Number(field, number)
        } else if mode == "cidr" {
            if !matches!(field, SigmaField::Ip) {
                return Err(unsupported("unsupported_modifier", key));
            }
            let (address, prefix) = pattern
                .split_once('/')
                .ok_or_else(|| unsupported("invalid_cidr", pattern))?;
            let ip = address
                .parse::<std::net::IpAddr>()
                .map_err(|_| unsupported("invalid_cidr", pattern))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| unsupported("invalid_cidr", pattern))?;
            if prefix > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(unsupported("invalid_cidr", pattern));
            }
            SigmaExpr::Cidr(ip, prefix)
        } else {
            text_expr(field, pattern, mode)?
        };
        exprs.push(expr);
    }
    Ok(if all {
        SigmaExpr::All(exprs)
    } else {
        SigmaExpr::Any(exprs)
    })
}

fn text_expr(field: SigmaField, pattern: &str, mode: &str) -> Result<SigmaExpr> {
    if pattern.is_empty() {
        return Err(unsupported("unsupported_value", "empty needle"));
    }
    let pattern = if mode == "re" {
        pattern.to_string()
    } else {
        let mut out = String::new();
        if mode != "contains" && mode != "endswith" {
            out.push('^');
        }
        for ch in pattern.chars() {
            match ch {
                '*' => out.push_str(".*"),
                '?' => out.push('.'),
                _ => out.push_str(&regex::escape(&ch.to_string())),
            }
        }
        if mode != "contains" && mode != "startswith" {
            out.push('$');
        }
        out
    };
    let regex = RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .size_limit(1024 * 1024)
        .dfa_size_limit(1024 * 1024)
        .build()
        .map_err(|err| unsupported("invalid_regex", err.to_string()))?;
    Ok(SigmaExpr::Text(field, regex))
}

fn sequence_expr(stage: &SigmaStage) -> Result<SigmaExpr> {
    let mut out = Vec::new();
    for group in &stage.command_line_all_groups {
        if group.is_empty() {
            return Err(unsupported("unsupported_value", "empty all group"));
        }
        out.push(SigmaExpr::Any(
            group
                .iter()
                .map(|s| text_expr(SigmaField::CommandLine, s, "contains"))
                .collect::<Result<_>>()?,
        ));
    }
    for (field, values, mode) in [
        (
            SigmaField::CommandLine,
            &stage.command_line_not_contains,
            "contains",
        ),
        (SigmaField::Process, &stage.process_not_any_of, "exact"),
        (SigmaField::Parent, &stage.parent_not_any_of, "exact"),
        (
            SigmaField::FilePath,
            &stage.file_path_not_contains,
            "contains",
        ),
    ] {
        for value in values {
            out.push(SigmaExpr::Not(Box::new(text_expr(field, value, mode)?)));
        }
    }
    Ok(SigmaExpr::All(out))
}

fn tokenize(condition: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for c in condition.chars() {
        if c.is_whitespace() || c == '(' || c == ')' {
            if !word.is_empty() {
                tokens.push(std::mem::take(&mut word));
            }
            if c == '(' || c == ')' {
                tokens.push(c.to_string());
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        tokens.push(word);
    }
    if tokens.is_empty() || tokens.len() > 256 {
        return Err(unsupported("resource_limit", "condition token count"));
    }
    Ok(tokens)
}

struct ConditionParser<'a> {
    tokens: &'a [String],
    pos: usize,
    selections: &'a HashMap<String, SigmaExpr>,
    depth: usize,
    nodes: usize,
}
impl ConditionParser<'_> {
    fn peek(&self) -> &str {
        self.tokens.get(self.pos).map(String::as_str).unwrap_or("")
    }
    fn or(&mut self) -> Result<SigmaExpr> {
        let mut out = vec![self.and()?];
        while self.peek() == "or" {
            self.pos += 1;
            out.push(self.and()?);
        }
        Ok(SigmaExpr::Any(out))
    }
    fn and(&mut self) -> Result<SigmaExpr> {
        let mut out = vec![self.primary()?];
        while self.peek() == "and" {
            self.pos += 1;
            out.push(self.primary()?);
        }
        Ok(SigmaExpr::All(out))
    }
    fn primary(&mut self) -> Result<SigmaExpr> {
        self.depth += 1;
        self.nodes += 1;
        if self.depth > 32 || self.nodes > 256 {
            return Err(unsupported("resource_limit", "condition complexity"));
        }
        let token = self.peek().to_string();
        self.pos += 1;
        let out = match token.as_str() {
            "not" => SigmaExpr::Not(Box::new(self.primary()?)),
            "(" => {
                let expr = self.or()?;
                if self.peek() != ")" {
                    return Err(unsupported("unsupported_condition", "missing )"));
                }
                self.pos += 1;
                expr
            }
            "1" | "all" => {
                if self.peek() != "of" {
                    return Err(unsupported("unsupported_condition", "missing of"));
                }
                self.pos += 1;
                let pattern = self.peek().to_string();
                self.pos += 1;
                let mut found: Vec<_> = self
                    .selections
                    .iter()
                    .filter(|(name, _)| {
                        pattern == "them"
                            || if let Some(prefix) = pattern.strip_suffix('*') {
                                !prefix.contains('*') && name.starts_with(prefix)
                            } else {
                                name.as_str() == pattern
                            }
                    })
                    .collect();
                found.sort_by_key(|(name, _)| *name);
                if found.is_empty() {
                    return Err(unsupported(
                        "unsupported_condition",
                        "no matching selectors",
                    ));
                }
                let exprs = found.into_iter().map(|(_, expr)| expr.clone()).collect();
                if token == "all" {
                    SigmaExpr::All(exprs)
                } else {
                    SigmaExpr::Any(exprs)
                }
            }
            _ => self
                .selections
                .get(&token)
                .cloned()
                .ok_or_else(|| unsupported("unsupported_condition", token))?,
        };
        self.depth -= 1;
        Ok(out)
    }
}

fn temporal_rule_from_ast(ast: &BoundedTemporalAst) -> TemporalRule {
    let stages = ast
        .stages
        .iter()
        .map(|stage| TemporalStage {
            predicate: stage.predicate.clone(),
            within_secs: stage.within_secs,
        })
        .collect();

    TemporalRule {
        name: ast.name.clone(),
        stages,
        level: ast.level,
        any_order: ast.any_order,
    }
}

fn build_bounded_expr(stages: &[AstStage]) -> TemporalExpr {
    if stages.len() == 1 {
        return TemporalExpr::Stage(0);
    }

    let mut expr = TemporalExpr::Stage(stages.len() - 1);
    for stage_idx in (0..stages.len() - 1).rev() {
        let within_secs = stages[stage_idx + 1].within_secs;
        expr = TemporalExpr::And(
            Box::new(TemporalExpr::Stage(stage_idx)),
            Box::new(TemporalExpr::EventuallyWithin {
                within_secs,
                expr: Box::new(expr),
            }),
        );
    }

    expr
}

fn non_empty(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn into_set(values: Vec<String>) -> Option<HashSet<String>> {
    if values.is_empty() {
        return None;
    }
    Some(values.into_iter().collect())
}

fn into_u16_set(values: Vec<u16>) -> Option<HashSet<u16>> {
    if values.is_empty() {
        return None;
    }
    Some(values.into_iter().collect())
}

fn mapping_get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn deserialize_string_vec_lenient<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    string_vec_from_value(&value).map_err(serde::de::Error::custom)
}

fn deserialize_u16_vec_lenient<'de, D>(deserializer: D) -> std::result::Result<Vec<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let mut out = Vec::new();
    for token in string_vec_from_value(&value).map_err(serde::de::Error::custom)? {
        out.push(
            token
                .trim()
                .parse::<u16>()
                .map_err(serde::de::Error::custom)?,
        );
    }
    Ok(out)
}

fn string_vec_from_value(value: &Value) -> std::result::Result<Vec<String>, String> {
    let values = match value {
        Value::String(_) | Value::Number(_) => vec![value.clone()],
        Value::Sequence(items) if !items.is_empty() => items.clone(),
        _ => return Err("constraint must contain nonempty scalar values".into()),
    };
    values
        .into_iter()
        .map(|item| {
            let text = match item {
                Value::String(s) => s.strip_suffix(',').unwrap_or(&s).to_string(),
                Value::Number(n) => n.to_string(),
                _ => return Err("constraint must contain scalar values".into()),
            };
            if text.is_empty() {
                Err("empty constraint".into())
            } else {
                Ok(text)
            }
        })
        .collect()
}

fn parse_event_class(raw: &str) -> Result<EventClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "process_exec" | "process_creation" => Ok(EventClass::ProcessExec),
        "process_exit" => Ok(EventClass::ProcessExit),
        "file_open" | "file_event" => Ok(EventClass::FileOpen),
        "network_connect" | "tcp_connect" | "network_connection" => Ok(EventClass::NetworkConnect),
        "dns_query" => Ok(EventClass::DnsQuery),
        "module_load" => Ok(EventClass::ModuleLoad),
        "login" => Ok(EventClass::Login),
        "alert" => Ok(EventClass::Alert),
        other => Err(SigmaCompileError::UnsupportedEventClass(other.to_string())),
    }
}
