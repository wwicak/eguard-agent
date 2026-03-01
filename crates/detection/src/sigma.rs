use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};

use crate::layer2::{TemporalPredicate, TemporalRule, TemporalStage};
use crate::types::EventClass;

#[derive(Debug, Clone)]
pub struct BoundedTemporalAst {
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
    MissingStageWindow { stage_index: usize },
    UnsupportedEventClass(String),
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
    within_secs: Option<u64>,
}

#[derive(Debug, Default)]
struct LegacySigmaAccumulator {
    process_any_of: HashSet<String>,
    parent_any_of: HashSet<String>,
    command_line_contains: HashSet<String>,
    file_path_any_of: HashSet<String>,
    file_path_contains: HashSet<String>,
    dst_port_any_of: HashSet<u16>,
}

impl LegacySigmaAccumulator {
    fn has_process_constraints(&self) -> bool {
        !self.process_any_of.is_empty()
            || !self.parent_any_of.is_empty()
            || !self.command_line_contains.is_empty()
    }

    fn has_file_constraints(&self) -> bool {
        !self.file_path_any_of.is_empty() || !self.file_path_contains.is_empty()
    }

    fn has_network_constraints(&self) -> bool {
        !self.dst_port_any_of.is_empty()
    }
}

pub fn compile_sigma_rule(yaml: &str) -> Result<TemporalRule> {
    let ast = compile_sigma_ast(yaml)?;
    Ok(temporal_rule_from_ast(&ast))
}

pub fn compile_sigma_ast(yaml: &str) -> Result<BoundedTemporalAst> {
    let doc: SigmaRuleDoc =
        serde_yaml::from_str(yaml).map_err(|err| SigmaCompileError::ParseYaml(err.to_string()))?;

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
                event_class,
                process_any_of: into_set(stage.process_any_of),
                process_starts_with: None,
                parent_any_of: into_set(stage.parent_any_of),
                uid_eq: stage.uid_eq,
                uid_ne: stage.uid_ne,
                dst_port_not_in: into_u16_set(stage.dst_port_not_in),
                dst_port_any_of: into_u16_set(stage.dst_port_any_of),
                file_path_any_of: into_set(stage.file_path_any_of),
                file_path_contains: into_set(stage.file_path_contains),
                command_line_contains: into_set(stage.command_line_contains),
                require_file_write: false,
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
    Ok(BoundedTemporalAst { name, stages, root })
}

fn compile_legacy_sigma_ast(yaml: &str, doc: &SigmaRuleDoc) -> Result<BoundedTemporalAst> {
    let root: Value =
        serde_yaml::from_str(yaml).map_err(|err| SigmaCompileError::ParseYaml(err.to_string()))?;
    let Some(root_map) = root.as_mapping() else {
        return Err(SigmaCompileError::MissingDetectionSequence);
    };

    let Some(detection) = mapping_get(root_map, "detection").and_then(Value::as_mapping) else {
        return Err(SigmaCompileError::MissingDetectionSequence);
    };

    let condition = mapping_get(detection, "condition")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("selection");

    let selector_names = select_legacy_selector_names(detection, condition);
    if selector_names.is_empty() {
        return Err(SigmaCompileError::MissingDetectionSequence);
    }

    let mut acc = LegacySigmaAccumulator::default();
    for selector in selector_names {
        if let Some(value) = mapping_get(detection, &selector) {
            accumulate_legacy_selector_value(value, &mut acc);
        }
    }

    let event_class = infer_legacy_event_class(&acc, &doc.logsource).ok_or_else(|| {
        SigmaCompileError::UnsupportedEventClass("legacy_sigma_unmappable".to_string())
    })?;

    let stage = AstStage {
        predicate: TemporalPredicate {
            event_class,
            process_any_of: some_set(acc.process_any_of),
            process_starts_with: None,
            parent_any_of: some_set(acc.parent_any_of),
            uid_eq: None,
            uid_ne: None,
            dst_port_not_in: None,
            dst_port_any_of: some_u16_set(acc.dst_port_any_of),
            file_path_any_of: some_set(acc.file_path_any_of),
            file_path_contains: some_set(acc.file_path_contains),
            command_line_contains: some_set(acc.command_line_contains),
            require_file_write: false,
        },
        within_secs: 30,
    };

    let name = doc
        .title
        .clone()
        .and_then(non_empty)
        .or_else(|| doc.id.clone().and_then(non_empty))
        .unwrap_or_else(|| "sigma_unnamed_rule".to_string());

    Ok(BoundedTemporalAst {
        name,
        stages: vec![stage],
        root: TemporalExpr::Stage(0),
    })
}

fn infer_legacy_event_class(
    acc: &LegacySigmaAccumulator,
    logsource: &SigmaLogSource,
) -> Option<EventClass> {
    if acc.has_process_constraints() {
        return Some(EventClass::ProcessExec);
    }
    if acc.has_file_constraints() {
        return Some(EventClass::FileOpen);
    }
    if acc.has_network_constraints() {
        return Some(EventClass::NetworkConnect);
    }

    let category = logsource.category.trim().to_ascii_lowercase();
    let product = logsource.product.trim().to_ascii_lowercase();
    let service = logsource.service.trim().to_ascii_lowercase();

    if category.contains("process") || service.contains("auditd") {
        Some(EventClass::ProcessExec)
    } else if category.contains("file") {
        Some(EventClass::FileOpen)
    } else if category.contains("network") {
        Some(EventClass::NetworkConnect)
    } else if category.contains("dns") {
        Some(EventClass::DnsQuery)
    } else if product == "linux" && service == "auditd" {
        Some(EventClass::ProcessExec)
    } else {
        None
    }
}

fn select_legacy_selector_names(detection: &Mapping, condition: &str) -> Vec<String> {
    let mut available = Vec::new();
    for key in detection.keys() {
        let Some(name) = key.as_str() else {
            continue;
        };
        if name.eq_ignore_ascii_case("condition") {
            continue;
        }
        available.push(name.to_string());
    }

    if available.is_empty() {
        return Vec::new();
    }

    let mut lookup = HashMap::new();
    for name in &available {
        lookup.insert(name.to_ascii_lowercase(), name.clone());
    }

    let sanitized = condition.replace(['(', ')', '\n'], " ");
    let mut selected = HashSet::new();

    for term in split_condition_terms(&sanitized) {
        if term.is_empty() {
            continue;
        }

        let mut positive = term.trim();
        if let Some(rest) = strip_prefix_ci(positive, "not ") {
            let _ = rest;
            continue;
        }

        if let Some(rest) =
            strip_prefix_ci(positive, "1 of ").or_else(|| strip_prefix_ci(positive, "all of "))
        {
            positive = rest.trim();
            if let Some(prefix) = positive.strip_suffix('*') {
                let prefix = prefix.trim().to_ascii_lowercase();
                for name in &available {
                    if name.to_ascii_lowercase().starts_with(&prefix) {
                        selected.insert(name.clone());
                    }
                }
                continue;
            }
        }

        let key = positive.trim().to_ascii_lowercase();
        if let Some(name) = lookup.get(&key) {
            selected.insert(name.clone());
        }
    }

    if selected.is_empty() {
        if let Some(selection) = lookup.get("selection") {
            selected.insert(selection.clone());
        }
    }

    available
        .into_iter()
        .filter(|name| selected.contains(name))
        .collect()
}

fn split_condition_terms(raw: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut current = String::new();

    for token in raw.split_whitespace() {
        if token.eq_ignore_ascii_case("and") || token.eq_ignore_ascii_case("or") {
            if !current.trim().is_empty() {
                terms.push(current.trim().to_string());
                current.clear();
            }
            continue;
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(token);
    }

    if !current.trim().is_empty() {
        terms.push(current.trim().to_string());
    }

    terms
}

fn strip_prefix_ci<'a>(raw: &'a str, prefix: &str) -> Option<&'a str> {
    if raw.len() < prefix.len() {
        return None;
    }

    if raw[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&raw[prefix.len()..])
    } else {
        None
    }
}

fn accumulate_legacy_selector_value(value: &Value, acc: &mut LegacySigmaAccumulator) {
    match value {
        Value::Mapping(map) => {
            for (key, field_value) in map {
                let Some(field_spec) = key.as_str() else {
                    continue;
                };
                if field_spec.eq_ignore_ascii_case("condition") {
                    continue;
                }
                accumulate_legacy_field_constraint(field_spec, field_value, acc);
            }
        }
        Value::Sequence(items) => {
            for item in items {
                accumulate_legacy_selector_value(item, acc);
            }
        }
        _ => {
            for token in collect_scalar_strings(value) {
                if let Some(needle) = normalize_contains_needle(&token) {
                    acc.command_line_contains.insert(needle);
                }
            }
        }
    }
}

fn accumulate_legacy_field_constraint(
    field_spec: &str,
    value: &Value,
    acc: &mut LegacySigmaAccumulator,
) {
    let mut parts = field_spec.split('|');
    let base = parts.next().unwrap_or("").trim().to_ascii_lowercase();

    if base.is_empty() {
        return;
    }

    let values = collect_scalar_strings(value);
    if values.is_empty() {
        return;
    }

    if is_destination_port_field(&base) {
        for token in values {
            if let Ok(port) = token.trim().parse::<u16>() {
                acc.dst_port_any_of.insert(port);
            }
        }
        return;
    }

    if is_process_field(&base) {
        for token in values {
            if let Some(name) = normalize_process_name(&token) {
                acc.process_any_of.insert(name);
            }
        }
        return;
    }

    if is_parent_process_field(&base) {
        for token in values {
            if let Some(name) = normalize_process_name(&token) {
                acc.parent_any_of.insert(name);
            }
        }
        return;
    }

    if is_file_field(&base) {
        for token in values {
            if let Some(path) = normalize_path_needle(&token) {
                acc.file_path_contains.insert(path);
            }
        }
        return;
    }

    if is_command_line_field(&base) {
        for token in values {
            if let Some(needle) = normalize_contains_needle(&token) {
                acc.command_line_contains.insert(needle);
            }
        }
    }
}

fn is_destination_port_field(base: &str) -> bool {
    matches!(base, "destinationport" | "dst_port" | "dport")
}

fn is_process_field(base: &str) -> bool {
    matches!(
        base,
        "image" | "exe" | "processname" | "process_name" | "process.executable"
    )
}

fn is_parent_process_field(base: &str) -> bool {
    matches!(
        base,
        "parentimage" | "parentprocessname" | "parent_process_name" | "parent.process.name"
    )
}

fn is_file_field(base: &str) -> bool {
    matches!(
        base,
        "targetfilename" | "filename" | "filepath" | "path" | "name" | "currentdirectory"
    )
}

fn is_command_line_field(base: &str) -> bool {
    if matches!(
        base,
        "commandline"
            | "parentcommandline"
            | "cmd"
            | "commands"
            | "execve"
            | "comm"
            | "query"
            | "c-uri"
            | "cs-uri"
            | "cs-uri-query"
            | "cs-uri-stem"
            | "cs-host"
            | "c-useragent"
            | "cs-user-agent"
            | "signature"
    ) {
        return true;
    }

    if let Some(rest) = base.strip_prefix('a') {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }

    false
}

fn normalize_process_name(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('*');
    if trimmed.is_empty() {
        return None;
    }

    let basename = trimmed
        .rsplit_once('/')
        .map(|(_, tail)| tail)
        .or_else(|| trimmed.rsplit_once('\\').map(|(_, tail)| tail))
        .unwrap_or(trimmed)
        .trim();

    if basename.is_empty() {
        None
    } else {
        Some(basename.to_ascii_lowercase())
    }
}

fn normalize_path_needle(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('*');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn normalize_contains_needle(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('*');
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed
        .replace("\\\\", "\\")
        .replace("^", "")
        .replace("$", "")
        .trim()
        .to_ascii_lowercase();

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn collect_scalar_strings(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_scalar_strings_into(value, &mut out);
    out
}

fn collect_scalar_strings_into(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Null => {}
        Value::Bool(v) => out.push(v.to_string()),
        Value::Number(v) => out.push(v.to_string()),
        Value::String(v) => out.push(v.clone()),
        Value::Sequence(values) => {
            for item in values {
                collect_scalar_strings_into(item, out);
            }
        }
        Value::Mapping(map) => {
            for nested in map.values() {
                collect_scalar_strings_into(nested, out);
            }
        }
        _ => {}
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

fn some_set(values: HashSet<String>) -> Option<HashSet<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn into_u16_set(values: Vec<u16>) -> Option<HashSet<u16>> {
    if values.is_empty() {
        return None;
    }
    Some(values.into_iter().collect())
}

fn some_u16_set(values: HashSet<u16>) -> Option<HashSet<u16>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
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
    Ok(string_vec_from_value(&value))
}

fn deserialize_u16_vec_lenient<'de, D>(deserializer: D) -> std::result::Result<Vec<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let mut out = Vec::new();
    for token in string_vec_from_value(&value) {
        if let Ok(port) = token.trim().parse::<u16>() {
            out.push(port);
        }
    }
    Ok(out)
}

fn string_vec_from_value(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_scalar_strings_into(value, &mut out);

    out.into_iter()
        .map(|item| item.trim().trim_matches(',').trim().to_string())
        .filter(|item| {
            let lower = item.to_ascii_lowercase();
            !item.is_empty() && lower != "none" && lower != "null"
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
