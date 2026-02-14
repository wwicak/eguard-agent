use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;

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
    detection: SigmaDetection,
}

#[derive(Debug, Deserialize)]
struct SigmaDetection {
    #[serde(default)]
    sequence: Vec<SigmaStage>,
}

#[derive(Debug, Deserialize)]
struct SigmaStage {
    event_class: String,
    #[serde(default)]
    process_any_of: Vec<String>,
    #[serde(default)]
    parent_any_of: Vec<String>,
    #[serde(default)]
    uid_eq: Option<u32>,
    #[serde(default)]
    uid_ne: Option<u32>,
    #[serde(default)]
    dst_port_not_in: Vec<u16>,
    #[serde(default)]
    within_secs: Option<u64>,
}

pub fn compile_sigma_rule(yaml: &str) -> Result<TemporalRule> {
    let ast = compile_sigma_ast(yaml)?;
    Ok(temporal_rule_from_ast(&ast))
}

pub fn compile_sigma_ast(yaml: &str) -> Result<BoundedTemporalAst> {
    let doc: SigmaRuleDoc =
        serde_yaml::from_str(yaml).map_err(|err| SigmaCompileError::ParseYaml(err.to_string()))?;

    if doc.detection.sequence.is_empty() {
        return Err(SigmaCompileError::MissingDetectionSequence);
    }

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
                parent_any_of: into_set(stage.parent_any_of),
                uid_eq: stage.uid_eq,
                uid_ne: stage.uid_ne,
                dst_port_not_in: if stage.dst_port_not_in.is_empty() {
                    None
                } else {
                    Some(stage.dst_port_not_in.into_iter().collect())
                },
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

fn parse_event_class(raw: &str) -> Result<EventClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "process_exec" => Ok(EventClass::ProcessExec),
        "process_exit" => Ok(EventClass::ProcessExit),
        "file_open" => Ok(EventClass::FileOpen),
        "network_connect" | "tcp_connect" => Ok(EventClass::NetworkConnect),
        "dns_query" => Ok(EventClass::DnsQuery),
        "module_load" => Ok(EventClass::ModuleLoad),
        "login" => Ok(EventClass::Login),
        "alert" => Ok(EventClass::Alert),
        other => Err(SigmaCompileError::UnsupportedEventClass(other.to_string())),
    }
}
