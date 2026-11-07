use crate::types::TelemetryEvent;

/// Same-event Sigma logic, separate from temporal sequence correlation.
#[derive(Debug)]
pub enum SigmaExpr {
    All(Vec<SigmaExpr>),
}

impl SigmaExpr {
    pub fn matches(&self, event: &TelemetryEvent) -> bool {
        match self {
            Self::All(children) => children.iter().all(|child| child.matches(event)),
        }
    }
}
