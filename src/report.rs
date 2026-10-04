use regex::Regex;
use serde::Serialize;

use crate::rules::RiskLevel;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub risk: String,
    pub preview: String,
    pub recommendation: String,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
}

pub fn risk_as_string(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
    }
}

pub fn redact_line(line: &str, pattern: &Regex) -> String {
    let redacted = pattern.replace_all(line, "[REDACTED]");
    let redacted = redacted.to_string();

    let preview: String = redacted.chars().take(120).collect();

    if redacted.chars().count() > 120 {
        format!("{preview}...[truncated]")
    } else {
        preview
    }
}
