use regex::Regex;

#[derive(Debug, Clone)]
pub enum RiskLevel {
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct FindingRule {
    pub name: &'static str,
    pub pattern: Regex,
    pub risk: RiskLevel,
    pub recommendation: &'static str,
}

pub fn default_rules() -> Vec<FindingRule> {
    vec![
        FindingRule {
            name: "Potential secret assignment",
            pattern: Regex::new(
                r#"(?i)\b(api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{8,}["']"#
            )
            .expect("secret rule must compile"),
            risk: RiskLevel::High,
            recommendation:
                "Move credentials to a secure secret store or environment variable.",
        },

        FindingRule {
            name: "Private key material",
            pattern: Regex::new(
                r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
            )
            .expect("private-key rule must compile"),
            risk: RiskLevel::High,
            recommendation:
                "Remove the private key from source control and rotate it if exposed.",
        },

        FindingRule {
            name: "Debug configuration",
            pattern: Regex::new(
                r#"(?i)\b(debug|development_mode)\s*[:=]\s*(true|1)"#
            )
            .expect("debug rule must compile"),
            risk: RiskLevel::Medium,
            recommendation:
                "Verify that debug settings are disabled in production.",
        },
    ]
}
