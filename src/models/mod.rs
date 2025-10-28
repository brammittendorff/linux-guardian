use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScanMode {
    /// Fast scan (10-30 seconds) - critical checks only
    Fast,
    /// Comprehensive scan (1-3 minutes) - most checks
    Comprehensive,
    /// Deep scan (5-15 minutes) - all checks including slow ones
    Deep,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum UserProfile {
    /// Auto-detect best profile based on system
    Auto,
    /// Desktop/home user (simple, focused on malware/threats)
    Desktop,
    /// Gamer (performance-aware, cryptominer focus)
    Gaming,
    /// Software developer (dev tools, containers, supply chain)
    Developer,
    /// Server administrator (all security checks, compliance)
    Server,
    /// Maximum security (all checks, paranoid mode)
    Paranoid,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum ScanCategory {
    /// All categories
    All,
    /// Active malware, rootkits, cryptominers
    Malware,
    /// System hardening (firewall, kernel params, encryption)
    Hardening,
    /// Privacy checks (telemetry, tracking)
    Privacy,
    /// Compliance checks (CIS, NIST)
    Compliance,
    /// Development environment security
    Development,
    /// Network security (ports, connections)
    Network,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum OutputStyle {
    /// Standard terminal output
    Terminal,
    /// JSON output for automation
    Json,
    /// Simple/plain English mode (non-technical)
    Simple,
    /// Only summary (no detailed findings)
    Summary,
}

impl std::fmt::Display for UserProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserProfile::Auto => write!(f, "Auto"),
            UserProfile::Desktop => write!(f, "Desktop"),
            UserProfile::Gaming => write!(f, "Gaming"),
            UserProfile::Developer => write!(f, "Developer"),
            UserProfile::Server => write!(f, "Server"),
            UserProfile::Paranoid => write!(f, "Paranoid"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Severity level
    pub severity: String,

    /// Category of the finding
    pub category: String,

    /// Short title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Suggested remediation
    pub remediation: Option<String>,

    /// Related CVE if applicable
    pub cve: Option<String>,

    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Finding {
    pub fn critical(category: &str, title: &str, description: &str) -> Self {
        Self {
            severity: "critical".to_string(),
            category: category.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            remediation: None,
            cve: None,
            details: None,
        }
    }

    pub fn high(category: &str, title: &str, description: &str) -> Self {
        Self {
            severity: "high".to_string(),
            category: category.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            remediation: None,
            cve: None,
            details: None,
        }
    }

    pub fn medium(category: &str, title: &str, description: &str) -> Self {
        Self {
            severity: "medium".to_string(),
            category: category.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            remediation: None,
            cve: None,
            details: None,
        }
    }

    pub fn low(category: &str, title: &str, description: &str) -> Self {
        Self {
            severity: "low".to_string(),
            category: category.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            remediation: None,
            cve: None,
            details: None,
        }
    }

    pub fn with_cve(mut self, cve: &str) -> Self {
        self.cve = Some(cve.to_string());
        self
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Check if finding matches category filter
    pub fn matches_category(&self, category_filter: ScanCategory) -> bool {
        match category_filter {
            ScanCategory::All => true,
            ScanCategory::Malware => matches!(
                self.category.as_str(),
                "malware" | "cryptominer" | "rootkit" | "process"
            ),
            ScanCategory::Hardening => matches!(
                self.category.as_str(),
                "firewall"
                    | "kernel_hardening"
                    | "encryption"
                    | "mac"
                    | "bootloader"
                    | "hardware_security"
            ),
            ScanCategory::Privacy => {
                self.category.contains("telemetry") || self.category.contains("privacy")
            }
            ScanCategory::Compliance => {
                self.category.contains("compliance") || self.category == "updates"
            }
            ScanCategory::Development => matches!(
                self.category.as_str(),
                "container_security" | "credential_permissions" | "development"
            ),
            ScanCategory::Network => matches!(
                self.category.as_str(),
                "network" | "ssh" | "network_exposure" | "ssh_backdoor"
            ),
        }
    }

    /// Check if finding matches minimum severity
    pub fn matches_severity(&self, min_severity: &str) -> bool {
        let severity_order = ["low", "medium", "high", "critical"];
        let finding_idx = severity_order
            .iter()
            .position(|&s| s == self.severity)
            .unwrap_or(0);
        let min_idx = severity_order
            .iter()
            .position(|&s| s == min_severity)
            .unwrap_or(0);
        finding_idx >= min_idx
    }

    /// Check if this is an active threat (not just hardening suggestion)
    pub fn is_threat(&self) -> bool {
        matches!(
            self.category.as_str(),
            "malware"
                | "cryptominer"
                | "rootkit"
                | "ssh_backdoor"
                | "privilege_escalation"
                | "network_exposure"
        ) || self.severity == "critical"
    }
}

/// Security score breakdown
#[derive(Debug, Clone, Serialize)]
pub struct SecurityScore {
    pub overall: u32,
    pub malware_detection: u32,
    pub system_hardening: u32,
    pub privacy: u32,
    pub network_security: u32,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl SecurityScore {
    pub fn calculate(findings: &[Finding]) -> Self {
        let critical_count = findings.iter().filter(|f| f.severity == "critical").count();
        let high_count = findings.iter().filter(|f| f.severity == "high").count();
        let medium_count = findings.iter().filter(|f| f.severity == "medium").count();
        let low_count = findings.iter().filter(|f| f.severity == "low").count();

        // Scoring algorithm (100 point scale)
        // Start at 100, subtract based on severity
        let deductions = (critical_count * 15) + (high_count * 8) + (medium_count * 3) + low_count;
        let overall = 100i32.saturating_sub(deductions as i32).max(0) as u32;

        // Category scores
        let malware_issues = findings
            .iter()
            .filter(|f| matches!(f.category.as_str(), "malware" | "cryptominer" | "rootkit"))
            .count();
        let malware_detection = if malware_issues == 0 {
            100
        } else {
            100u32.saturating_sub((malware_issues * 20) as u32)
        };

        let hardening_issues = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.category.as_str(),
                    "firewall" | "kernel_hardening" | "encryption" | "mac"
                )
            })
            .count();
        let system_hardening = 100u32.saturating_sub((hardening_issues * 5) as u32);

        let privacy_issues = findings
            .iter()
            .filter(|f| f.category.contains("privacy") || f.category.contains("telemetry"))
            .count();
        let privacy = 100u32.saturating_sub((privacy_issues * 10) as u32);

        let network_issues = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.category.as_str(),
                    "network" | "ssh" | "network_exposure" | "firewall"
                )
            })
            .count();
        let network_security = 100u32.saturating_sub((network_issues * 8) as u32);

        Self {
            overall,
            malware_detection,
            system_hardening,
            privacy,
            network_security,
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }

    pub fn rating(&self) -> &str {
        match self.overall {
            90..=100 => "Excellent",
            75..=89 => "Good",
            60..=74 => "Fair",
            40..=59 => "Poor",
            _ => "Critical",
        }
    }
}
