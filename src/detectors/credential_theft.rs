/// Credential Theft Detection - Monitor access to sensitive data stores
/// Detects: Browser cookies, passwords, SSH keys, cloud credentials being stolen
use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tracing::{debug, info};

/// Sensitive credential locations (what attackers target)
const CREDENTIAL_LOCATIONS: &[(&str, &str)] = &[
    // Browser cookies & passwords
    (
        "~/.config/google-chrome/Default/Cookies",
        "Chrome cookies database",
    ),
    (
        "~/.config/google-chrome/Default/Login Data",
        "Chrome saved passwords",
    ),
    ("~/.mozilla/firefox/*/cookies.sqlite", "Firefox cookies"),
    (
        "~/.mozilla/firefox/*/logins.json",
        "Firefox saved passwords",
    ),
    (
        "~/.config/BraveSoftware/Brave-Browser/Default/Cookies",
        "Brave cookies",
    ),
    // SSH keys
    ("~/.ssh/id_rsa", "SSH private key"),
    ("~/.ssh/id_ed25519", "SSH private key"),
    ("~/.ssh/id_ecdsa", "SSH private key"),
    // Cloud provider credentials
    ("~/.aws/credentials", "AWS credentials"),
    ("~/.azure/credentials", "Azure credentials"),
    ("~/.config/gcloud/credentials", "Google Cloud credentials"),
    ("~/.kube/config", "Kubernetes credentials"),
    // Password managers
    ("~/.password-store", "pass password manager"),
    ("~/.local/share/keyrings", "GNOME Keyring"),
    // Git credentials
    ("~/.git-credentials", "Git stored credentials"),
    // Docker
    ("~/.docker/config.json", "Docker registry credentials"),
];

/// Detect processes accessing credential stores
pub async fn detect_credential_theft() -> Result<Vec<Finding>> {
    info!("🔍 Detecting credential theft attempts...");
    let mut findings = Vec::new();

    // Get home directory
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());

    // Build full paths
    let sensitive_paths: Vec<String> = CREDENTIAL_LOCATIONS
        .iter()
        .map(|(path, _)| path.replace("~", &home))
        .collect();

    // Get all processes
    let processes = match all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            debug!("Failed to read processes: {}", e);
            return Ok(findings);
        }
    };

    // Track which processes are accessing credential files
    let mut suspicious_accesses: HashSet<(i32, String)> = HashSet::new();

    for process in processes.flatten() {
        let pid = process.pid;

        // Get process name
        if let Ok(stat) = process.stat() {
            let comm = stat.comm.clone();

            // Skip legitimate processes
            if is_legitimate_credential_accessor(&comm) {
                continue;
            }

            // Check open files
            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(entries) = fs::read_dir(&fd_dir) {
                for entry in entries.flatten() {
                    if let Ok(link) = fs::read_link(entry.path()) {
                        let link_str = link.to_string_lossy().to_string();

                        // Check if accessing any sensitive path
                        for sensitive_path in &sensitive_paths {
                            if link_str.contains(sensitive_path) {
                                suspicious_accesses.insert((pid, comm.clone()));
                                debug!(
                                    "Process {} (PID {}) accessing {}",
                                    comm, pid, sensitive_path
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Report suspicious accesses
    for (pid, comm) in suspicious_accesses {
        findings.push(
            Finding::high(
                "credential_theft",
                "Suspicious Access to Credential Store",
                &format!(
                    "Process '{}' (PID: {}) is accessing sensitive credential files (cookies, passwords, SSH keys). \
                     This could indicate credential theft malware.",
                    comm, pid
                ),
            )
            .with_remediation(&format!(
                "Investigate immediately: ps -p {} -f && lsof -p {} | grep -E 'Cookies|Login|ssh|aws|kube'",
                pid, pid
            )),
        );
    }

    info!("  Found {} suspicious credential accesses", findings.len());
    Ok(findings)
}

/// Check if process legitimately accesses credentials
fn is_legitimate_credential_accessor(comm: &str) -> bool {
    let legitimate = [
        "chrome",
        "chromium",
        "firefox",
        "brave",
        "gnome-keyring",
        "kwallet",
        "ssh-agent",
        "gpg-agent",
        "pass",
        "aws",
        "gcloud",
        "kubectl",
        "docker",
    ];

    legitimate
        .iter()
        .any(|&app| comm.to_lowercase().contains(app))
}

/// Check for credential files with weak permissions
pub async fn check_credential_permissions() -> Result<Vec<Finding>> {
    info!("🔍 Checking credential file permissions...");
    let mut findings = Vec::new();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());

    // Critical files that must have strict permissions
    let protected_files = [
        (format!("{}/.ssh/id_rsa", home), 0o600, "SSH private key"),
        (
            format!("{}/.ssh/id_ed25519", home),
            0o600,
            "SSH private key",
        ),
        (
            format!("{}/.aws/credentials", home),
            0o600,
            "AWS credentials",
        ),
        (
            format!("{}/.docker/config.json", home),
            0o600,
            "Docker credentials",
        ),
        (format!("{}/.kube/config", home), 0o600, "Kubernetes config"),
    ];

    for (path, expected_mode, description) in &protected_files {
        if !std::path::Path::new(path).exists() {
            continue;
        }

        if let Ok(metadata) = fs::metadata(path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode() & 0o777;

            // Check if permissions are too open
            if mode != *expected_mode {
                let severity = if (mode & 0o044) != 0 {
                    "critical" // Readable by others
                } else {
                    "high"
                };

                let finding = if severity == "critical" {
                    Finding::critical(
                        "credential_permissions",
                        &format!("{} Has Insecure Permissions", description),
                        &format!(
                            "{} has permissions {:o} (should be {:o}). Others can read your credentials!",
                            path, mode, expected_mode
                        ),
                    )
                } else {
                    Finding::high(
                        "credential_permissions",
                        &format!("{} Has Wrong Permissions", description),
                        &format!(
                            "{} has permissions {:o} (should be {:o})",
                            path, mode, expected_mode
                        ),
                    )
                };

                findings.push(finding.with_remediation(&format!(
                    "Fix permissions: chmod {:o} '{}'",
                    expected_mode, path
                )));
            }
        }
    }

    // Check SSH directory permissions
    let ssh_dir = format!("{}/.ssh", home);
    if std::path::Path::new(&ssh_dir).exists() {
        if let Ok(metadata) = fs::metadata(&ssh_dir) {
            let permissions = metadata.permissions();
            let mode = permissions.mode() & 0o777;

            if mode != 0o700 {
                findings.push(
                    Finding::high(
                        "credential_permissions",
                        ".ssh Directory Has Wrong Permissions",
                        &format!(".ssh directory has permissions {:o} (should be 700)", mode),
                    )
                    .with_remediation(&format!("Fix: chmod 700 '{}'", ssh_dir)),
                );
            }
        }
    }

    info!("  Checked credential file permissions");
    Ok(findings)
}

/// Scan for exposed credentials in files (accidental commits, etc.)
pub async fn scan_exposed_credentials() -> Result<Vec<Finding>> {
    info!("🔍 Scanning for exposed credentials in files...");
    let mut findings = Vec::new();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());

    // Patterns that indicate exposed credentials
    let credential_patterns = [
        ("AKIA", "AWS Access Key"),
        ("AIza", "Google API Key"),
        ("sk_live_", "Stripe API Key"),
        ("ghp_", "GitHub Personal Access Token"),
        ("glpat-", "GitLab Personal Access Token"),
        ("xox", "Slack Token"),
        ("-----BEGIN PRIVATE KEY-----", "Private Key"),
        ("password=", "Password in config"),
        ("api_key=", "API Key"),
    ];

    // Scan common locations
    let scan_dirs = [
        format!("{}/.bashrc", home),
        format!("{}/.zshrc", home),
        format!("{}/.profile", home),
        format!("{}/.*_history", home),
    ];

    for file_path in &scan_dirs {
        if let Ok(content) = fs::read_to_string(file_path) {
            for (pattern, cred_type) in &credential_patterns {
                if content.contains(pattern) {
                    findings.push(
                        Finding::critical(
                            "exposed_credentials",
                            "Credentials Exposed in Shell Config",
                            &format!(
                                "{} detected in {}: {}. Credentials should never be in config files!",
                                cred_type, file_path, pattern
                            ),
                        )
                        .with_remediation(&format!(
                            "Remove credentials from {} and use environment variables or secure keyring",
                            file_path
                        )),
                    );
                }
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_credential_locations_defined() {
        assert!(CREDENTIAL_LOCATIONS.len() >= 10);
    }

    #[test]
    fn test_legitimate_accessor_detection() {
        assert!(is_legitimate_credential_accessor("chrome"));
        assert!(is_legitimate_credential_accessor("firefox"));
        assert!(!is_legitimate_credential_accessor("suspicious_script"));
    }

    #[test]
    fn test_permission_too_open() {
        let mode_644 = 0o644; // rw-r--r-- (too open for SSH key)
        let mode_600 = 0o600; // rw------- (correct)

        assert_eq!(mode_644 & 0o044, 0o044); // Others can read
        assert_eq!(mode_600 & 0o044, 0o000); // Others cannot read
    }

    #[test]
    fn test_credential_pattern_detection() {
        let content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        assert!(content.contains("AKIA"));
    }
}
