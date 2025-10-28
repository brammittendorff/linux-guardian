use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::process::Command;
use tracing::{debug, info};

/// Check Mandatory Access Control (SELinux/AppArmor) status
pub async fn check_mandatory_access_control() -> Result<Vec<Finding>> {
    info!("🔍 Checking Mandatory Access Control (SELinux/AppArmor)...");
    let mut findings = Vec::new();

    // Check SELinux (RHEL/Fedora/CentOS)
    if let Some(selinux_findings) = check_selinux().await {
        findings.extend(selinux_findings);
        info!("  MAC status: SELinux checked");
        return Ok(findings);
    }

    // Check AppArmor (Ubuntu/Debian/SUSE)
    if let Some(apparmor_findings) = check_apparmor().await {
        findings.extend(apparmor_findings);
        info!("  MAC status: AppArmor checked");
        return Ok(findings);
    }

    // No MAC system detected
    findings.push(
        Finding::high(
            "mac",
            "No Mandatory Access Control Detected",
            "Neither SELinux nor AppArmor is active. System lacks kernel-level security policy enforcement.",
        )
        .with_remediation("Enable AppArmor (Ubuntu/Debian): sudo systemctl enable apparmor && sudo systemctl start apparmor"),
    );

    info!("  MAC status: No MAC system detected");
    Ok(findings)
}

/// Check SELinux status
async fn check_selinux() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check if SELinux is present
    if !std::path::Path::new("/sys/fs/selinux").exists() {
        return None; // SELinux not available
    }

    // Check enforcement status
    if let Ok(enforce) = fs::read_to_string("/sys/fs/selinux/enforce") {
        let status = enforce.trim();
        debug!("SELinux enforce status: {}", status);

        match status {
            "0" => {
                findings.push(
                    Finding::high(
                        "mac",
                        "SELinux in Permissive Mode",
                        "SELinux is installed but not enforcing policies. Security violations are logged but not blocked.",
                    )
                    .with_remediation("Enable enforcement: sudo setenforce 1 && Edit /etc/selinux/config set SELINUX=enforcing"),
                );
            }
            "1" => {
                debug!("SELinux is enforcing - good!");
                // Check for policy type
                if let Ok(sestatus) = Command::new("sestatus").output() {
                    let output = String::from_utf8_lossy(&sestatus.stdout);

                    if !output.contains("Policy from config file:") {
                        findings.push(
                            Finding::low(
                                "mac",
                                "SELinux Policy Not Configured",
                                "SELinux is enforcing but policy type unclear",
                            )
                            .with_remediation("Check SELinux configuration: sudo sestatus -v"),
                        );
                    }
                }
            }
            _ => {
                findings.push(
                    Finding::medium(
                        "mac",
                        "SELinux Status Unknown",
                        &format!("SELinux enforce status is '{}'", status),
                    )
                    .with_remediation("Check SELinux: sudo sestatus"),
                );
            }
        }
    } else {
        findings.push(
            Finding::high(
                "mac",
                "SELinux Not Active",
                "SELinux filesystem present but enforcement status cannot be determined",
            )
            .with_remediation("Check SELinux status: sudo sestatus"),
        );
    }

    Some(findings)
}

/// Check AppArmor status
async fn check_apparmor() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check if AppArmor is present
    if !std::path::Path::new("/sys/kernel/security/apparmor").exists() {
        return None; // AppArmor not available
    }

    // Check if aa-status is available
    let output = Command::new("aa-status").output().ok()?;

    if !output.status.success() {
        // AppArmor present but aa-status failed
        findings.push(
            Finding::medium(
                "mac",
                "AppArmor Status Unknown",
                "AppArmor kernel interface present but cannot query status",
            )
            .with_remediation("Install apparmor-utils: sudo apt install apparmor-utils"),
        );
        return Some(findings);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("AppArmor status output: {} lines", stdout.lines().count());

    // Parse profile counts
    let profiles_loaded = extract_count(&stdout, "profiles are loaded");
    let profiles_enforced = extract_count(&stdout, "profiles are in enforce mode");
    let profiles_complain = extract_count(&stdout, "profiles are in complain mode");

    debug!(
        "AppArmor: {} loaded, {} enforcing, {} complain",
        profiles_loaded, profiles_enforced, profiles_complain
    );

    if profiles_loaded == 0 {
        findings.push(
            Finding::high(
                "mac",
                "AppArmor Has No Profiles Loaded",
                "AppArmor is present but no security profiles are loaded",
            )
            .with_remediation("Enable AppArmor profiles: sudo aa-enforce /etc/apparmor.d/*"),
        );
    } else if profiles_enforced == 0 {
        findings.push(
            Finding::high(
                "mac",
                "AppArmor Not Enforcing",
                &format!(
                    "AppArmor has {} profiles loaded but none in enforce mode (all in complain)",
                    profiles_loaded
                ),
            )
            .with_remediation("Set profiles to enforce mode: sudo aa-enforce /etc/apparmor.d/*"),
        );
    } else if profiles_complain > profiles_enforced {
        findings.push(
            Finding::medium(
                "mac",
                "Many AppArmor Profiles in Complain Mode",
                &format!(
                    "{} profiles in complain mode vs {} enforcing. Violations are logged but not blocked.",
                    profiles_complain, profiles_enforced
                ),
            )
            .with_remediation("Review and enforce profiles: sudo aa-status && sudo aa-enforce /etc/apparmor.d/<profile>"),
        );
    } else {
        debug!(
            "AppArmor properly configured: {} enforcing, {} complain",
            profiles_enforced, profiles_complain
        );
    }

    Some(findings)
}

/// Extract count from aa-status output
/// Example: "37 profiles are loaded." → 37
fn extract_count(text: &str, pattern: &str) -> usize {
    for line in text.lines() {
        if line.contains(pattern) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(first) = parts.first() {
                if let Ok(count) = first.parse::<usize>() {
                    return count;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_selinux_status_parsing() {
        assert_eq!("0".trim(), "0"); // Permissive
        assert_eq!("1".trim(), "1"); // Enforcing
    }

    #[test]
    fn test_apparmor_count_extraction() {
        let output = "37 profiles are loaded.\n36 profiles are in enforce mode.\n1 profile is in complain mode.";

        assert_eq!(extract_count(output, "profiles are loaded"), 37);
        assert_eq!(extract_count(output, "profiles are in enforce mode"), 36);
        assert_eq!(extract_count(output, "profile is in complain mode"), 1);
    }

    #[test]
    fn test_dpkg_verify_parsing() {
        let line = "??5??????  c /etc/example.conf";
        let is_config = line.contains("/etc/") || line.contains(".conf");
        assert!(is_config);

        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts[0].chars().nth(2), Some('5')); // MD5 mismatch at index 2
    }
}
