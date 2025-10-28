use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Check for available security updates
pub async fn check_security_updates() -> Result<Vec<Finding>> {
    info!("🔍 Checking for available security updates...");
    let mut findings = Vec::new();

    // Try apt (Debian/Ubuntu)
    if let Some(apt_findings) = check_apt_updates().await {
        findings.extend(apt_findings);
        return Ok(findings);
    }

    // Try dnf (Fedora/RHEL 8+)
    if let Some(dnf_findings) = check_dnf_updates().await {
        findings.extend(dnf_findings);
        return Ok(findings);
    }

    // Try yum (RHEL 7)
    if let Some(yum_findings) = check_yum_updates().await {
        findings.extend(yum_findings);
        return Ok(findings);
    }

    // Try pacman (Arch)
    if let Some(pacman_findings) = check_pacman_updates().await {
        findings.extend(pacman_findings);
        return Ok(findings);
    }

    debug!("No supported package manager found for update checking");
    Ok(findings)
}

/// Check apt for security updates (Debian/Ubuntu)
async fn check_apt_updates() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check if apt is available
    let check = Command::new("apt").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    // Update package cache (non-interactive)
    debug!("Updating apt cache...");
    let _ = Command::new("apt-get").args(["update", "-qq"]).output();

    // Get upgradeable packages
    let output = Command::new("apt")
        .args(["list", "--upgradeable"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Count security updates
    let security_updates: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("-security") || l.contains("-updates"))
        .collect();

    let total_updates: usize = stdout.lines().filter(|l| l.contains("/")).count();

    debug!(
        "Found {} total updates, {} security",
        total_updates,
        security_updates.len()
    );

    if security_updates.len() > 20 {
        findings.push(
            Finding::critical(
                "updates",
                "Many Security Updates Available",
                &format!(
                    "{} security updates available (out of {} total). System is vulnerable to known exploits.",
                    security_updates.len(),
                    total_updates
                ),
            )
            .with_remediation("Update immediately: sudo apt update && sudo apt upgrade -y"),
        );
    } else if security_updates.len() > 5 {
        findings.push(
            Finding::high(
                "updates",
                "Security Updates Available",
                &format!(
                    "{} security updates available. System may be vulnerable.",
                    security_updates.len()
                ),
            )
            .with_remediation("Update system: sudo apt update && sudo apt upgrade"),
        );
    } else if !security_updates.is_empty() {
        findings.push(
            Finding::medium(
                "updates",
                "Security Updates Available",
                &format!("{} security updates available.", security_updates.len()),
            )
            .with_remediation("Update system: sudo apt update && sudo apt upgrade"),
        );
    } else if total_updates > 50 {
        findings.push(
            Finding::medium(
                "updates",
                "Many Updates Available",
                &format!(
                    "{} updates available (non-security). Keeping system updated is good practice.",
                    total_updates
                ),
            )
            .with_remediation("Update when convenient: sudo apt update && sudo apt upgrade"),
        );
    }

    info!("  Found {} security updates", security_updates.len());
    Some(findings)
}

/// Check dnf for security updates (Fedora/RHEL 8+)
async fn check_dnf_updates() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("dnf").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    // Check for security updates
    debug!("Checking dnf for security updates...");
    let output = Command::new("dnf")
        .args(["updateinfo", "list", "security"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let security_count = stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("Last metadata"))
        .count();

    debug!("Found {} security advisories", security_count);

    if security_count > 20 {
        findings.push(
            Finding::critical(
                "updates",
                "Many Security Updates Available",
                &format!("{} security updates available via dnf", security_count),
            )
            .with_remediation("Update immediately: sudo dnf upgrade --security -y"),
        );
    } else if security_count > 5 {
        findings.push(
            Finding::high(
                "updates",
                "Security Updates Available",
                &format!("{} security updates available", security_count),
            )
            .with_remediation("Update system: sudo dnf upgrade --security"),
        );
    } else if security_count > 0 {
        findings.push(
            Finding::medium(
                "updates",
                "Security Updates Available",
                &format!("{} security updates available", security_count),
            )
            .with_remediation("Update system: sudo dnf upgrade"),
        );
    }

    info!("  Found {} security updates (dnf)", security_count);
    Some(findings)
}

/// Check yum for security updates (RHEL 7)
async fn check_yum_updates() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("yum").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    debug!("Checking yum for security updates...");
    let output = Command::new("yum")
        .args(["updateinfo", "list", "security"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let security_count = stdout
        .lines()
        .filter(|l| l.contains("RHSA") || l.contains("security"))
        .count();

    if security_count > 10 {
        findings.push(
            Finding::critical(
                "updates",
                "Many Security Updates Available",
                &format!("{} security updates available via yum", security_count),
            )
            .with_remediation("Update immediately: sudo yum update --security -y"),
        );
    } else if security_count > 0 {
        findings.push(
            Finding::high(
                "updates",
                "Security Updates Available",
                &format!("{} security updates available", security_count),
            )
            .with_remediation("Update system: sudo yum update --security"),
        );
    }

    info!("  Found {} security updates (yum)", security_count);
    Some(findings)
}

/// Check pacman for updates (Arch Linux)
async fn check_pacman_updates() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("pacman").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    debug!("Checking pacman for updates...");

    // Sync package databases
    let _ = Command::new("pacman").args(["-Sy", "--noconfirm"]).output();

    // Check for updates (uses checkupdates if available, otherwise pacman -Qu)
    let output = Command::new("checkupdates")
        .output()
        .or_else(|_| Command::new("pacman").args(["-Qu"]).output())
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let update_count = stdout.lines().filter(|l| !l.trim().is_empty()).count();

    debug!("Found {} available updates", update_count);

    if update_count > 50 {
        findings.push(
            Finding::high(
                "updates",
                "Many Updates Available",
                &format!(
                    "{} updates available. Arch is rolling release - update regularly.",
                    update_count
                ),
            )
            .with_remediation("Update system: sudo pacman -Syu"),
        );
    } else if update_count > 10 {
        findings.push(
            Finding::medium(
                "updates",
                "Updates Available",
                &format!("{} updates available", update_count),
            )
            .with_remediation("Update system: sudo pacman -Syu"),
        );
    }

    info!("  Found {} updates (pacman)", update_count);
    Some(findings)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_ufw_status_detection() {
        let inactive = "Status: inactive";
        assert!(inactive.contains("inactive"));

        let active = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere";
        assert!(active.contains("active"));

        let rule_count = active
            .lines()
            .filter(|l| l.contains("ALLOW") || l.contains("DENY"))
            .count();
        assert_eq!(rule_count, 1);
    }

    #[test]
    fn test_apt_security_update_detection() {
        let apt_output = "package1/jammy-security\npackage2/jammy-updates\npackage3/jammy";
        let security_count = apt_output
            .lines()
            .filter(|l| l.contains("-security") || l.contains("-updates"))
            .count();
        assert_eq!(security_count, 2);
    }

    // Note: Severity thresholds for update counts:
    // - Critical: > 20 updates
    // - High: 6-20 updates
    // - Medium: 1-5 updates
    // - Low: 0 updates
}
