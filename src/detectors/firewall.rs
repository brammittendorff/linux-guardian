use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Check firewall status across different firewall systems
pub async fn check_firewall() -> Result<Vec<Finding>> {
    info!("🔍 Checking firewall status...");
    let mut findings = Vec::new();

    // Try UFW first (Ubuntu/Debian default)
    if let Some(ufw_finding) = check_ufw().await {
        findings.push(ufw_finding);
        info!("  Firewall status: UFW checked");
        return Ok(findings);
    }

    // Try firewalld (RHEL/Fedora/CentOS default)
    if let Some(firewalld_finding) = check_firewalld().await {
        findings.push(firewalld_finding);
        info!("  Firewall status: firewalld checked");
        return Ok(findings);
    }

    // Try nftables
    if let Some(nft_finding) = check_nftables().await {
        findings.push(nft_finding);
        info!("  Firewall status: nftables checked");
        return Ok(findings);
    }

    // Fallback: check iptables
    if let Some(iptables_finding) = check_iptables().await {
        findings.push(iptables_finding);
        info!("  Firewall status: iptables checked");
        return Ok(findings);
    }

    // No firewall detected
    findings.push(
        Finding::critical(
            "firewall",
            "No Firewall Detected",
            "No active firewall found (UFW, firewalld, nftables, or iptables). System is exposed to network attacks.",
        )
        .with_remediation("Install and enable a firewall: sudo apt install ufw && sudo ufw enable (Ubuntu/Debian) or sudo systemctl enable --now firewalld (RHEL/Fedora)"),
    );

    info!("  Firewall status: No firewall detected");
    Ok(findings)
}

/// Check UFW (Uncomplicated Firewall) status
async fn check_ufw() -> Option<Finding> {
    let output = Command::new("ufw").arg("status").output().ok()?;

    if !output.status.success() {
        return None; // UFW not installed
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("UFW status: {}", stdout);

    if stdout.contains("Status: inactive") {
        return Some(
            Finding::critical(
                "firewall",
                "Firewall Disabled (UFW)",
                "UFW firewall is installed but not active. System is exposed to network attacks.",
            )
            .with_remediation("Enable firewall: sudo ufw enable"),
        );
    }

    if stdout.contains("Status: active") {
        // Check if rules are configured
        let rule_count = stdout
            .lines()
            .filter(|l| l.contains("ALLOW") || l.contains("DENY"))
            .count();

        if rule_count < 2 {
            let desc = format!(
                "UFW is active but only has {} rules. Consider reviewing configuration.",
                rule_count
            );
            return Some(
                Finding::medium("firewall", "Firewall Has Few Rules", &desc)
                    .with_remediation("Review firewall rules: sudo ufw status verbose"),
            );
        }

        debug!("UFW is active with {} rules", rule_count);
        return None; // Firewall is good
    }

    None
}

/// Check firewalld status
async fn check_firewalld() -> Option<Finding> {
    let output = Command::new("firewall-cmd").arg("--state").output().ok()?;

    if !output.status.success() {
        return None; // firewalld not installed
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("firewalld state: {}", stdout);

    if stdout.trim() == "not running" {
        return Some(
            Finding::critical(
                "firewall",
                "Firewall Disabled (firewalld)",
                "firewalld is installed but not running. System is exposed to network attacks.",
            )
            .with_remediation("Enable firewall: sudo systemctl enable --now firewalld"),
        );
    }

    if stdout.trim() == "running" {
        // Check default zone
        if let Ok(zone_output) = Command::new("firewall-cmd")
            .arg("--get-default-zone")
            .output()
        {
            let zone = String::from_utf8_lossy(&zone_output.stdout)
                .trim()
                .to_string();

            if zone == "public" || zone == "external" {
                debug!("firewalld running with secure default zone: {}", zone);
                return None; // Good
            } else if zone == "trusted" {
                let desc = format!(
                    "firewalld default zone is '{}' which allows all traffic",
                    zone
                );
                return Some(
                    Finding::high("firewall", "Firewall Default Zone Too Permissive", &desc)
                        .with_remediation(
                            "Set secure default zone: sudo firewall-cmd --set-default-zone=public",
                        ),
                );
            }
        }

        return None; // Firewall is running
    }

    None
}

/// Check nftables status
async fn check_nftables() -> Option<Finding> {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None; // nftables not installed
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("nftables ruleset length: {} bytes", stdout.len());

    // If output is very short or empty, no rules configured
    if stdout.trim().is_empty() || stdout.len() < 50 {
        return Some(
            Finding::high(
                "firewall",
                "nftables Has No Rules",
                "nftables is installed but has no firewall rules configured",
            )
            .with_remediation(
                "Configure nftables rules or use UFW/firewalld for easier management",
            ),
        );
    }

    // nftables is configured
    debug!("nftables has rules configured");
    None
}

/// Check iptables status
async fn check_iptables() -> Option<Finding> {
    let output = Command::new("iptables").args(["-L", "-n"]).output().ok()?;

    if !output.status.success() {
        return None; // iptables not available
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("iptables output length: {} bytes", stdout.len());

    // Count rules (excluding chain headers and policy lines)
    let rule_count = stdout
        .lines()
        .filter(|l| !l.starts_with("Chain") && !l.starts_with("target") && !l.trim().is_empty())
        .count();

    if rule_count < 3 {
        let desc = format!(
            "iptables has only {} rules configured. System likely exposed.",
            rule_count
        );
        return Some(
            Finding::critical(
                "firewall",
                "iptables Has No Rules",
                &desc,
            )
            .with_remediation("Configure iptables rules or install UFW for easier management: sudo apt install ufw && sudo ufw enable"),
        );
    }

    // Check for default ACCEPT policies (dangerous)
    if stdout.contains("policy ACCEPT") {
        // Count how many chains have ACCEPT policy
        let accept_policies = stdout
            .lines()
            .filter(|l| l.contains("policy ACCEPT"))
            .count();

        if accept_policies > 0 {
            let desc = format!(
                "{} iptables chains have default ACCEPT policy",
                accept_policies
            );
            return Some(
                Finding::high(
                    "firewall",
                    "iptables Has Permissive Default Policy",
                    &desc,
                )
                .with_remediation("Review iptables policies: sudo iptables -L -v | Consider using UFW for easier management"),
            );
        }
    }

    debug!("iptables configured with {} rules", rule_count);
    None
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_ufw_status_parsing() {
        let inactive_status = "Status: inactive";
        assert!(inactive_status.contains("inactive"));

        let active_status = "Status: active\n22/tcp ALLOW Anywhere";
        assert!(active_status.contains("active"));
    }

    #[test]
    fn test_firewalld_state_parsing() {
        assert_eq!("running".trim(), "running");
        assert_eq!("not running".trim(), "not running");
    }

    #[test]
    fn test_iptables_rule_counting() {
        let output = "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:22\n";

        let rule_count = output
            .lines()
            .filter(|l| !l.starts_with("Chain") && !l.starts_with("target") && !l.trim().is_empty())
            .count();

        assert_eq!(rule_count, 1);
    }
}
