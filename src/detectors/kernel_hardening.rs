use crate::models::Finding;
use anyhow::Result;
use std::fs;
use tracing::{debug, info};

/// Critical kernel security parameters
const CRITICAL_SYSCTLS: &[(&str, &str, &str)] = &[
    // (parameter, expected_value, description)
    (
        "kernel.dmesg_restrict",
        "1",
        "Restrict dmesg to root (prevents info disclosure)",
    ),
    (
        "kernel.kptr_restrict",
        "2",
        "Hide kernel pointers (prevents exploitation)",
    ),
    (
        "kernel.yama.ptrace_scope",
        "1",
        "Restrict ptrace (prevents process injection)",
    ),
    (
        "kernel.randomize_va_space",
        "2",
        "Enable ASLR (prevents memory exploits)",
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        "1",
        "Reverse path filtering (prevents IP spoofing)",
    ),
    ("net.ipv4.tcp_syncookies", "1", "SYN flood protection"),
    (
        "net.ipv4.conf.all.accept_source_route",
        "0",
        "Disable source routing (prevents MITM)",
    ),
    (
        "net.ipv4.conf.all.accept_redirects",
        "0",
        "Disable ICMP redirects (prevents MITM)",
    ),
    (
        "net.ipv4.conf.all.send_redirects",
        "0",
        "Disable sending redirects",
    ),
    (
        "net.ipv4.conf.all.log_martians",
        "1",
        "Log impossible addresses (detect attacks)",
    ),
    (
        "fs.protected_hardlinks",
        "1",
        "Hardlink protection (prevents privilege escalation)",
    ),
    (
        "fs.protected_symlinks",
        "1",
        "Symlink protection (prevents privilege escalation)",
    ),
    (
        "fs.suid_dumpable",
        "0",
        "Prevent SUID core dumps (prevents info disclosure)",
    ),
];

/// Check kernel hardening parameters
pub async fn check_kernel_hardening() -> Result<Vec<Finding>> {
    info!("🔍 Checking kernel hardening parameters...");
    let mut findings = Vec::new();

    let mut checked = 0;
    let mut misconfigurations = 0;

    for (param, expected, description) in CRITICAL_SYSCTLS {
        if let Some(finding) = check_sysctl(param, expected, description).await {
            findings.push(finding);
            misconfigurations += 1;
        }
        checked += 1;
    }

    info!(
        "  Checked {} kernel parameters, found {} misconfigurations",
        checked, misconfigurations
    );

    Ok(findings)
}

/// Check a single sysctl parameter
async fn check_sysctl(param: &str, expected: &str, description: &str) -> Option<Finding> {
    let sysctl_path = format!("/proc/sys/{}", param.replace('.', "/"));

    match fs::read_to_string(&sysctl_path) {
        Ok(actual) => {
            let actual = actual.trim();
            debug!("sysctl {} = {} (expected: {})", param, actual, expected);

            if actual != expected {
                let severity = match param {
                    p if p.contains("randomize_va_space") => "high", // ASLR critical
                    p if p.contains("ptrace_scope") => "high",       // Prevents code injection
                    p if p.contains("kptr_restrict") => "medium",
                    p if p.contains("protected_symlinks") || p.contains("protected_hardlinks") => {
                        "high"
                    }
                    _ => "medium",
                };

                let finding = match severity {
                    "high" => Finding::high(
                        "kernel_hardening",
                        &format!("Kernel Parameter Not Hardened: {}", param),
                        &format!(
                            "{}: Current value '{}', should be '{}'. {}",
                            param, actual, expected, description
                        ),
                    ),
                    _ => Finding::medium(
                        "kernel_hardening",
                        &format!("Kernel Parameter Not Optimal: {}", param),
                        &format!(
                            "{}: Current value '{}', recommended '{}'. {}",
                            param, actual, expected, description
                        ),
                    ),
                };

                return Some(
                    finding.with_remediation(&format!(
                        "Set parameter: sudo sysctl -w {}={} && echo '{}={}' | sudo tee -a /etc/sysctl.conf",
                        param, expected, param, expected
                    )),
                );
            }

            None
        }
        Err(_) => {
            debug!("sysctl parameter {} not available", param);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_sysctl_path_conversion() {
        let param = "kernel.dmesg_restrict";
        let path = format!("/proc/sys/{}", param.replace('.', "/"));
        assert_eq!(path, "/proc/sys/kernel/dmesg_restrict");
    }

    #[test]
    fn test_critical_sysctls_completeness() {
        assert!(CRITICAL_SYSCTLS.len() >= 12);

        // Verify all entries have values
        for (param, expected, desc) in CRITICAL_SYSCTLS {
            assert!(!param.is_empty());
            assert!(!expected.is_empty());
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn test_value_comparison() {
        assert_eq!("1".trim(), "1");
        assert_ne!("0".trim(), "1");
        assert_eq!("2".trim(), "2");
    }
}
