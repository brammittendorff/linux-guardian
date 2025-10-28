use crate::models::Finding;
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tracing::{debug, info};
use walkdir::WalkDir;

/// Check for vulnerable sudo versions (CVE-2025-32462, CVE-2025-32463)
pub async fn check_sudo_vulnerabilities() -> Result<Vec<Finding>> {
    info!("🔍 Checking sudo version for known vulnerabilities...");
    let mut findings = Vec::new();

    // Try to get sudo version
    let output = Command::new("sudo").arg("--version").output();

    if let Ok(output) = output {
        let version_str = String::from_utf8_lossy(&output.stdout);
        debug!("Sudo version output: {}", version_str);

        // Parse version number
        let re = Regex::new(r"Sudo version (\d+)\.(\d+)\.(\d+)").unwrap();
        if let Some(captures) = re.captures(&version_str) {
            let major: u32 = captures[1].parse().unwrap_or(0);
            let minor: u32 = captures[2].parse().unwrap_or(0);
            let patch: u32 = captures[3].parse().unwrap_or(0);

            debug!("Parsed version: {}.{}.{}", major, minor, patch);

            // Check for CVE-2025-32462 & CVE-2025-32463
            // Vulnerable: 1.8.8 through 1.9.17 (before 1.9.17p1)
            if major == 1
                && minor >= 8
                && ((minor == 8 && patch >= 8) || (minor == 9 && patch <= 17))
            {
                let cve_desc = if minor == 9 && (14..=17).contains(&patch) {
                    "CVE-2025-32462 (Policy-Check) and CVE-2025-32463 (chroot-to-root, CVSS 9.3)"
                } else {
                    "CVE-2025-32462 (Policy-Check Flaw)"
                };

                findings.push(
                        Finding::critical(
                            "privilege_escalation",
                            "Vulnerable Sudo Version Detected",
                            &format!(
                                "Sudo version {}.{}.{} is vulnerable to {}.  This allows local privilege escalation to root.",
                                major, minor, patch, cve_desc
                            ),
                        )
                        .with_cve("CVE-2025-32462, CVE-2025-32463")
                        .with_remediation("Update sudo to version 1.9.17p1 or later immediately: sudo apt update && sudo apt upgrade sudo"),
                    );
            }

            // Check for other known CVEs based on version
            // CVE-2021-3156 (Baron Samedit) - versions before 1.9.5p2
            if major == 1 && minor <= 9 && patch < 5 {
                findings.push(
                    Finding::critical(
                        "privilege_escalation",
                        "Sudo Heap Overflow Vulnerability (Baron Samedit)",
                        &format!(
                            "Sudo version {}.{}.{} is vulnerable to CVE-2021-3156, allowing heap-based buffer overflow for privilege escalation.",
                            major, minor, patch
                        ),
                    )
                    .with_cve("CVE-2021-3156")
                    .with_remediation("Update sudo to version 1.9.5p2 or later"),
                );
            }
        }
    } else {
        debug!("Sudo not found or not accessible");
    }

    Ok(findings)
}

/// Check if a binary is part of an installed package
/// Returns Some(package_name) if it's packaged, None otherwise
fn check_if_packaged(path: &str) -> Option<String> {
    // Try dpkg (Debian/Ubuntu)
    if let Ok(output) = Command::new("dpkg").arg("-S").arg(path).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // dpkg -S output format: "package-name: /path/to/file"
            if let Some(pkg) = stdout.split(':').next() {
                return Some(pkg.trim().to_string());
            }
        }
    }

    // Try rpm (RedHat/Fedora/CentOS)
    if let Ok(output) = Command::new("rpm").arg("-qf").arg(path).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // rpm -qf output is just the package name
            if !stdout.is_empty() && !stdout.contains("not owned") {
                return Some(stdout);
            }
        }
    }

    // Try pacman (Arch Linux)
    if let Ok(output) = Command::new("pacman").arg("-Qo").arg(path).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // pacman -Qo output format: "/path is owned by package version"
            if let Some(owned_part) = stdout.split("is owned by").nth(1) {
                if let Some(pkg) = owned_part.split_whitespace().next() {
                    return Some(pkg.to_string());
                }
            }
        }
    }

    None
}

/// Scan for SUID and SGID binaries
pub async fn scan_suid_binaries(is_root: bool) -> Result<Vec<Finding>> {
    info!("🔍 Scanning for suspicious SUID/SGID binaries...");
    let mut findings = Vec::new();

    if !is_root {
        debug!("Skipping SUID scan - requires root privileges for complete scan");
        return Ok(findings);
    }

    // Known legitimate SUID binaries (whitelist)
    let legitimate_suid: HashSet<&str> = [
        // Core system utilities
        "/usr/bin/sudo",
        "/usr/bin/sudoedit",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chfn",
        "/usr/bin/chsh",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/pkexec",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/fusermount",
        "/usr/bin/fusermount3",
        "/usr/bin/sg",
        "/usr/bin/newuidmap",
        "/usr/bin/newgidmap",
        "/usr/bin/ubuntu-core-launcher",
        "/bin/su",
        "/bin/sudo",
        "/bin/sudoedit",
        "/bin/mount",
        "/bin/umount",
        "/bin/ping",
        "/bin/fusermount",
        "/bin/fusermount3",
        "/bin/passwd",
        "/bin/chfn",
        "/bin/chsh",
        "/bin/newgrp",
        "/bin/gpasswd",
        "/bin/pkexec",
        "/bin/sg",
        "/bin/newuidmap",
        "/bin/newgidmap",
        "/bin/ntfs-3g",
        "/bin/ubuntu-core-launcher",
        // PolicyKit
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        // OpenSSH
        "/usr/lib/openssh/ssh-keysign",
        // NFS
        "/usr/sbin/mount.nfs",
        "/sbin/mount.nfs",
        // NTFS support
        "/usr/bin/ntfs-3g",
        "/sbin/mount.ntfs-3g",
        "/sbin/mount.ntfs",
        // Networking
        "/usr/bin/ping",
        "/usr/bin/ping6",
        "/sbin/pppd",
        "/usr/sbin/pppd",
        // Mail (Exim, Sendmail, Postfix)
        "/usr/sbin/exim4",
        "/usr/sbin/exim",
        "/usr/sbin/sendmail",
        "/usr/sbin/rsmtp",
        "/usr/sbin/rmail",
        "/usr/sbin/runq",
        "/usr/bin/newaliases",
        "/usr/bin/mailq",
        "/usr/lib/exim4/exim4",
        "/usr/lib/sendmail",
        "/sbin/exim4",
        "/sbin/exim",
        "/sbin/sendmail",
        "/sbin/rsmtp",
        "/sbin/rmail",
        "/sbin/runq",
        "/bin/newaliases",
        "/bin/mailq",
        // Xorg/Display
        "/usr/lib/xorg/Xorg.wrap",
        "/usr/bin/Xorg",
        // Package managers
        "/usr/bin/pkexec",
        // Other legitimate tools
        "/sbin/runq",
        "/usr/bin/at",
        "/usr/bin/crontab",
        "/usr/sbin/unix_chkpwd",
        "/usr/bin/chage",
    ]
    .iter()
    .cloned()
    .collect();

    // Suspicious locations for SUID binaries
    let suspicious_paths = ["/tmp", "/dev/shm", "/var/tmp", "/home"];

    // Scan system for SUID/SGID binaries
    let search_paths = ["/usr", "/bin", "/sbin", "/tmp", "/var", "/home", "/dev"];

    for base_path in &search_paths {
        if !std::path::Path::new(base_path).exists() {
            continue;
        }

        for entry in WalkDir::new(base_path)
            .max_depth(if base_path == &"/tmp" || base_path == &"/var" {
                6
            } else {
                10
            })
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip non-files
            if !path.is_file() {
                continue;
            }

            // Check permissions
            if let Ok(metadata) = fs::metadata(path) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();

                // Check for SUID (4000) or SGID (2000)
                let is_suid = (mode & 0o4000) != 0;
                let is_sgid = (mode & 0o2000) != 0;

                if is_suid || is_sgid {
                    let path_str = path.to_string_lossy().to_string();
                    debug!("Found SUID/SGID binary: {}", path_str);

                    // Check if it's in a suspicious location
                    let in_suspicious_location =
                        suspicious_paths.iter().any(|sp| path_str.starts_with(sp));

                    // Check if it's not in the whitelist
                    let is_unknown = !legitimate_suid.contains(path_str.as_str());

                    if in_suspicious_location {
                        findings.push(
                            Finding::critical(
                                "privilege_escalation",
                                "SUID Binary in Suspicious Location",
                                &format!(
                                    "Found {} binary in suspicious location: {}. This could indicate a privilege escalation backdoor.",
                                    if is_suid { "SUID" } else { "SGID" },
                                    path_str
                                ),
                            )
                            .with_remediation(&format!("Investigate and remove if malicious: sudo rm '{}'", path_str)),
                        );
                    } else if is_unknown && is_suid {
                        // IMPROVED: Check if binary is part of an installed package
                        let package_info = check_if_packaged(&path_str);

                        if let Some(pkg_name) = package_info {
                            // Binary is part of a legitimate package - log but don't flag as finding
                            debug!(
                                "SUID binary {} is part of package '{}' - legitimate",
                                path_str, pkg_name
                            );
                        } else {
                            // Binary is NOT part of any package - suspicious!
                            findings.push(
                                Finding::high(
                                    "privilege_escalation",
                                    "Unpackaged SUID Binary Detected",
                                    &format!(
                                        "Found SUID binary not managed by package manager: {}. This is highly suspicious.",
                                        path_str
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate origin: ls -la '{}' && file '{}' && sudo strings '{}' | head -20",
                                    path_str, path_str, path_str
                                )),
                            );
                        }
                    }
                }
            }
        }
    }

    info!("  Found {} suspicious SUID/SGID binaries", findings.len());
    Ok(findings)
}

/// Check for kernel vulnerabilities (CVE database check)
pub async fn check_kernel_vulnerabilities() -> Result<Vec<Finding>> {
    info!("🔍 Checking kernel version for known vulnerabilities...");
    let mut findings = Vec::new();

    // Read kernel version
    if let Ok(version) = fs::read_to_string("/proc/version") {
        debug!("Kernel version: {}", version);

        // Parse kernel version
        let re = Regex::new(r"Linux version (\d+)\.(\d+)\.(\d+)").unwrap();
        if let Some(captures) = re.captures(&version) {
            let major: u32 = captures[1].parse().unwrap_or(0);
            let minor: u32 = captures[2].parse().unwrap_or(0);
            let patch: u32 = captures[3].parse().unwrap_or(0);

            // Check for known vulnerable kernel versions
            // CVE-2023-0386 - OverlayFS privilege escalation
            if major == 5 && minor < 19 {
                findings.push(
                    Finding::high(
                        "privilege_escalation",
                        "Kernel Vulnerable to OverlayFS Exploit",
                        &format!(
                            "Kernel version {}.{}.{} may be vulnerable to CVE-2023-0386 (OverlayFS privilege escalation)",
                            major, minor, patch
                        ),
                    )
                    .with_cve("CVE-2023-0386")
                    .with_remediation("Update kernel to 5.19+ or apply security patches"),
                );
            }

            // CVE-2021-22555 - Netfilter heap overflow
            if major <= 5 && minor < 12 {
                findings.push(
                    Finding::high(
                        "privilege_escalation",
                        "Kernel Vulnerable to Netfilter Exploit",
                        &format!(
                            "Kernel version {}.{}.{} may be vulnerable to CVE-2021-22555 (Netfilter heap overflow)",
                            major, minor, patch
                        ),
                    )
                    .with_cve("CVE-2021-22555")
                    .with_remediation("Update kernel to 5.12+ or apply security patches"),
                );
            }
        }
    }

    Ok(findings)
}

/// Check for capabilities abuse
pub async fn check_capabilities_abuse() -> Result<Vec<Finding>> {
    info!("🔍 Checking for suspicious file capabilities...");
    let mut findings = Vec::new();

    // Try to use getcap to find files with capabilities
    let output = Command::new("getcap").arg("-r").arg("/").output();

    if let Ok(output) = output {
        let result = String::from_utf8_lossy(&output.stdout);

        // Dangerous capabilities
        let dangerous_caps = [
            "cap_dac_override",    // Bypass file read/write/execute permission checks
            "cap_dac_read_search", // Bypass file read permission checks
            "cap_sys_admin",       // Allows almost any privileged operation
            "cap_sys_ptrace",      // Allows tracing any process
            "cap_sys_module",      // Allows loading kernel modules
        ];

        for line in result.lines() {
            for cap in &dangerous_caps {
                if line.contains(cap) {
                    findings.push(
                        Finding::high(
                            "privilege_escalation",
                            "Dangerous File Capability Detected",
                            &format!("File has dangerous capability: {}", line),
                        )
                        .with_remediation(
                            "Review and remove if unnecessary: sudo setcap -r <file>",
                        ),
                    );
                }
            }
        }
    }

    Ok(findings)
}
