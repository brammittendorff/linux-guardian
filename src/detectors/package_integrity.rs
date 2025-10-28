use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Verify package integrity to detect supply chain attacks and tampering
pub async fn verify_package_integrity() -> Result<Vec<Finding>> {
    info!("🔍 Verifying package integrity (supply chain attack detection)...");
    let mut findings = Vec::new();

    // Try dpkg (Debian/Ubuntu)
    if let Some(dpkg_findings) = check_dpkg_integrity().await {
        findings.extend(dpkg_findings);
        return Ok(findings);
    }

    // Try rpm (RHEL/Fedora)
    if let Some(rpm_findings) = check_rpm_integrity().await {
        findings.extend(rpm_findings);
        return Ok(findings);
    }

    // Try pacman (Arch)
    if let Some(pacman_findings) = check_pacman_integrity().await {
        findings.extend(pacman_findings);
        return Ok(findings);
    }

    debug!("No supported package manager found for integrity checking");
    Ok(findings)
}

/// Check dpkg package integrity (Debian/Ubuntu)
async fn check_dpkg_integrity() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("dpkg").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    info!(
        "  Running dpkg --verify (verifying ALL installed packages - this takes 30-90 seconds)..."
    );
    let start = std::time::Instant::now();

    let output = Command::new("dpkg").args(["--verify"]).output().ok()?;

    let elapsed = start.elapsed();
    debug!("dpkg --verify completed in {:.2}s", elapsed.as_secs_f32());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // dpkg --verify output format:
    // ??5??????  /usr/bin/example
    // Position meanings:
    // 1: Package file checksum
    // 5: MD5 checksum mismatch (CRITICAL - file modified!)

    let mut modified_files = Vec::new();
    let mut config_changes = 0;

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }

        // Parse verification code
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let status_code = parts[0];
        let file_path = parts[1];

        // Check if it's a config file (expected to change)
        let is_config = file_path.contains("/etc/") || file_path.contains(".conf");

        // Check for MD5 mismatch (position 4 = index 4 in status_code)
        if status_code.len() >= 5 && status_code.chars().nth(4) == Some('5') {
            if is_config {
                config_changes += 1;
                debug!("Config file modified (expected): {}", file_path);
            } else {
                // Non-config file modified = TAMPERING!
                modified_files.push(file_path.to_string());

                findings.push(
                    Finding::critical(
                        "package_integrity",
                        "System Package File Tampered",
                        &format!(
                            "File {} has been modified from its installed package version. This could indicate supply chain attack or system compromise.",
                            file_path
                        ),
                    )
                    .with_remediation(&format!(
                        "Investigate immediately: sudo dpkg -S {} && sudo apt-get install --reinstall $(dpkg -S {} | cut -d: -f1)",
                        file_path, file_path
                    )),
                );
            }
        }
    }

    if modified_files.is_empty() && config_changes == 0 {
        debug!("Package integrity check: All packages verified successfully");
    } else {
        info!(
            "  Package integrity: {} files modified ({} configs, {} suspicious)",
            config_changes + modified_files.len(),
            config_changes,
            modified_files.len()
        );
    }

    Some(findings)
}

/// Check rpm package integrity (RHEL/Fedora)
async fn check_rpm_integrity() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("rpm").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    info!("  Running rpm -Va (this may take 30-60 seconds)...");

    let output = Command::new("rpm").args(["-Va"]).output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // rpm -Va output format:
    // S.5....T.  c /etc/example.conf
    // S = Size, 5 = MD5 checksum, T = mtime, c = config file

    let mut modified_files = Vec::new();
    let mut config_changes = 0;

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }

        let is_config = line.contains(" c ");
        let has_checksum_change = line.len() >= 3 && line.chars().nth(2) == Some('5');

        if has_checksum_change {
            let file_path = line.split_whitespace().last().unwrap_or("unknown");

            if is_config {
                config_changes += 1;
            } else {
                modified_files.push(file_path.to_string());

                findings.push(
                    Finding::critical(
                        "package_integrity",
                        "System Package File Tampered",
                        &format!("File {} has been modified: {}", file_path, line),
                    )
                    .with_remediation(&format!(
                        "Investigate: rpm -qf {} && sudo yum reinstall $(rpm -qf {})",
                        file_path, file_path
                    )),
                );
            }
        }
    }

    info!(
        "  Package integrity: {} modified ({} configs, {} suspicious)",
        config_changes + modified_files.len(),
        config_changes,
        modified_files.len()
    );

    Some(findings)
}

/// Check pacman package integrity (Arch Linux)
async fn check_pacman_integrity() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("pacman").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    info!("  Running pacman -Qk (checking file integrity)...");

    let output = Command::new("pacman")
        .args(["-Qk"]) // Check all packages
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // pacman -Qk output:
    // warning: package_name: /path/to/file (Modification time mismatch)
    // warning: package_name: /path/to/file (Size mismatch)

    let warnings: Vec<&str> = stdout.lines().filter(|l| l.contains("warning:")).collect();

    if warnings.len() > 10 {
        findings.push(
            Finding::high(
                "package_integrity",
                "Multiple Package Integrity Issues",
                &format!("{} files have integrity warnings", warnings.len()),
            )
            .with_remediation("Review warnings: pacman -Qk | Reinstall affected packages"),
        );
    } else if !warnings.is_empty() {
        findings.push(
            Finding::medium(
                "package_integrity",
                "Package Integrity Warnings",
                &format!(
                    "{} files have integrity warnings (may be config files)",
                    warnings.len()
                ),
            )
            .with_remediation("Review warnings: pacman -Qk"),
        );
    }

    info!("  Found {} package integrity warnings", warnings.len());
    Some(findings)
}
