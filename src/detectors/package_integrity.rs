use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};
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

/// Get cache path for package integrity results
fn get_integrity_cache_path() -> PathBuf {
    let mut path = if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache/linux-guardian")
    } else {
        PathBuf::from("/tmp/linux-guardian")
    };
    let _ = fs::create_dir_all(&path);
    path.push("package_integrity.cache");
    path
}

/// Check if package database has changed (indicates new installs/updates)
fn package_db_modified() -> Option<SystemTime> {
    // Check dpkg status file modification time
    fs::metadata("/var/lib/dpkg/status")
        .ok()
        .and_then(|m| m.modified().ok())
}

/// Check dpkg package integrity (Debian/Ubuntu)
async fn check_dpkg_integrity() -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let check = Command::new("dpkg").arg("--version").output().ok()?;
    if !check.status.success() {
        return None;
    }

    let cache_path = get_integrity_cache_path();
    let current_db_time = package_db_modified()?;

    // Check if we have a recent cache
    if let Ok(cache_metadata) = fs::metadata(&cache_path) {
        if let Ok(cache_time) = cache_metadata.modified() {
            let cache_age = SystemTime::now().duration_since(cache_time).ok()?;

            // Use cache if:
            // 1. Cache is less than 24 hours old AND
            // 2. Package database hasn't been modified since cache was created
            if cache_age < Duration::from_secs(24 * 3600) {
                if let Ok(cache_db_time) = fs::read_to_string(&cache_path) {
                    if let Some(line) = cache_db_time.lines().next() {
                        // First line contains the package DB timestamp
                        if line.starts_with("DB_TIME:") {
                            let cached_db_timestamp = line.strip_prefix("DB_TIME:")?.trim();
                            let current_db_timestamp = format!("{:?}", current_db_time);

                            if cached_db_timestamp == current_db_timestamp {
                                info!(
                                    "  Using cached integrity check (no package changes detected)"
                                );
                                debug!(
                                    "Cache age: {:.1}h, package DB unchanged",
                                    cache_age.as_secs_f32() / 3600.0
                                );

                                // Parse cached findings
                                for line in cache_db_time.lines().skip(1) {
                                    if !line.is_empty() {
                                        findings.push(
                                            Finding::high(
                                                "package_integrity",
                                                "Modified Package File Detected",
                                                &format!("Package file has been modified: {}", line),
                                            )
                                            .with_remediation("Investigate: This could indicate tampering or corruption. Reinstall affected package or run debsums for details."),
                                        );
                                    }
                                }
                                return Some(findings);
                            }
                        }
                    }
                }
            }
        }
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

    // Write cache with package DB timestamp and modified files
    let cache_content = format!(
        "DB_TIME: {:?}\n{}",
        current_db_time,
        modified_files.join("\n")
    );
    let _ = fs::write(&cache_path, cache_content);
    debug!("Cached integrity results to {:?}", cache_path);

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
