use crate::cve_db;
/// SQLite-backed CVE detection - checks installed packages against local CVE database
use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info, warn};

/// Check installed packages against SQLite CVE database
pub async fn check_cve_database() -> Result<Vec<Finding>> {
    info!("🔍 Checking installed packages against CVE database...");
    let start = std::time::Instant::now();

    // Check if database exists and is recent
    if let Ok(conn) = cve_db::init_database() {
        if cve_db::needs_update(&conn)? {
            warn!("CVE database is outdated (>7 days old). Run with --update-cve-db to refresh.");
            warn!("Falling back to built-in CVE knowledge base...");
            return Ok(Vec::new());
        }
    } else {
        warn!("CVE database not initialized. Run with --update-cve-db to create it.");
        return Ok(Vec::new());
    }

    // Get packages (using cache if available)
    let packages = if let Some(cached) = cve_db::package_cache::load_package_cache() {
        debug!("Using cached package list ({} packages)", cached.len());
        cached
    } else {
        info!("  Building package list (this may take 5-10 seconds on first run)...");
        let pkgs = get_all_installed_packages();
        // Save to cache for next time
        let _ = cve_db::package_cache::save_package_cache(&pkgs);
        pkgs
    };

    let query_start = std::time::Instant::now();
    info!(
        "  Querying {} packages against CVE database...",
        packages.len()
    );

    // Query database for matches
    let findings = cve_db::check_installed_packages(&packages)?;

    let query_time = query_start.elapsed();
    let total_time = start.elapsed();

    info!(
        "  Found {} CVE matches (query: {:.2}s, total: {:.2}s)",
        findings.len(),
        query_time.as_secs_f32(),
        total_time.as_secs_f32()
    );

    Ok(findings)
}

/// Get comprehensive list of installed packages for CVE checking
fn get_all_installed_packages() -> Vec<(String, String)> {
    let mut packages = Vec::new();

    // Add packages from package managers
    packages.extend(get_dpkg_packages());
    packages.extend(get_rpm_packages());

    // Add critical binaries
    packages.extend(get_binary_versions());

    // Remove duplicates
    packages.sort_by(|a, b| a.0.cmp(&b.0));
    packages.dedup_by(|a, b| a.0 == b.0);

    packages
}

/// Get dpkg packages
fn get_dpkg_packages() -> Vec<(String, String)> {
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Package}\t${Version}\n"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() == 2 {
                        Some((
                            normalize_package_name(parts[0]),
                            parse_version_string(parts[1]),
                        ))
                    } else {
                        None
                    }
                })
                .collect();
        }
    }

    Vec::new()
}

/// Get rpm packages
fn get_rpm_packages() -> Vec<(String, String)> {
    let output = Command::new("rpm")
        .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() == 2 {
                        Some((normalize_package_name(parts[0]), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect();
        }
    }

    Vec::new()
}

/// Get versions of critical binaries
fn get_binary_versions() -> Vec<(String, String)> {
    let mut packages = Vec::new();

    // Sudo
    if let Ok(ver) = get_sudo_version() {
        packages.push(("sudo".to_string(), ver));
    }

    // Kernel
    if let Ok(ver) = get_kernel_version() {
        packages.push(("linux-kernel".to_string(), ver.clone()));
        packages.push(("linux".to_string(), ver));
    }

    // OpenSSH
    if let Ok(ver) = get_openssh_version() {
        packages.push(("openssh".to_string(), ver));
    }

    // XZ Utils
    if let Ok(ver) = get_xz_version() {
        packages.push(("xz-utils".to_string(), ver.clone()));
        packages.push(("xz".to_string(), ver));
    }

    // glibc
    if let Ok(ver) = get_glibc_version() {
        packages.push(("glibc".to_string(), ver.clone()));
        packages.push(("libc".to_string(), ver));
    }

    // systemd
    if let Ok(ver) = get_systemd_version() {
        packages.push(("systemd".to_string(), ver));
    }

    // polkit
    if let Ok(ver) = get_polkit_version() {
        packages.push(("polkit".to_string(), ver.clone()));
        packages.push(("policykit".to_string(), ver));
    }

    packages
}

// Reuse version getters from cve_knowledge_base
fn get_sudo_version() -> Result<String> {
    let output = Command::new("sudo").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"Sudo version (\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse sudo version"))
}

fn get_kernel_version() -> Result<String> {
    let version = std::fs::read_to_string("/proc/version")?;
    let re = regex::Regex::new(r"Linux version (\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&version) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse kernel version"))
}

fn get_openssh_version() -> Result<String> {
    let output = Command::new("ssh").arg("-V").output()?;
    let text = String::from_utf8_lossy(&output.stderr);
    let re = regex::Regex::new(r"OpenSSH_(\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse OpenSSH version"))
}

fn get_xz_version() -> Result<String> {
    let output = Command::new("xz").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse xz version"))
}

fn get_glibc_version() -> Result<String> {
    let output = Command::new("ldd").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"(\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse glibc version"))
}

fn get_systemd_version() -> Result<String> {
    let output = Command::new("systemctl").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"systemd (\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse systemd version"))
}

fn get_polkit_version() -> Result<String> {
    let output = Command::new("pkexec").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"version (\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }
    Err(anyhow::anyhow!("Could not parse polkit version"))
}

/// Normalize package name for matching
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase()
        .trim()
        .replace("-dev", "")
        .replace("-common", "")
        .replace("lib32", "")
        .replace("lib64", "")
}

/// Parse version string (remove debian/ubuntu/rpm suffixes)
fn parse_version_string(version: &str) -> String {
    version
        .split(&['-', '+', '~'][..])
        .next()
        .unwrap_or(version)
        .trim()
        .to_string()
}
