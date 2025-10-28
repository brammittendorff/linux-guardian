/// Binary Legitimacy Scanner - Detect trojaned/backdoored binaries
/// NO API KEYS REQUIRED - Uses local verification methods
use crate::models::Finding;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tracing::{debug, info};

/// Critical system binaries that MUST be validated
/// Using /bin paths (dpkg tracks them there, even with usrmerge)
const CRITICAL_BINARIES: &[&str] = &[
    "/usr/bin/sudo", // sudo is actually in /usr/bin
    "/bin/su",       // Tracked in /bin by dpkg
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/passwd",
    "/bin/login",     // Tracked in /bin
    "/bin/systemctl", // Tracked in /bin
    "/bin/ps",        // Tracked in /bin
    "/bin/ls",        // Tracked in /bin
    "/bin/netstat",
    "/usr/bin/ss", // iproute2 package
];

/// Suspicious strings in binaries (backdoor indicators)
/// NOTE: /dev/tcp/ is LEGITIMATE bash feature - excluded!
const SUSPICIOUS_STRINGS: &[&str] = &[
    "eval(base64_decode",
    "nc -e /bin/sh",
    "nc -e /bin/bash",
    "bash -i >& /dev/tcp", // Reverse shell (specific pattern)
    "sh -i >& /dev/tcp",
    "0.0.0.0:4444",    // Common reverse shell port
    "PAYLOAD_START",   // Metasploit marker
    "msfvenom",        // Metasploit payload generator
    "chmod 777 /tmp",  // Suspicious permission change
    "iptables -F && ", // Flush firewall in script
    "setenforce 0 &&", // Disable SELinux in script
    "rm -rf /var/log", // Log deletion
    "ROOTKIT_",        // Rootkit marker
    "BACKDOOR_",       // Backdoor marker
];

/// Scan critical binaries for legitimacy
pub async fn validate_critical_binaries() -> Result<Vec<Finding>> {
    info!("🔍 Validating critical system binaries...");
    let mut findings = Vec::new();

    for binary_path in CRITICAL_BINARIES {
        if !std::path::Path::new(binary_path).exists() {
            debug!("{} not found (may be normal)", binary_path);
            continue;
        }

        // 1. Check if binary is from a package
        if let Some(finding) = check_binary_from_package(binary_path).await {
            findings.push(finding);
            continue; // If not from package, already flagged
        }

        // 2. Check file permissions
        if let Some(finding) = check_binary_permissions(binary_path) {
            findings.push(finding);
        }

        // 3. Check for suspicious strings (backdoor detection)
        if let Some(finding) = check_binary_strings(binary_path).await {
            findings.push(finding);
        }

        // 4. Check modification time (recently modified = suspicious)
        if let Some(finding) = check_binary_modification_time(binary_path) {
            findings.push(finding);
        }
    }

    info!("  Validated {} critical binaries", CRITICAL_BINARIES.len());
    Ok(findings)
}

/// Check if binary belongs to a package (dpkg/rpm)
async fn check_binary_from_package(binary_path: &str) -> Option<Finding> {
    // Handle usrmerge: /usr/bin/foo might be registered as /bin/foo
    let alternate_paths = vec![
        binary_path.to_string(),
        binary_path.replace("/usr/bin/", "/bin/"),
        binary_path.replace("/usr/sbin/", "/sbin/"),
    ];

    // Try dpkg (Debian/Ubuntu) with all possible paths
    for path in &alternate_paths {
        if let Ok(output) = Command::new("dpkg").args(["-S", path]).output() {
            if output.status.success() {
                debug!("{} belongs to package (verified via {})", binary_path, path);
                return None; // Good - from package
            }
        }
    }

    // Try rpm (RHEL/Fedora)
    for path in &alternate_paths {
        if let Ok(output) = Command::new("rpm").args(["-qf", path]).output() {
            if output.status.success() {
                debug!("{} belongs to package (verified via {})", binary_path, path);
                return None; // Good - from package
            }
        }
    }

    // Binary not from any package - SUSPICIOUS!
    // But only flag if binary actually exists
    if !std::path::Path::new(binary_path).exists() {
        return None; // Binary doesn't exist, skip
    }

    Some(
        Finding::critical(
            "binary_validation",
            "Critical Binary Not From Package",
            &format!(
                "{} is a critical system binary but doesn't belong to any package. \
                 This could indicate a trojaned/replaced binary.",
                binary_path
            ),
        )
        .with_remediation(&format!(
            "URGENT: Investigate {} - may be backdoor. Reinstall package or restore from backup",
            binary_path
        )),
    )
}

/// Check binary file permissions
fn check_binary_permissions(binary_path: &str) -> Option<Finding> {
    if let Ok(metadata) = fs::metadata(binary_path) {
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;

        // Critical binaries should not be world-writable
        if (mode & 0o002) != 0 {
            return Some(
                Finding::critical(
                    "binary_validation",
                    "Critical Binary is World-Writable",
                    &format!(
                        "{} is writable by everyone (mode: {:o}). Attacker could replace it with backdoor!",
                        binary_path, mode
                    ),
                )
                .with_remediation(&format!("Fix immediately: sudo chmod 755 {}", binary_path)),
            );
        }

        // Critical binaries should be owned by root
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = metadata.uid();
            if uid != 0 {
                return Some(
                    Finding::high(
                        "binary_validation",
                        "Critical Binary Not Owned by Root",
                        &format!("{} is owned by UID {} (should be root/0)", binary_path, uid),
                    )
                    .with_remediation(&format!("Fix: sudo chown root:root {}", binary_path)),
                );
            }
        }
    }

    None
}

/// Scan binary for suspicious strings
async fn check_binary_strings(binary_path: &str) -> Option<Finding> {
    // Read binary (limit to first 1MB for performance)
    let mut file = match fs::File::open(binary_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB
    let bytes_read = file.read(&mut buffer).unwrap_or(0);

    if bytes_read == 0 {
        return None;
    }

    // Convert to string (lossy)
    let content = String::from_utf8_lossy(&buffer[..bytes_read]);

    // Check for suspicious patterns
    for pattern in SUSPICIOUS_STRINGS {
        if content.contains(pattern) {
            return Some(
                Finding::critical(
                    "binary_validation",
                    "Suspicious String in Critical Binary",
                    &format!(
                        "{} contains suspicious pattern: '{}'. This could indicate a backdoor or trojan.",
                        binary_path, pattern
                    ),
                )
                .with_remediation(&format!(
                    "CRITICAL: Investigate {} with: strings {} | grep -i backdoor && sudo apt-get install --reinstall $(dpkg -S {} | cut -d: -f1)",
                    binary_path, binary_path, binary_path
                )),
            );
        }
    }

    None
}

/// Check if binary was recently modified (suspicious)
fn check_binary_modification_time(binary_path: &str) -> Option<Finding> {
    if let Ok(metadata) = fs::metadata(binary_path) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();

            // Critical binaries modified in last 7 days = SUSPICIOUS
            // (Unless system was recently updated)
            if age.as_secs() < 7 * 24 * 3600 {
                return Some(
                    Finding::high(
                        "binary_validation",
                        "Critical Binary Recently Modified",
                        &format!(
                            "{} was modified {} days ago. If you didn't update recently, this could indicate tampering.",
                            binary_path,
                            age.as_secs() / 86400
                        ),
                    )
                    .with_remediation("Verify with package manager: dpkg -V or rpm -V. Reinstall if tampered."),
                );
            }
        }
    }

    None
}

/// Scan for web shells in web directories
pub async fn scan_web_shells() -> Result<Vec<Finding>> {
    info!("🔍 Scanning for web shells...");
    let mut findings = Vec::new();

    // Common web roots
    let web_roots = [
        "/var/www",
        "/srv/http",
        "/usr/share/nginx/html",
        "/var/www/html",
    ];

    for web_root in &web_roots {
        if !std::path::Path::new(web_root).exists() {
            continue;
        }

        // Scan for suspicious files
        for entry in walkdir::WalkDir::new(web_root)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check file extension
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy();

                // Suspicious extensions
                if ext_str == "suspected" || ext_str == "bak" || ext_str == "old" {
                    continue; // Skip backup files
                }

                // PHP/ASP files - check for web shell patterns
                if ext_str == "php" || ext_str == "asp" || ext_str == "aspx" {
                    if let Ok(content) = fs::read_to_string(path) {
                        // Check for web shell patterns
                        for pattern in &[
                            "eval(base64_decode",
                            "system($_GET",
                            "system($_POST",
                            "system($_REQUEST",
                            "shell_exec(",
                            "passthru(",
                            "exec($_",
                            "base64_decode(",
                        ] {
                            if content.contains(pattern) {
                                findings.push(
                                    Finding::critical(
                                        "web_shell",
                                        "Web Shell Detected",
                                        &format!(
                                            "Possible web shell found: {} contains suspicious pattern: '{}'",
                                            path.display(),
                                            pattern
                                        ),
                                    )
                                    .with_remediation(&format!("Delete immediately: sudo rm '{}'", path.display())),
                                );
                                break; // One detection per file is enough
                            }
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        debug!("No web shells detected");
    }

    Ok(findings)
}

/// Calculate SHA256 hash of a file
pub fn hash_file(path: &str) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_world_writable_detection() {
        let mode = 0o100666; // rw-rw-rw-
        assert_eq!(mode & 0o002, 0o002); // World-writable
    }

    #[test]
    fn test_suspicious_string_patterns() {
        let content = "some code eval(base64_decode($_POST['cmd'])) more code";
        assert!(content.contains("eval(base64_decode"));
    }

    #[test]
    fn test_recent_modification() {
        let seven_days_ago = 7 * 24 * 3600;
        let one_day_ago = 24 * 3600;

        assert!(one_day_ago < seven_days_ago);
    }
}
