use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tracing::{debug, info};
use walkdir::WalkDir;

/// Critical system files that must have specific permissions
const CRITICAL_FILES: &[(&str, u32)] = &[
    // (file_path, expected_mode)
    ("/etc/passwd", 0o644),
    ("/etc/shadow", 0o640),
    ("/etc/gshadow", 0o640),
    ("/etc/group", 0o644),
    ("/etc/sudoers", 0o440),
    ("/root/.ssh", 0o700),
    ("/etc/ssh/sshd_config", 0o600),
];

/// Check file permissions and scan for world-writable files
pub async fn check_file_permissions() -> Result<Vec<Finding>> {
    info!("🔍 Checking critical file permissions...");
    let mut findings = Vec::new();

    // Check critical system files
    findings.extend(check_critical_file_permissions().await?);

    // Scan for world-writable files (limited scope for performance)
    findings.extend(scan_world_writable_files().await?);

    info!("  Checked file permissions");
    Ok(findings)
}

/// Check permissions on critical system files
async fn check_critical_file_permissions() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for (file_path, expected_mode) in CRITICAL_FILES {
        if !std::path::Path::new(file_path).exists() {
            debug!("File {} does not exist (may be normal)", file_path);
            continue;
        }

        if let Ok(metadata) = fs::metadata(file_path) {
            let permissions = metadata.permissions();
            let actual_mode = permissions.mode() & 0o777;

            if actual_mode != *expected_mode {
                // Determine severity based on file
                let severity = if file_path.contains("shadow") || file_path.contains("sudoers") {
                    "high"
                } else {
                    "medium"
                };

                let finding = match severity {
                    "high" => Finding::high(
                        "file_permissions",
                        &format!("Critical File Has Wrong Permissions: {}", file_path),
                        &format!(
                            "{} has permissions {:o}, should be {:o}. Unauthorized access possible.",
                            file_path, actual_mode, expected_mode
                        ),
                    ),
                    _ => Finding::medium(
                        "file_permissions",
                        &format!("File Permissions Not Optimal: {}", file_path),
                        &format!(
                            "{} has permissions {:o}, recommended {:o}",
                            file_path, actual_mode, expected_mode
                        ),
                    ),
                };

                findings.push(finding.with_remediation(&format!(
                    "Fix permissions: sudo chmod {:o} {}",
                    expected_mode, file_path
                )));
            } else {
                debug!("{} has correct permissions: {:o}", file_path, actual_mode);
            }
        }
    }

    Ok(findings)
}

/// Scan for world-writable files in critical directories
async fn scan_world_writable_files() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Scan these critical directories (limited scope for performance)
    let scan_paths = ["/etc", "/usr/bin", "/usr/sbin", "/opt"];

    let mut world_writable_count = 0;

    for base_path in &scan_paths {
        if !std::path::Path::new(base_path).exists() {
            continue;
        }

        for entry in WalkDir::new(base_path)
            .max_depth(4) // Limit depth for performance
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip if not a file
            if !path.is_file() {
                continue;
            }

            // Check permissions
            if let Ok(metadata) = fs::metadata(path) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();

                // Check if world-writable (002 bit set)
                if (mode & 0o002) != 0 {
                    let path_str = path.to_string_lossy();

                    // Skip /tmp and /var/tmp (expected to have world-writable files)
                    if path_str.contains("/tmp") {
                        continue;
                    }

                    world_writable_count += 1;

                    if world_writable_count <= 10 {
                        // Only report first 10 to avoid spam
                        findings.push(
                            Finding::medium(
                                "file_permissions",
                                "World-Writable File in Critical Directory",
                                &format!(
                                    "File {} is writable by everyone (permissions: {:o})",
                                    path_str,
                                    mode & 0o777
                                ),
                            )
                            .with_remediation(&format!(
                                "Remove world-write: sudo chmod o-w '{}'",
                                path_str
                            )),
                        );
                    }
                }
            }
        }
    }

    if world_writable_count > 10 {
        findings.push(
            Finding::high(
                "file_permissions",
                "Many World-Writable Files Detected",
                &format!(
                    "Found {} world-writable files in critical directories. This allows any user to modify system files.",
                    world_writable_count
                ),
            )
            .with_remediation("Review and fix: sudo find /etc /usr -type f -perm -002 -ls"),
        );
    }

    debug!("Found {} world-writable files", world_writable_count);
    Ok(findings)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_world_writable_detection() {
        let mode_666 = 0o100666; // rw-rw-rw- (world-writable)
        let mode_644 = 0o100644; // rw-r--r--
        let mode_755 = 0o100755; // rwxr-xr-x

        assert_eq!(mode_666 & 0o002, 0o002); // World-writable
        assert_eq!(mode_644 & 0o002, 0); // Not world-writable
        assert_eq!(mode_755 & 0o002, 0); // Not world-writable
    }

    #[test]
    fn test_critical_files_list() {
        assert!(CRITICAL_FILES.len() >= 6);

        for (path, mode) in CRITICAL_FILES {
            assert!(path.starts_with('/'));
            assert!(*mode <= 0o777);
        }
    }

    #[test]
    fn test_permission_mode_extraction() {
        let full_mode = 0o100644; // Regular file, rw-r--r--
        let perm_only = full_mode & 0o777;
        assert_eq!(perm_only, 0o644);
    }
}
