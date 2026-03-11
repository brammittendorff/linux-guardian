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

/// Scan for world-writable files in critical directories.
/// Groups findings by application/directory to avoid spam (e.g. Tdarr with 50
/// world-writable files produces one finding, not 50).
async fn scan_world_writable_files() -> Result<Vec<Finding>> {
    use std::collections::HashMap;

    let mut findings = Vec::new();

    // Scan these critical directories (limited scope for performance)
    let scan_paths = ["/etc", "/usr/bin", "/usr/sbin", "/opt"];

    // Group world-writable files by their top-level application directory
    // e.g. /opt/Tdarr/Tdarr_Node/foo.js -> "/opt/Tdarr"
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut total_count = 0;

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

            if !path.is_file() {
                continue;
            }

            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.permissions().mode();

                if (mode & 0o002) != 0 {
                    let path_str = path.to_string_lossy().to_string();

                    // Skip /tmp (expected to be world-writable)
                    if path_str.contains("/tmp/") {
                        continue;
                    }

                    total_count += 1;

                    // Group by app directory: /opt/App/... -> /opt/App
                    // /etc/foo -> /etc, /usr/bin/foo -> /usr/bin
                    let group_key = get_app_group(&path_str, base_path);
                    groups.entry(group_key).or_default().push(path_str);
                }
            }
        }
    }

    // Emit one finding per group (or per file if ungrouped)
    for (group, files) in &groups {
        if files.len() == 1 {
            // Single file — report individually
            findings.push(
                Finding::medium(
                    "file_permissions",
                    "World-Writable File in Critical Directory",
                    &format!("File {} is writable by everyone", files[0]),
                )
                .with_remediation(&format!(
                    "Remove world-write: sudo chmod o-w '{}'",
                    files[0]
                )),
            );
        } else {
            // Multiple files in same app — group them
            let examples: Vec<&str> = files.iter().take(3).map(|s| s.as_str()).collect();
            let severity = if files.len() > 5 {
                // Many world-writable files in one app is worse
                Finding::high(
                    "file_permissions",
                    "Application Has Many World-Writable Files",
                    &format!(
                        "{} files under '{}' are writable by everyone. Examples: {}{}",
                        files.len(),
                        group,
                        examples.join(", "),
                        if files.len() > 3 { ", ..." } else { "" }
                    ),
                )
            } else {
                Finding::medium(
                    "file_permissions",
                    "World-Writable Files in Application Directory",
                    &format!(
                        "{} files under '{}' are writable by everyone: {}",
                        files.len(),
                        group,
                        examples.join(", ")
                    ),
                )
            };
            findings.push(
                severity
                    .with_remediation(&format!("Fix permissions: sudo chmod -R o-w '{}'", group)),
            );
        }
    }

    debug!(
        "Found {} world-writable files in {} groups",
        total_count,
        groups.len()
    );
    Ok(findings)
}

/// Get the application group directory for grouping world-writable findings.
/// e.g. /opt/Tdarr/Tdarr_Node/foo.js -> /opt/Tdarr
///      /etc/some.conf -> /etc
fn get_app_group(path: &str, base_path: &str) -> String {
    // For /opt, group by /opt/<app_name>
    if base_path == "/opt" {
        let parts: Vec<&str> = path.splitn(4, '/').collect();
        if parts.len() >= 3 {
            return format!("/{}/{}", parts[1], parts[2]);
        }
    }
    // For everything else, group by the base scan path
    base_path.to_string()
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
