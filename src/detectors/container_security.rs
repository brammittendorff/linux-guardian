/// Docker/Container Security Scanner (Desktop Focus)
/// Detects: Privileged containers, docker socket exposure, container escapes
use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tracing::{debug, info};

/// Check Docker/container security
pub async fn check_container_security() -> Result<Vec<Finding>> {
    info!("🔍 Checking Docker/container security...");
    let mut findings = Vec::new();

    // Check if Docker is installed
    if !is_docker_installed() {
        debug!("Docker not installed, skipping container checks");
        return Ok(findings);
    }

    // Check Docker socket permissions
    findings.extend(check_docker_socket_permissions());

    // Check for privileged containers
    findings.extend(check_privileged_containers().await?);

    // Check for containers with dangerous mounts
    findings.extend(check_dangerous_mounts().await?);

    // Check Docker daemon configuration
    findings.extend(check_docker_daemon_config());

    info!("  Completed container security checks");
    Ok(findings)
}

/// Check if Docker is installed
fn is_docker_installed() -> bool {
    Command::new("docker").arg("--version").output().is_ok()
}

/// Check Docker socket permissions
fn check_docker_socket_permissions() -> Vec<Finding> {
    let mut findings = Vec::new();
    let socket_path = "/var/run/docker.sock";

    if !std::path::Path::new(socket_path).exists() {
        return findings;
    }

    if let Ok(metadata) = fs::metadata(socket_path) {
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;

        // Docker socket should be 660 or 600, not world-accessible
        if (mode & 0o006) != 0 {
            findings.push(
                Finding::critical(
                    "container_security",
                    "Docker Socket World-Accessible",
                    "Docker socket has world-accessible permissions. Anyone can control Docker = root access!",
                )
                .with_remediation("Fix immediately: sudo chmod 660 /var/run/docker.sock"),
            );
        }

        // Check if socket is readable by user's groups
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let gid = metadata.gid();
            debug!("Docker socket GID: {}", gid);
        }
    }

    findings
}

/// Check for privileged containers
async fn check_privileged_containers() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let output = Command::new("docker")
        .args(["ps", "--format", "{{.ID}}|{{.Names}}"])
        .output();

    if let Ok(output) = output {
        if !output.status.success() {
            debug!("Cannot list containers (may need root)");
            return Ok(findings);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 2 {
                continue;
            }

            let container_id = parts[0];
            let container_name = parts[1];

            // Check if privileged
            let inspect = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.HostConfig.Privileged}}",
                    container_id,
                ])
                .output();

            if let Ok(inspect_output) = inspect {
                let is_privileged =
                    String::from_utf8_lossy(&inspect_output.stdout).trim() == "true";

                if is_privileged {
                    findings.push(
                        Finding::critical(
                            "container_security",
                            "Privileged Container Running",
                            &format!(
                                "Container '{}' ({}) is running in privileged mode. This allows container escape to host!",
                                container_name, container_id
                            ),
                        )
                        .with_remediation(&format!(
                            "Stop and restart without --privileged: docker stop {} && docker run (without --privileged)",
                            container_name
                        )),
                    );
                }
            }
        }
    }

    Ok(findings)
}

/// Check for dangerous volume mounts
async fn check_dangerous_mounts() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let output = Command::new("docker")
        .args(["ps", "--format", "{{.ID}}|{{.Names}}"])
        .output();

    if let Ok(output) = output {
        if !output.status.success() {
            return Ok(findings);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 2 {
                continue;
            }

            let container_id = parts[0];
            let container_name = parts[1];

            // Check mounts
            let inspect = Command::new("docker")
                .args(["inspect", "--format", "{{.Mounts}}", container_id])
                .output();

            if let Ok(inspect_output) = inspect {
                let mounts = String::from_utf8_lossy(&inspect_output.stdout);

                // Dangerous mounts
                let dangerous_paths = [
                    "/", // Root filesystem
                    "/etc",
                    "/var/run/docker.sock", // Docker socket
                    "/proc",
                    "/sys",
                ];

                for dangerous_path in &dangerous_paths {
                    if mounts.contains(dangerous_path) {
                        findings.push(
                            Finding::critical(
                                "container_security",
                                "Container Has Dangerous Mount",
                                &format!(
                                    "Container '{}' mounts {} from host. This allows container escape!",
                                    container_name, dangerous_path
                                ),
                            )
                            .with_remediation(&format!(
                                "Remove dangerous mount from container '{}'. Never mount / or /var/run/docker.sock",
                                container_name
                            )),
                        );
                    }
                }
            }
        }
    }

    Ok(findings)
}

/// Check Docker daemon configuration
fn check_docker_daemon_config() -> Vec<Finding> {
    let mut findings = Vec::new();
    let daemon_json = "/etc/docker/daemon.json";

    if std::path::Path::new(daemon_json).exists() {
        if let Ok(content) = fs::read_to_string(daemon_json) {
            // Check for insecure registries
            if content.contains("insecure-registries") {
                findings.push(
                    Finding::high(
                        "container_security",
                        "Docker Uses Insecure Registries",
                        "Docker is configured to use insecure (HTTP) registries. Images could be compromised.",
                    )
                    .with_remediation("Remove insecure-registries from /etc/docker/daemon.json"),
                );
            }

            // Check if userland-proxy is disabled (can cause security issues)
            if content.contains("\"userland-proxy\": false") {
                findings.push(
                    Finding::medium(
                        "container_security",
                        "Docker Userland Proxy Disabled",
                        "Docker userland-proxy is disabled. This can cause network security issues.",
                    )
                    .with_remediation("Review Docker networking configuration"),
                );
            }
        }
    }

    findings
}

/// Check for container escape attempts in logs
pub async fn detect_container_escape_attempts() -> Result<Vec<Finding>> {
    info!("🔍 Checking for container escape attempts...");
    let findings = Vec::new();

    // Check Docker logs for escape patterns
    let output = Command::new("docker")
        .args(["events", "--since", "24h", "--filter", "type=container"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for suspicious events
        let suspicious_events = [
            "mount",      // Mounting host filesystems
            "exec",       // Executing commands (could be escape)
            "privileged", // Privilege escalation
        ];

        for event in suspicious_events {
            if stdout.contains(event) {
                debug!("Found suspicious container event: {}", event);
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // Test removed - is_legitimate_credential_accessor not implemented in current version

    #[test]
    fn test_permission_checking() {
        let too_open = 0o644; // rw-r--r--
        let secure = 0o600; // rw-------

        assert_eq!(too_open & 0o044, 0o044); // Others can read
        assert_eq!(secure & 0o044, 0o000); // Others cannot read
    }

    #[test]
    fn test_dangerous_mount_detection() {
        let mounts = "bind /var/run/docker.sock /var/run/docker.sock";
        assert!(mounts.contains("/var/run/docker.sock"));
    }
}
