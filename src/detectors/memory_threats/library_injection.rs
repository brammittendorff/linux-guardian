use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::fs;
use tracing::{debug, info};

/// Detect LD_PRELOAD injection attacks
/// Works without root for own-user processes, needs root for others
pub async fn detect_ld_preload_injection() -> Result<Vec<Finding>> {
    info!("🔍 Checking for LD_PRELOAD injection...");
    let mut findings = Vec::new();

    // Check system-wide LD_PRELOAD files
    check_system_preload(&mut findings);

    // Check per-process LD_PRELOAD
    let processes = match all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            debug!("Could not enumerate processes: {}", e);
            return Ok(findings);
        }
    };

    for process_result in processes {
        let process = match process_result {
            Ok(p) => p,
            Err(_) => continue,
        };

        let pid = process.pid;
        let comm = process
            .stat()
            .ok()
            .map(|s| s.comm.clone())
            .unwrap_or_default();

        // Read environment variables
        let environ_path = format!("/proc/{}/environ", pid);
        let environ = match fs::read_to_string(&environ_path) {
            Ok(e) => e,
            Err(_) => continue, // Can't read (different user or permission denied)
        };

        // environ is null-byte separated
        for var in environ.split('\0') {
            if let Some(value) = var.strip_prefix("LD_PRELOAD=") {
                if value.is_empty() {
                    continue;
                }

                let is_suspicious = is_suspicious_preload(value);

                if is_suspicious {
                    findings.push(
                        Finding::critical(
                            "library_injection",
                            "Suspicious LD_PRELOAD Injection Detected",
                            &format!(
                                "Process '{}' (PID: {}) has suspicious LD_PRELOAD: {}. \
                                 This is commonly used for credential theft, rootkits, and code injection.",
                                comm, pid, value
                            ),
                        )
                        .with_remediation(&format!(
                            "Investigate: cat /proc/{}/environ | tr '\\0' '\\n' | grep LD_PRELOAD && \
                             sudo kill -9 {}",
                            pid, pid
                        ))
                        .with_details(serde_json::json!({
                            "pid": pid,
                            "comm": comm,
                            "ld_preload": value,
                            "technique": "LD_PRELOAD",
                            "mitre_attack": "T1574.006"
                        })),
                    );
                } else {
                    debug!(
                        "Process {} (PID: {}) has LD_PRELOAD: {} (appears legitimate)",
                        comm, pid, value
                    );
                }
            }

            // Also check LD_LIBRARY_PATH for hijacking
            if let Some(value) = var.strip_prefix("LD_LIBRARY_PATH=") {
                if value.contains("/tmp")
                    || value.contains("/dev/shm")
                    || value.contains("/var/tmp")
                {
                    findings.push(
                        Finding::high(
                            "library_injection",
                            "Suspicious LD_LIBRARY_PATH",
                            &format!(
                                "Process '{}' (PID: {}) has suspicious LD_LIBRARY_PATH: {}. \
                                 May be loading malicious libraries from temporary directories.",
                                comm, pid, value
                            ),
                        )
                        .with_remediation("Investigate why library path includes temp directories"),
                    );
                }
            }
        }

        // Check /proc/PID/maps for injected shared libraries
        check_injected_libraries(pid, &comm, &mut findings);
    }

    if findings.is_empty() {
        debug!("No LD_PRELOAD injection detected");
    }

    Ok(findings)
}

/// Check system-wide preload configuration files
fn check_system_preload(findings: &mut Vec<Finding>) {
    if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if is_suspicious_preload(line) {
                findings.push(
                    Finding::critical(
                        "library_injection",
                        "Suspicious System-Wide LD_PRELOAD",
                        &format!(
                            "/etc/ld.so.preload contains suspicious library: {}. \
                             This affects ALL processes on the system.",
                            line
                        ),
                    )
                    .with_remediation(
                        "Review: cat /etc/ld.so.preload - remove unknown entries immediately",
                    ),
                );
            }
        }
    }
}

/// Check if a preloaded library path is suspicious
fn is_suspicious_preload(path: &str) -> bool {
    let suspicious_locations = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/root/"];
    let legitimate_preloads = [
        "libfakeroot",
        "libjemalloc",
        "libtcmalloc",
        "libasan",
        "libSegFault",
        "libgtk3-nocsd",
        "libsandbox",
        "libtsocks",
        "libproxychains",
        "libnss_",
        "libeatmydata",
    ];

    for loc in &suspicious_locations {
        if path.contains(loc) {
            return true;
        }
    }

    for legit in &legitimate_preloads {
        if path.contains(legit) {
            return false;
        }
    }

    !path.starts_with("/usr/lib") && !path.starts_with("/lib")
}

/// Check /proc/PID/maps for injected shared libraries from suspicious locations
fn check_injected_libraries(pid: i32, comm: &str, findings: &mut Vec<Finding>) {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = match fs::read_to_string(&maps_path) {
        Ok(m) => m,
        Err(_) => return,
    };

    let suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let path = parts[5..].join(" ");

        // Check for shared libraries loaded from suspicious locations
        if path.ends_with(".so") || path.contains(".so.") {
            for sus in &suspicious_paths {
                if path.starts_with(sus) {
                    findings.push(
                        Finding::critical(
                            "library_injection",
                            "Injected Shared Library from Suspicious Location",
                            &format!(
                                "Process '{}' (PID: {}) has loaded library from suspicious path: {}",
                                comm, pid, path
                            ),
                        )
                        .with_remediation(&format!(
                            "Investigate: ls -la '{}' && cat /proc/{}/maps | grep '{}'",
                            path, pid, sus
                        )),
                    );
                    break;
                }
            }
        }

        // Check for deleted shared libraries (injected then removed)
        if (path.ends_with(".so (deleted)") || path.contains(".so.") && path.contains("(deleted)"))
            && !path.contains("/usr/")
            && !path.contains("/lib/")
        {
            findings.push(
                Finding::high(
                    "library_injection",
                    "Deleted Shared Library Still Loaded",
                    &format!(
                        "Process '{}' (PID: {}) has a deleted library still mapped: {}",
                        comm, pid, path
                    ),
                )
                .with_remediation(&format!(
                    "Investigate process: sudo kill -9 {} if suspicious",
                    pid
                )),
            );
        }
    }
}
