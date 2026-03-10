use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::fs;
use tracing::{debug, info};

/// Detect fileless malware using memfd_create
/// Works without root - checks /proc/PID/exe for memfd: paths
pub async fn detect_fileless_malware() -> Result<Vec<Finding>> {
    info!("🔍 Checking for fileless malware (memfd_create)...");
    let mut findings = Vec::new();

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

        // Check /proc/PID/exe symlink
        let exe_link = format!("/proc/{}/exe", pid);
        let exe_path = match fs::read_link(&exe_link) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        // memfd_create fileless execution: exe points to /memfd:*
        if exe_path.contains("memfd:") {
            findings.push(
                Finding::critical(
                    "fileless_malware",
                    "Fileless Malware Detected (memfd_create)",
                    &format!(
                        "Process '{}' (PID: {}) is executing from memory ({}). \
                         This is a strong indicator of fileless malware using memfd_create.",
                        comm, pid, exe_path
                    ),
                )
                .with_remediation(&format!(
                    "Kill immediately: sudo kill -9 {} && investigate: ls -la /proc/{}/fd",
                    pid, pid
                ))
                .with_details(serde_json::json!({
                    "pid": pid,
                    "comm": comm,
                    "exe_path": exe_path,
                    "technique": "memfd_create",
                    "mitre_attack": "T1620"
                })),
            );
            continue;
        }

        // /dev/shm execution: malware written to shared memory, executed, deleted
        if exe_path.contains("/dev/shm/") {
            let severity = if exe_path.contains("(deleted)") {
                "deleted from /dev/shm - likely covering tracks"
            } else {
                "running from /dev/shm"
            };
            findings.push(
                Finding::critical(
                    "fileless_malware",
                    "Suspicious Execution from Shared Memory",
                    &format!(
                        "Process '{}' (PID: {}) is {} ({}). \
                         /dev/shm is commonly used for fileless malware execution.",
                        comm, pid, severity, exe_path
                    ),
                )
                .with_remediation(&format!(
                    "Kill: sudo kill -9 {} && check: ls -la /dev/shm/",
                    pid
                )),
            );
        }
    }

    if findings.is_empty() {
        debug!("No fileless malware detected");
    }

    Ok(findings)
}
