use crate::models::Finding;
use anyhow::Result;
use procfs::process::{all_processes, Process};
use std::collections::HashSet;
use std::fs;
use tracing::{debug, info};

/// Suspicious process locations
const SUSPICIOUS_LOCATIONS: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/.config/", // Hidden in config directories
];

/// Known malware process names
const KNOWN_MALWARE: &[&str] = &[
    "kinsing",
    "kdevtmpfsi",
    "perfctl",
    "cshell",
    "kaiji",
    "ddostf",
    "tsunami",
    "billgates",
    "mr.black",
    "xorddos",
];

/// Detect suspicious processes
pub async fn detect_suspicious_processes() -> Result<Vec<Finding>> {
    info!("🔍 Detecting suspicious processes...");
    let mut findings = Vec::new();

    // Get all processes
    let processes = match all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            debug!("Failed to read processes: {}", e);
            return Ok(findings);
        }
    };

    // Get list of PIDs from /proc
    let mut proc_pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if let Ok(pid) = file_name.parse::<i32>() {
                    proc_pids.insert(pid);
                }
            }
        }
    }

    // Analyze each process
    for process in processes.flatten() {
        let pid = process.pid;

        if let Ok(stat) = process.stat() {
            let comm = stat.comm.clone();
            let comm_lower = comm.to_lowercase();

            // Check for known malware names
            for malware in KNOWN_MALWARE {
                if comm_lower.contains(malware) {
                    findings.push(
                        Finding::critical(
                            "malware",
                            "Known Malware Process Detected",
                            &format!("Detected known malware process: '{}' (PID: {})", comm, pid),
                        )
                        .with_remediation(&format!(
                            "Kill immediately: sudo kill -9 {} && investigate source",
                            pid
                        )),
                    );
                }
            }

            // Get executable path
            if let Ok(exe) = process.exe() {
                let exe_path = exe.to_string_lossy().to_string();

                // Check for processes running from suspicious locations
                for sus_loc in SUSPICIOUS_LOCATIONS {
                    if exe_path.starts_with(sus_loc) {
                        findings.push(
                            Finding::high(
                                "suspicious_process",
                                "Process Running from Suspicious Location",
                                &format!(
                                    "Process '{}' (PID: {}) running from: {}",
                                    comm, pid, exe_path
                                ),
                            )
                            .with_remediation(&format!(
                                "Investigate: sudo ls -la '{}' && sudo kill -9 {}",
                                exe_path, pid
                            )),
                        );
                    }
                }

                // Check for processes with deleted binaries
                // BUT exclude browsers and other legitimate software that does this during updates
                if exe_path.contains("(deleted)") {
                    let is_whitelisted = comm.contains("chrome")
                            || comm.contains("firefox")
                            || comm.contains("chromium")
                            || comm.contains("brave")
                            || comm.contains("code")  // VS Code
                            || comm.contains("electron")
                            || comm.contains("Discord")
                            || comm.contains("Slack");

                    if !is_whitelisted {
                        findings.push(
                                Finding::high(
                                    "suspicious_process",
                                    "Process with Deleted Binary",
                                    &format!(
                                        "Process '{}' (PID: {}) binary has been deleted - often indicates malware",
                                        comm, pid
                                    ),
                                )
                                .with_remediation(&format!("Kill and investigate: sudo kill -9 {}", pid)),
                            );
                    }
                }

                // Check for hidden processes (starts with dot)
                if comm.starts_with('.') {
                    findings.push(
                        Finding::medium(
                            "suspicious_process",
                            "Hidden Process Name Detected",
                            &format!(
                                "Process with hidden name: '{}' (PID: {}) at {}",
                                comm, pid, exe_path
                            ),
                        )
                        .with_remediation("Investigate why process name starts with dot"),
                    );
                }
            }

            // Check for processes with unusual parent-child relationships
            // Only flag if it's ALSO in a suspicious location (reduce false positives)
            let ppid = stat.ppid;
            if ppid == 1 && pid > 1000 {
                // Check if process is from suspicious location
                if let Ok(exe) = process.exe() {
                    let exe_path = exe.to_string_lossy();
                    let in_suspicious_loc = SUSPICIOUS_LOCATIONS
                        .iter()
                        .any(|&loc| exe_path.starts_with(loc));

                    if in_suspicious_loc && !is_legitimate_daemon(&comm) {
                        findings.push(
                                Finding::high(
                                    "suspicious_process",
                                    "Suspicious Orphaned Process",
                                    &format!(
                                        "Process '{}' (PID: {}) from {} parent is init - possible daemonized malware",
                                        comm, pid, exe_path
                                    ),
                                )
                                .with_remediation("Investigate this process immediately"),
                            );
                    }
                }
            }

            // Check for processes listening on network but not in expected locations
            if let Ok(io) = process.io() {
                // High I/O might indicate data exfiltration
                if io.read_bytes > 100_000_000 || io.write_bytes > 100_000_000 {
                    debug!(
                        "Process {} has high I/O: read {} MB, write {} MB",
                        comm,
                        io.read_bytes / 1_000_000,
                        io.write_bytes / 1_000_000
                    );
                }
            }
        }
    }

    // Detect hidden processes using ps vs /proc comparison
    // This is the CORRECT way to find rootkit-hidden processes
    if let Ok(hidden_findings) = detect_hidden_processes().await {
        findings.extend(hidden_findings);
    }

    info!("  Found {} suspicious processes", findings.len());
    Ok(findings)
}

/// Detect hidden processes by comparing ps output with /proc enumeration
/// This catches rootkits that hide processes from /proc but can't hide from `ps`
async fn detect_hidden_processes() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Get PIDs from /proc directory
    let mut proc_pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if let Ok(pid) = file_name.parse::<i32>() {
                    proc_pids.insert(pid);
                }
            }
        }
    }

    // Get PIDs from `ps` command (uses different kernel API)
    let ps_output = std::process::Command::new("ps")
        .args(["-eo", "pid"])
        .output();

    if let Ok(output) = ps_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut ps_pids = HashSet::new();

        for line in stdout.lines().skip(1) {
            // Skip header
            if let Ok(pid) = line.trim().parse::<i32>() {
                ps_pids.insert(pid);
            }
        }

        debug!(
            "Found {} PIDs in /proc, {} PIDs via ps",
            proc_pids.len(),
            ps_pids.len()
        );

        // Find PIDs that exist in ps but NOT in /proc (hidden by rootkit)
        for pid in &ps_pids {
            if !proc_pids.contains(pid) && *pid > 1 {
                // ROBUST RACE CONDITION HANDLING
                // Retry verification to distinguish between short-lived processes and actual rootkit hiding

                // Get process details from ps
                let process_details = get_process_details_from_ps(*pid);

                // Filter out short-lived processes (likely race conditions, not rootkits)
                // If ps can't find the process, it exited very quickly
                if process_details.0 == "<unknown>" {
                    debug!(
                        "PID {} is a short-lived process (race condition), skipping",
                        pid
                    );
                    continue;
                }

                // CRITICAL FIX: Retry verification with small delay to avoid false positives
                // If the process is truly hidden by a rootkit, it will still be visible in ps
                // If it's a short-lived process, both ps and /proc will show it's gone
                std::thread::sleep(std::time::Duration::from_millis(50));

                // Re-check /proc after delay
                let proc_exists = std::path::Path::new(&format!("/proc/{}", pid)).exists();

                // Re-check ps after delay
                let ps_details_retry = get_process_details_from_ps(*pid);

                // If process disappeared from BOTH ps and /proc, it's just terminated (not hidden)
                if !proc_exists && ps_details_retry.0 == "<unknown>" {
                    debug!(
                        "PID {} terminated during scan (race condition, not rootkit), skipping",
                        pid
                    );
                    continue;
                }

                // If process still visible in ps but NOT in /proc consistently, flag as rootkit
                if ps_details_retry.0 != "<unknown>" && !proc_exists {
                    findings.push(
                        Finding::critical(
                            "rootkit",
                            "Hidden Process Detected (Rootkit Indicator)",
                            &format!(
                                "Process '{}' (PID: {}) found via ps but hidden from /proc - strong rootkit indicator. {}",
                                process_details.0,  // command name
                                pid,
                                process_details.1   // full command line
                            ),
                        )
                        .with_remediation(&format!(
                            "CRITICAL: Investigate immediately: ps -p {} -f | Verify if this is a short-lived process or actual rootkit",
                            pid
                        ))
                        .with_details(serde_json::json!({
                            "pid": pid,
                            "command": process_details.0,
                            "full_cmdline": process_details.1,
                            "detection_method": "ps_vs_proc_mismatch",
                            "verified_with_retry": true
                        })),
                    );
                } else {
                    debug!(
                        "PID {} inconsistency resolved after retry (race condition, not rootkit)",
                        pid
                    );
                }
            }
        }

        // Also check reverse: PIDs in /proc but not in ps (less common but possible)
        for pid in &proc_pids {
            if !ps_pids.contains(pid) && *pid > 1 {
                // Try to get process info from /proc (with early exit checks)
                let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                    .unwrap_or_else(|_| String::new())
                    .trim()
                    .to_string();

                // If we can't read comm, process already exited (race condition)
                if comm.is_empty() {
                    debug!("PID {} exited during scan (race condition), skipping", pid);
                    continue;
                }

                // Filter out kernel threads (they appear in /proc but not always in ps)
                // Kernel threads are in brackets [kthreadd], [kworker/...], etc.
                if comm.starts_with('[') && comm.ends_with(']') {
                    debug!("PID {} is kernel thread '{}', skipping", pid, comm);
                    continue;
                }

                let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
                    .unwrap_or_else(|_| String::new())
                    .replace('\0', " ")
                    .trim()
                    .to_string();

                // If no cmdline, it's likely a kernel thread
                if cmdline.is_empty() && comm.contains("kworker") {
                    debug!("PID {} is kernel worker, skipping", pid);
                    continue;
                }

                // ROBUST RACE CONDITION HANDLING (reverse case)
                // Retry to distinguish short-lived processes from actual hiding
                std::thread::sleep(std::time::Duration::from_millis(50));

                // Re-check /proc after delay
                let proc_still_exists = std::path::Path::new(&format!("/proc/{}", pid)).exists();

                // Re-check ps after delay
                let ps_details_retry = get_process_details_from_ps(*pid);

                // If process disappeared from /proc but still not in ps, it just terminated (race condition)
                if !proc_still_exists {
                    debug!(
                        "PID {} exited before investigation (race condition), skipping",
                        pid
                    );
                    continue;
                }

                // If process now visible in ps after retry, it was a timing issue (not hiding)
                if ps_details_retry.0 != "<unknown>" {
                    debug!(
                        "PID {} now visible in ps after retry (race condition, not hiding)",
                        pid
                    );
                    continue;
                }

                // If process still in /proc but consistently not in ps, flag it
                findings.push(
                    Finding::high(
                        "rootkit",
                        "Process Enumeration Anomaly",
                        &format!(
                            "Process '{}' (PID: {}) in /proc but not visible to ps - possible rootkit manipulation. Command: {}",
                            comm, pid, if cmdline.is_empty() { "<no cmdline>" } else { &cmdline }
                        ),
                    )
                    .with_remediation(&format!(
                        "Investigate: ps -p {} -f && cat /proc/{}/cmdline && ls -la /proc/{}/exe | Check if still exists or is short-lived process",
                        pid, pid, pid
                    ))
                    .with_details(serde_json::json!({
                        "pid": pid,
                        "command": comm,
                        "cmdline": cmdline,
                        "detection_method": "proc_vs_ps_mismatch",
                        "verified_with_retry": true
                    })),
                );
            }
        }
    } else {
        debug!("ps command not available, skipping hidden process detection");
    }

    Ok(findings)
}

/// Get process details from ps command
fn get_process_details_from_ps(pid: i32) -> (String, String) {
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm=,args="])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.trim().splitn(2, ' ').collect();

            if parts.len() >= 2 {
                return (parts[0].to_string(), parts[1].to_string());
            } else if parts.len() == 1 {
                return (parts[0].to_string(), String::new());
            }
        }
    }

    // Fallback if ps fails (process might have exited)
    (
        "<unknown>".to_string(),
        "Process may have already exited".to_string(),
    )
}

/// Check if a process name is a legitimate system daemon
fn is_legitimate_daemon(name: &str) -> bool {
    let legitimate = [
        // System daemons
        "systemd",
        "cron",
        "sshd",
        "rsyslogd",
        "dbus-daemon",
        "networkd",
        "udevd",
        "acpid",
        "atd",
        "chronyd",
        "dockerd",
        "containerd",
        "snapd",
        "avahi",
        "polkit",
        "smartd",
        "NetworkManager",
        "wpa_supplicant",
        "ModemManager",
        "boltd",
        "bluetoothd",
        "rtkit",
        "udisksd",
        "upowerd",
        "colord",
        "login",
        "cupsd",
        "cups-browsed",
        "ollama",
        "exim",
        "postfix",
        "bzfs",
        // Desktop environment
        "swaybg",
        "swaybar",
        "Xwayland",
        "gnome",
        "kde",
        "xfce",
        // Shells (legitimate user shells)
        "bash",
        "zsh",
        "sh",
        "fish",
        "dash",
        // Applications
        "low-memory-moni",
        "code", // VS Code
        "electron",
        "chrome",
        "firefox",
        "Discord",
        "Slack",
    ];

    legitimate.iter().any(|&d| name.contains(d))
}

/// Detect processes with suspicious network behavior
pub async fn detect_suspicious_network_processes() -> Result<Vec<Finding>> {
    info!("🔍 Checking for processes with suspicious network behavior...");
    let mut findings = Vec::new();

    // Parse /proc/net/tcp and /proc/net/udp to find listening processes
    let tcp_content = fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let _udp_content = fs::read_to_string("/proc/net/udp").unwrap_or_default();

    // Track processes with listening sockets
    let mut listening_processes = HashSet::new();

    // Parse TCP connections (simplified)
    for line in tcp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 9 {
            // Check if listening (state 0A = LISTEN)
            if parts[3] == "0A" {
                // Get inode
                if let Ok(inode) = parts[9].parse::<u64>() {
                    // Find process with this inode
                    if let Some(pid) = find_process_by_inode(inode) {
                        listening_processes.insert(pid);
                    }
                }
            }
        }
    }

    // Analyze listening processes
    for pid in listening_processes {
        if let Ok(process) = Process::new(pid) {
            if let Ok(stat) = process.stat() {
                let comm = stat.comm.clone();

                // Check if it's running from suspicious location
                if let Ok(exe) = process.exe() {
                    let exe_path = exe.to_string_lossy();

                    for sus_loc in SUSPICIOUS_LOCATIONS {
                        if exe_path.starts_with(sus_loc) {
                            findings.push(
                                Finding::critical(
                                    "network_backdoor",
                                    "Suspicious Process Listening on Network",
                                    &format!(
                                        "Process '{}' (PID: {}) from suspicious location {} is listening on network",
                                        comm, pid, exe_path
                                    ),
                                )
                                .with_remediation(&format!("Kill and investigate: sudo kill -9 {} && sudo netstat -tulpn", pid)),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

/// Find process by socket inode
fn find_process_by_inode(inode: u64) -> Option<i32> {
    if let Ok(processes) = all_processes() {
        for process in processes.flatten() {
            let pid = process.pid;

            // Check /proc/[pid]/fd for matching inode
            let fd_path = format!("/proc/{}/fd", pid);
            if let Ok(entries) = fs::read_dir(&fd_path) {
                for entry in entries.flatten() {
                    if let Ok(link) = fs::read_link(entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.contains(&format!("socket:[{}]", inode)) {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}
