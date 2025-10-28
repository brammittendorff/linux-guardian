use crate::models::Finding;
use anyhow::Result;
use procfs::process::{all_processes, Process};
use tracing::{debug, info};

/// Known cryptominer process names and patterns
const KNOWN_MINERS: &[&str] = &[
    "xmrig",
    "minerd",
    "cpuminer",
    "ccminer",
    "ethminer",
    "minergate",
    "cryptonight",
    "stratum",
    "xmr-stak",
    "randomx",
    "monero",
    "kdevtmpfsi", // Known malware miner
    "kinsing",    // Kinsing malware
    "perfctl",    // Perfctl malware
];

/// Suspicious process names that are often used to hide miners
const SUSPICIOUS_NAMES: &[&str] = &[
    "kworker",    // Real kernel workers don't run in userspace
    "systemd",    // If running from unusual location
    "apache",     // Fake apache
    "nginx",      // Fake nginx
    "httpd",      // Fake httpd
    "[kthreadd]", // Malicious processes often mimic kernel threads
];

/// Known mining pool domains and IPs
const MINING_POOLS: &[&str] = &[
    "minexmr.com",
    "supportxmr.com",
    "pool.hashvault.pro",
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
    "monerohash.com",
    "viaxmr.com",
    "monero.crypto-pool.fr",
    "xmrpool.eu",
    "nanopool.org",
    "f2pool.com",
];

/// Detect CPU anomalies and potential cryptominers
pub async fn detect_cpu_anomalies() -> Result<Vec<Finding>> {
    info!("🔍 Detecting CPU anomalies and cryptominers...");
    let mut findings = Vec::new();

    // Get all processes
    let processes = match all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            debug!("Failed to read processes: {}", e);
            return Ok(findings);
        }
    };

    let mut high_cpu_processes: Vec<(i32, String, f32, String)> = Vec::new();

    // Analyze each process
    for process in processes.flatten() {
        if let Ok(stat) = process.stat() {
            let pid = process.pid;

            // Get process name
            let comm = stat.comm.clone();

            // Calculate CPU usage
            let cpu_usage = calculate_cpu_usage(&process);

            // Get command line
            let cmdline = process
                .cmdline()
                .unwrap_or_default()
                .join(" ")
                .chars()
                .take(200)
                .collect::<String>();

            // Check for known miner names
            let comm_lower = comm.to_lowercase();
            let cmdline_lower = cmdline.to_lowercase();

            for miner in KNOWN_MINERS {
                if comm_lower.contains(miner) || cmdline_lower.contains(miner) {
                    findings.push(
                            Finding::critical(
                                "cryptominer",
                                "Known Cryptominer Process Detected",
                                &format!(
                                    "Detected known cryptominer process '{}' (PID: {}). Command: {}",
                                    comm, pid, cmdline
                                ),
                            )
                            .with_remediation(&format!("Kill process and investigate: sudo kill -9 {} && sudo ps aux | grep {}", pid, comm)),
                        );
                }
            }

            // Check for suspicious process names
            for sus_name in SUSPICIOUS_NAMES {
                if comm.contains(sus_name) {
                    // Check if it's running from suspicious location
                    if let Ok(exe) = process.exe() {
                        let exe_path = exe.to_string_lossy();
                        if exe_path.contains("/tmp")
                            || exe_path.contains("/dev/shm")
                            || exe_path.contains("/var/tmp")
                        {
                            findings.push(
                                    Finding::high(
                                        "cryptominer",
                                        "Suspicious Process in Unusual Location",
                                        &format!(
                                            "Process '{}' (PID: {}) running from suspicious location: {}",
                                            comm, pid, exe_path
                                        ),
                                    )
                                    .with_remediation(&format!("Investigate and kill if malicious: sudo kill -9 {}", pid)),
                                );
                        }
                    }
                }
            }

            // Check for mining pool connections in command line
            for pool in MINING_POOLS {
                if cmdline_lower.contains(pool) {
                    findings.push(
                        Finding::critical(
                            "cryptominer",
                            "Mining Pool Connection Detected",
                            &format!(
                                "Process '{}' (PID: {}) connecting to mining pool: {}",
                                comm, pid, pool
                            ),
                        )
                        .with_remediation(&format!(
                            "Kill process immediately: sudo kill -9 {}",
                            pid
                        )),
                    );
                }
            }

            // Track high CPU processes
            if cpu_usage > 80.0 {
                high_cpu_processes.push((pid, comm.clone(), cpu_usage, cmdline.clone()));
            }

            // Check for processes that delete their binary (common miner technique)
            // BUT exclude legitimate processes like Chrome that do this during updates
            if let Ok(exe) = process.exe() {
                let exe_path = exe.to_string_lossy();
                if exe_path.contains("(deleted)") {
                    // Whitelist: Chrome, Firefox, VS Code and other apps legitimately do this during updates
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
                                    "cryptominer",
                                    "Process Running with Deleted Binary",
                                    &format!(
                                        "Process '{}' (PID: {}) is running but its binary has been deleted - common miner tactic",
                                        comm, pid
                                    ),
                                )
                                .with_remediation(&format!("Investigate: sudo ls -la /proc/{}/exe && sudo kill -9 {}", pid, pid)),
                            );
                    }
                }
            }
        }
    }

    // Report top high CPU processes
    if !high_cpu_processes.is_empty() {
        high_cpu_processes.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
        let top_processes = high_cpu_processes.iter().take(3);

        for (pid, comm, cpu, cmdline) in top_processes {
            if *cpu > 90.0 {
                findings.push(
                    Finding::medium(
                        "cryptominer",
                        "High CPU Usage Detected",
                        &format!(
                            "Process '{}' (PID: {}) using {:.1}% CPU. Command: {}",
                            comm, pid, cpu, cmdline
                        ),
                    )
                    .with_remediation("Investigate high CPU usage - may indicate cryptomining"),
                );
            }
        }
    }

    info!(
        "  Found {} potential cryptominer indicators",
        findings.len()
    );
    Ok(findings)
}

/// Calculate CPU usage for a process (simplified)
fn calculate_cpu_usage(process: &Process) -> f32 {
    // This is a simplified calculation
    // In a real implementation, you'd want to sample over time
    if let Ok(stat) = process.stat() {
        let total_time = stat.utime + stat.stime;

        // Get system uptime from /proc/uptime
        if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
            if let Some(uptime_s) = uptime_str.split_whitespace().next() {
                if let Ok(uptime_sec) = uptime_s.parse::<f64>() {
                    let uptime_ticks = (uptime_sec * 100.0) as u64;
                    if uptime_ticks > 0 {
                        return (total_time as f32 / uptime_ticks as f32) * 100.0;
                    }
                }
            }
        }
    }
    0.0
}

/// Check for hidden cryptocurrency mining (dormant miners)
pub async fn check_dormant_miners() -> Result<Vec<Finding>> {
    info!("🔍 Checking for dormant/hidden miners...");
    let mut findings = Vec::new();

    // Check for mining-related files in suspicious locations
    let suspicious_paths = ["/tmp", "/dev/shm", "/var/tmp", "/home"];
    let miner_indicators = [
        "xmrig",
        "miner",
        "pool",
        "stratum",
        "hashrate",
        "cryptonight",
    ];

    for base_path in &suspicious_paths {
        if let Ok(entries) = std::fs::read_dir(base_path) {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    let file_name_lower = file_name.to_lowercase();

                    for indicator in &miner_indicators {
                        if file_name_lower.contains(indicator) {
                            findings.push(
                                Finding::high(
                                    "cryptominer",
                                    "Suspicious Mining-Related File",
                                    &format!(
                                        "Found suspicious file in {}: {}",
                                        base_path, file_name
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate file: ls -la {}/{}",
                                    base_path, file_name
                                )),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

/// Detect miners hiding in cron jobs
pub async fn check_cron_miners() -> Result<Vec<Finding>> {
    info!("🔍 Checking cron jobs for miners...");
    let mut findings = Vec::new();

    // Check system crontabs
    let cron_locations = ["/etc/crontab", "/var/spool/cron/crontabs", "/etc/cron.d"];

    for location in &cron_locations {
        if let Ok(content) = std::fs::read_to_string(location) {
            let content_lower = content.to_lowercase();

            for miner in KNOWN_MINERS {
                if content_lower.contains(miner) {
                    findings.push(
                        Finding::critical(
                            "cryptominer",
                            "Cryptominer in Cron Job",
                            &format!("Found miner '{}' in cron: {}", miner, location),
                        )
                        .with_remediation(&format!(
                            "Edit crontab and remove malicious entries: sudo vi {}",
                            location
                        )),
                    );
                }
            }

            for pool in MINING_POOLS {
                if content_lower.contains(pool) {
                    findings.push(
                        Finding::critical(
                            "cryptominer",
                            "Mining Pool in Cron Job",
                            &format!("Found mining pool '{}' in cron: {}", pool, location),
                        )
                        .with_remediation(&format!(
                            "Edit crontab and remove malicious entries: sudo vi {}",
                            location
                        )),
                    );
                }
            }
        }
    }

    Ok(findings)
}
