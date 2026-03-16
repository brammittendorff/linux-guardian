use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info};
use walkdir::WalkDir;

/// Detect systemd service tampering and backdoors
pub async fn detect_systemd_tampering() -> Result<Vec<Finding>> {
    info!("🔍 Checking for systemd service tampering...");
    let mut findings = Vec::new();

    // Track canonical paths to avoid duplicate findings when directories
    // are symlinked (e.g. /lib/systemd/system → /usr/lib/systemd/system)
    // or unit files are symlinked into .wants/ directories.
    let mut seen_canonical: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    // Locations to check for systemd units
    let unit_paths = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/home/*/.config/systemd/user", // User services
    ];

    for path_pattern in &unit_paths {
        let path = PathBuf::from(path_pattern);

        if !path.exists() && !path_pattern.contains('*') {
            continue;
        }

        // Expand glob if needed
        let paths_to_check: Vec<PathBuf> = if path_pattern.contains('*') {
            // Expand /home/*
            if let Ok(entries) = fs::read_dir("/home") {
                entries
                    .flatten()
                    .filter_map(|e| {
                        let user_path = e.path().join(".config/systemd/user");
                        if user_path.exists() {
                            Some(user_path)
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![path]
        };

        for check_path in paths_to_check {
            if !check_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&check_path)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let file_path = entry.path();

                // Resolve symlinks to the real file and skip if already seen.
                let canonical = match fs::canonicalize(file_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if !seen_canonical.insert(canonical) {
                    continue;
                }

                // Only check .service, .timer, .socket files
                if let Some(ext) = file_path.extension() {
                    let ext_str = ext.to_string_lossy();
                    if !matches!(ext_str.as_ref(), "service" | "timer" | "socket") {
                        continue;
                    }
                } else {
                    continue;
                }

                // Read the unit file
                if let Ok(content) = fs::read_to_string(file_path) {
                    let content_lower = content.to_lowercase();

                    // Check for suspicious ExecStart commands
                    // NOTE: "/bin/bash -c" is NOT suspicious — it's used by
                    // many legitimate services (cloud-init, etc.). The truly
                    // malicious patterns below already catch real backdoors.
                    let suspicious_commands = [
                        "curl",
                        "wget",
                        "nc -e",
                        "nc -c",
                        "nc -l",
                        "ncat -e",
                        "netcat -e",
                        "/dev/tcp/",
                        "/tmp/",
                        "/dev/shm",
                        "bash -i",
                        "sh -i",
                        "base64 -d",
                        "python -c",
                        "perl -e",
                        "ruby -e",
                        "php -r",
                        "; rm ",
                        "&& rm ",
                        ">/dev/tcp/",
                        ">/dev/udp/",
                    ];

                    for suspicious in &suspicious_commands {
                        if content_lower.contains(suspicious) {
                            findings.push(
                                Finding::critical(
                                    "systemd_backdoor",
                                    "Suspicious Systemd Service Command",
                                    &format!(
                                        "Service {} contains suspicious command '{}'. Possible backdoor!",
                                        file_path.display(),
                                        suspicious
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate: cat '{}' && sudo systemctl disable {}",
                                    file_path.display(),
                                    file_path.file_stem().unwrap().to_string_lossy()
                                )),
                            );
                        }
                    }

                    // Check for services running as root that shouldn't
                    if (content_lower.contains("user=root") || !content_lower.contains("user="))
                        && content_lower.contains("execstart=")
                    {
                        // Extract the command
                        for line in content.lines() {
                            if line.to_lowercase().starts_with("execstart=") {
                                let cmd = line.split('=').nth(1).unwrap_or("").trim();
                                let cmd_lower = cmd.to_lowercase();

                                // Split binary from arguments — only check arguments
                                // for network keywords. Checking the binary name causes
                                // false positives (e.g., "rpcbind" contains "bind").
                                let args_part = cmd_lower
                                    .split_whitespace()
                                    .skip(1)
                                    .collect::<Vec<_>>()
                                    .join(" ");

                                // Extract the actual binary path (before arguments)
                                let binary_path = cmd.split_whitespace().next().unwrap_or("");

                                // Network-facing services shouldn't run as root —
                                // UNLESS the binary is package-managed (dpkg/rpm owns it).
                                // A package-managed binary in a system path is a distro
                                // service that was designed to run as root. An attacker
                                // can't fake dpkg ownership.
                                let is_pkg_managed = !binary_path.is_empty()
                                    && std::process::Command::new("dpkg")
                                        .args(["-S", binary_path])
                                        .output()
                                        .map(|o| o.status.success())
                                        .unwrap_or(false);

                                if !is_pkg_managed
                                    && (args_part.contains("--listen")
                                        || args_part.contains("--bind")
                                        || args_part.contains("--serve")
                                        || args_part.contains("--http")
                                        || args_part.contains("-l ")
                                        || args_part.ends_with("-l"))
                                {
                                    findings.push(
                                        Finding::medium(
                                            "systemd_root_service",
                                            "Network Service Running as Root",
                                            &format!(
                                                "Service {} runs network command as root: {}",
                                                file_path.display(),
                                                cmd
                                            ),
                                        )
                                        .with_remediation(
                                            "Add 'User=<non-root-user>' to [Service] section",
                                        ),
                                    );
                                }
                            }
                        }
                    }

                    // Check for obfuscated commands
                    if content.contains("base64")
                        || content.contains("xxd")
                        || content.contains("eval")
                    {
                        findings.push(
                            Finding::high(
                                "systemd_obfuscation",
                                "Obfuscated Command in Systemd Service",
                                &format!(
                                    "Service {} contains obfuscated commands (base64/eval). Could hide malware!",
                                    file_path.display()
                                ),
                            )
                            .with_remediation(&format!("Review: cat '{}'", file_path.display())),
                        );
                    }

                    // Check for services with no description (suspicious)
                    if !content.to_lowercase().contains("description=") {
                        debug!("Service without description: {}", file_path.display());
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        debug!("Systemd service check passed");
    }

    Ok(findings)
}

/// Check systemd timers (persistence mechanism like cron)
pub async fn check_systemd_timers() -> Result<Vec<Finding>> {
    info!("🔍 Checking systemd timers for backdoors...");
    let mut findings = Vec::new();

    // List all active timers
    if let Ok(output) = Command::new("systemctl")
        .args(["list-timers", "--all", "--no-pager"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            // Skip header
            if line.trim().is_empty() {
                continue;
            }

            // Timer names often end in .timer
            if let Some(timer_name) = line.split_whitespace().last() {
                if timer_name.ends_with(".timer") {
                    // Get the timer unit file
                    if let Ok(show_output) =
                        Command::new("systemctl").args(["cat", timer_name]).output()
                    {
                        let timer_content = String::from_utf8_lossy(&show_output.stdout);

                        // Check frequency - timers running every minute are suspicious
                        if timer_content.contains("OnCalendar=*:*:*")
                            || timer_content.contains("OnBootSec=")
                            || timer_content.contains("OnUnitActiveSec=1")
                        {
                            findings.push(
                                Finding::medium(
                                    "systemd_frequent_timer",
                                    "Frequently Running Systemd Timer",
                                    &format!(
                                        "Timer {} runs very frequently. Could be malware persistence.",
                                        timer_name
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate: systemctl cat {} && systemctl disable {}",
                                    timer_name, timer_name
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

/// Check for modified init scripts (legacy but still used)
pub async fn check_init_scripts() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check individual files inside /etc/init.d for recent modifications
    if let Ok(entries) = fs::read_dir("/etc/init.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(metadata) = path.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();

                    if age.as_secs() < 7 * 24 * 3600 {
                        let file_name = path.display();
                        findings.push(
                            Finding::medium(
                                "init_script_modified",
                                "Init Script Recently Modified",
                                &format!(
                                    "{} was modified {:.1} days ago. Unusual for init scripts.",
                                    file_name,
                                    age.as_secs_f32() / 86400.0
                                ),
                            )
                            .with_remediation(&format!("Review: cat '{}'", file_name)),
                        );
                    }
                }
            }
        }
    }

    // Check rc.local separately (it's a file, not a directory)
    let rc_local = "/etc/rc.local";
    if let Ok(metadata) = fs::metadata(rc_local) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();

            if age.as_secs() < 7 * 24 * 3600 {
                findings.push(
                    Finding::medium(
                        "init_script_modified",
                        "Init Script Recently Modified",
                        &format!(
                            "{} was modified {:.1} days ago. Unusual for init scripts.",
                            rc_local,
                            age.as_secs_f32() / 86400.0
                        ),
                    )
                    .with_remediation(&format!("Review: cat '{}'", rc_local)),
                );
            }
        }
    }

    // Check rc.local content for suspicious commands
    if let Ok(content) = fs::read_to_string(rc_local) {
        let content_lower = content.to_lowercase();

        let suspicious = [
            "curl",
            "wget",
            "/tmp",
            "bash -c",
            "nc -e",
            "nc -l",
            "/dev/tcp/",
            "base64",
        ];
        for pattern in &suspicious {
            if content_lower.contains(pattern) {
                findings.push(
                    Finding::high(
                        "rc_local_backdoor",
                        "Suspicious Command in rc.local",
                        &format!("rc.local contains suspicious command: {}", pattern),
                    )
                    .with_remediation("Review: cat /etc/rc.local"),
                );
            }
        }
    }

    Ok(findings)
}
