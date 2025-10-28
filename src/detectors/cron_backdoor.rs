use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tracing::{debug, info};
use walkdir::WalkDir;

/// Enhanced cron backdoor detection (beyond cryptominers)
pub async fn detect_cron_backdoors() -> Result<Vec<Finding>> {
    info!("🔍 Checking for cron backdoors...");
    let mut findings = Vec::new();

    // Locations to check
    let cron_locations = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];

    for location in &cron_locations {
        let path = PathBuf::from(location);

        if !path.exists() {
            continue;
        }

        if path.is_file() {
            // Single file (like /etc/crontab)
            check_cron_file(&path, &mut findings)?;
        } else if path.is_dir() {
            // Directory with multiple cron files
            for entry in WalkDir::new(&path)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.path().is_file() {
                    check_cron_file(entry.path(), &mut findings)?;
                }
            }
        }
    }

    // Check user crontabs (if accessible)
    if let Ok(output) = std::process::Command::new("crontab").args(["-l"]).output() {
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            check_cron_content(&content, "user crontab", &mut findings);
        }
    }

    if findings.is_empty() {
        debug!("Cron backdoor check passed");
    }

    Ok(findings)
}

fn check_cron_file(path: &std::path::Path, findings: &mut Vec<Finding>) -> Result<()> {
    let content = fs::read_to_string(path)?;

    // Check permissions first
    if let Ok(metadata) = fs::metadata(path) {
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Cron files should NOT be world-writable
        if mode & 0o002 != 0 {
            findings.push(
                Finding::high(
                    "cron_writable",
                    "World-Writable Cron File",
                    &format!(
                        "Cron file {} is world-writable ({:o}). Attacker can inject commands!",
                        path.display(),
                        mode & 0o777
                    ),
                )
                .with_remediation(&format!(
                    "Fix permissions: sudo chmod 644 {}",
                    path.display()
                )),
            );
        }
    }

    check_cron_content(&content, &path.display().to_string(), findings);

    Ok(())
}

fn check_cron_content(content: &str, source: &str, findings: &mut Vec<Finding>) {
    // Suspicious command patterns in cron jobs
    let backdoor_patterns = [
        ("curl", "Downloading external content"),
        ("wget", "Downloading external content"),
        ("nc ", "Netcat - reverse shell"),
        ("netcat", "Netcat - reverse shell"),
        ("/dev/tcp/", "TCP socket redirection"),
        ("/dev/udp/", "UDP socket redirection"),
        ("bash -i", "Interactive bash shell"),
        ("sh -i", "Interactive shell"),
        ("python -c", "Inline Python code"),
        ("perl -e", "Inline Perl code"),
        ("ruby -e", "Inline Ruby code"),
        ("php -r", "Inline PHP code"),
        ("base64 -d", "Base64 decoding (obfuscation)"),
        ("eval", "Code evaluation (obfuscation)"),
        ("/tmp/", "Execution from /tmp"),
        ("/dev/shm", "Execution from shared memory"),
        ("chmod +x", "Making files executable"),
        (">/dev/null 2>&1 &", "Backgrounding and hiding output"),
    ];

    for line in content.lines() {
        // Skip comments
        if line.trim().starts_with('#') {
            continue;
        }

        let line_lower = line.to_lowercase();

        for (pattern, description) in &backdoor_patterns {
            if line_lower.contains(pattern) {
                // Check if it's a legitimate command or backdoor
                let is_suspicious = check_command_legitimacy(line);

                if is_suspicious {
                    findings.push(
                        Finding::critical(
                            "cron_backdoor",
                            "Suspicious Command in Cron Job",
                            &format!(
                                "Cron job in {} contains suspicious command: {}. Pattern: {} ({})",
                                source,
                                line.trim(),
                                pattern,
                                description
                            ),
                        )
                        .with_remediation(&format!(
                            "Review and remove: sudo crontab -e or edit {}",
                            source
                        )),
                    );
                    break; // Don't report same line multiple times
                }
            }
        }

        // Check for jobs running every minute (* * * * *)
        if line.starts_with("* * * * *") || line.starts_with("*/1 * * * *") {
            findings.push(
                Finding::medium(
                    "cron_frequent",
                    "Cron Job Running Every Minute",
                    &format!(
                        "Cron job in {} runs every minute: {}. Could be cryptominer or backdoor.",
                        source,
                        line.trim()
                    ),
                )
                .with_remediation("Review if this frequency is necessary"),
            );
        }

        // Check for cron jobs with no username (in /etc/crontab)
        if source.contains("/etc/crontab") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Format: min hour day month dow user command
            if fields.len() >= 7 {
                let user = fields[5];
                if user == "root" {
                    // Root cron jobs with network activity are high risk
                    if line_lower.contains("curl")
                        || line_lower.contains("wget")
                        || line_lower.contains("nc ")
                    {
                        findings.push(
                            Finding::high(
                                "cron_root_network",
                                "Root Cron Job with Network Activity",
                                &format!("Root cron job with network command: {}", line.trim()),
                            )
                            .with_remediation("Consider running as non-root user"),
                        );
                    }
                }
            }
        }
    }
}

fn check_command_legitimacy(command: &str) -> bool {
    // Simple heuristic to reduce false positives
    let cmd_lower = command.to_lowercase();

    // Legitimate patterns (common update scripts)
    let legitimate = [
        "apt-get update",
        "yum update",
        "dnf update",
        "zypper update",
        "pacman -syu",
        "certbot renew",
        "backup",
        "logrotate",
    ];

    for legit in &legitimate {
        if cmd_lower.contains(legit) {
            return false; // Not suspicious
        }
    }

    // If downloading to /tmp and executing, very suspicious
    if (cmd_lower.contains("curl") || cmd_lower.contains("wget"))
        && (cmd_lower.contains("/tmp") || cmd_lower.contains("/dev/shm"))
        && (cmd_lower.contains("bash") || cmd_lower.contains("sh") || cmd_lower.contains("chmod"))
    {
        return true;
    }

    // Base64 decode piped to bash is almost always malicious
    if cmd_lower.contains("base64") && cmd_lower.contains("bash") {
        return true;
    }

    // Reverse shell patterns
    if cmd_lower.contains("/dev/tcp") || cmd_lower.contains("/dev/udp") {
        return true;
    }

    // If it has suspicious pattern + obfuscation, flag it
    if cmd_lower.contains("eval") || cmd_lower.contains("exec") {
        return true;
    }

    // Default: flag it if we got here (it matched a suspicious pattern)
    true
}

/// Check for at jobs (another persistence mechanism)
pub async fn check_at_jobs() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check if atd is running
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["is-active", "atd"])
        .output()
    {
        if output.status.success() {
            // List at jobs
            if let Ok(atq_output) = std::process::Command::new("atq").output() {
                let jobs = String::from_utf8_lossy(&atq_output.stdout);

                if !jobs.trim().is_empty() {
                    let job_count = jobs.lines().count();

                    if job_count > 0 {
                        findings.push(
                            Finding::medium(
                                "at_jobs_present",
                                "Scheduled AT Jobs Detected",
                                &format!(
                                    "{} at jobs scheduled. AT jobs can be used for persistence.",
                                    job_count
                                ),
                            )
                            .with_remediation("Review: atq && at -c <job_number>"),
                        );
                    }
                }
            }
        }
    }

    Ok(findings)
}
