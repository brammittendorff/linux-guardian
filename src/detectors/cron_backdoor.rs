use crate::models::Finding;
use anyhow::Result;
use regex::Regex;
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

/// Check if a file is managed by a package manager (dpkg, rpm)
/// Package-managed files are legitimate and installed by trusted packages
fn is_package_managed_file(file_path: &str) -> bool {
    // Try dpkg first (Debian/Ubuntu)
    if let Ok(output) = std::process::Command::new("dpkg")
        .args(["-S", file_path])
        .output()
    {
        if output.status.success() {
            // dpkg found a package owning this file
            return true;
        }
    }

    // Try rpm (RHEL/Fedora/openSUSE)
    if let Ok(output) = std::process::Command::new("rpm")
        .args(["-qf", file_path])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // rpm returns "file ... is not owned by any package" on failure
            if !stdout.contains("is not owned by any package") {
                return true;
            }
        }
    }

    false
}

fn check_cron_content(content: &str, source: &str, findings: &mut Vec<Finding>) {
    // Generic verification: Check if cron file is owned by a package
    // Files in /etc/cron.* that are managed by dpkg are legitimate
    if is_package_managed_file(source) {
        debug!("Skipping package-managed cron file: {}", source);
        return;
    }

    // Regex patterns for precise detection of netcat with IP:port
    let nc_with_ip_port =
        Regex::new(r"n(?:c|cat|etcat)\s+(?:-[elc]\s+)?(?:\d{1,3}\.){3}\d{1,3}\s+\d{1,5}").unwrap();
    let nc_with_exec = Regex::new(r"n(?:c|cat|etcat)\s+-[ec]\s+/bin/(?:ba)?sh").unwrap();
    let nc_listen = Regex::new(r"n(?:c|cat|etcat)\s+-l").unwrap();
    let dev_tcp_pattern = Regex::new(r"/dev/tcp/(?:\d{1,3}\.){3}\d{1,3}/\d{1,5}").unwrap();
    let reverse_shell = Regex::new(r"(?:ba)?sh\s+-i\s+[>&<]+\s*/dev/tcp/").unwrap();

    // Suspicious command patterns in cron jobs
    let backdoor_patterns = [
        ("curl", "Downloading external content"),
        ("wget", "Downloading external content"),
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

        // Check regex patterns first (more precise) - these are ALWAYS suspicious
        if let Some(caps) = nc_with_ip_port.find(&line_lower) {
            findings.push(
                Finding::critical(
                    "cron_backdoor",
                    "Netcat with IP:Port in Cron Job",
                    &format!(
                        "Cron job in {} contains netcat connecting to IP:port: {}. Match: '{}'",
                        source,
                        line.trim(),
                        caps.as_str()
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Remove backdoor: sudo crontab -e or edit {}",
                    source
                )),
            );
            continue;
        }

        if let Some(caps) = nc_with_exec.find(&line_lower) {
            findings.push(
                Finding::critical(
                    "cron_backdoor",
                    "Netcat Executing Shell in Cron Job",
                    &format!(
                        "Cron job in {} contains netcat executing shell: {}. Match: '{}'",
                        source,
                        line.trim(),
                        caps.as_str()
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Remove backdoor: sudo crontab -e or edit {}",
                    source
                )),
            );
            continue;
        }

        if let Some(caps) = nc_listen.find(&line_lower) {
            findings.push(
                Finding::critical(
                    "cron_backdoor",
                    "Netcat Listening in Cron Job",
                    &format!(
                        "Cron job in {} contains netcat in listen mode: {}. Match: '{}'",
                        source,
                        line.trim(),
                        caps.as_str()
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Remove backdoor: sudo crontab -e or edit {}",
                    source
                )),
            );
            continue;
        }

        if let Some(caps) = dev_tcp_pattern.find(&line_lower) {
            findings.push(
                Finding::critical(
                    "cron_backdoor",
                    "Reverse Shell Pattern in Cron Job",
                    &format!(
                        "Cron job in {} uses /dev/tcp/ to connect to IP:port: {}. Match: '{}'",
                        source,
                        line.trim(),
                        caps.as_str()
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Remove reverse shell: sudo crontab -e or edit {}",
                    source
                )),
            );
            continue;
        }

        if let Some(caps) = reverse_shell.find(&line_lower) {
            findings.push(
                Finding::critical(
                    "cron_backdoor",
                    "Interactive Shell Reverse Connection in Cron",
                    &format!(
                        "Cron job in {} contains interactive shell redirected to TCP: {}. Match: '{}'",
                        source,
                        line.trim(),
                        caps.as_str()
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Remove reverse shell: sudo crontab -e or edit {}",
                    source
                )),
            );
            continue;
        }

        // Check generic patterns (need legitimacy check)
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
                        || nc_with_ip_port.is_match(&line_lower)
                        || nc_with_exec.is_match(&line_lower)
                        || nc_listen.is_match(&line_lower)
                        || dev_tcp_pattern.is_match(&line_lower)
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
