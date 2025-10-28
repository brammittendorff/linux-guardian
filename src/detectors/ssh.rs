use crate::models::Finding;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use tracing::{debug, info};

/// Check for unauthorized SSH keys
pub async fn check_unauthorized_keys() -> Result<Vec<Finding>> {
    info!("🔍 Checking for unauthorized SSH keys...");
    let mut findings = Vec::new();

    // Check for root SSH keys
    let root_ssh_dir = "/root/.ssh";
    if let Ok(authorized_keys) = fs::read_to_string(format!("{}/authorized_keys", root_ssh_dir)) {
        let key_count = authorized_keys
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .count();

        if key_count > 0 {
            debug!("Found {} SSH keys for root", key_count);

            // Check for recently modified authorized_keys (last 7 days)
            if let Ok(metadata) = fs::metadata(format!("{}/authorized_keys", root_ssh_dir)) {
                if let Ok(modified) = metadata.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();

                    if age.as_secs() < 7 * 24 * 3600 {
                        findings.push(
                            Finding::high(
                                "ssh_backdoor",
                                "Recent Root SSH Key Modification",
                                &format!(
                                    "Root authorized_keys file was modified {} days ago. {} keys present.",
                                    age.as_secs() / 86400,
                                    key_count
                                ),
                            )
                            .with_remediation("Review /root/.ssh/authorized_keys and remove unauthorized keys"),
                        );
                    }
                }
            }

            // Check for suspicious key comments or patterns
            for line in authorized_keys.lines() {
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }

                // Check for keys without comments (suspicious)
                if !line.contains("@") && !line.contains(" ") {
                    findings.push(
                        Finding::medium(
                            "ssh_backdoor",
                            "SSH Key Without Comment/Identifier",
                            "Found SSH key in root's authorized_keys without identifying comment",
                        )
                        .with_remediation(
                            "Add identifying comments to all SSH keys or remove unknown keys",
                        ),
                    );
                }

                // Check for options that could be malicious
                if line.contains("command=") {
                    findings.push(
                        Finding::high(
                            "ssh_backdoor",
                            "SSH Key with Forced Command",
                            &format!("Found SSH key with forced command option: {}", line),
                        )
                        .with_remediation(
                            "Review forced commands in authorized_keys for malicious content",
                        ),
                    );
                }
            }
        }
    }

    // Check all user home directories for SSH keys
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let username = entry.file_name();
                    let ssh_path =
                        format!("/home/{}/.ssh/authorized_keys", username.to_string_lossy());

                    if let Ok(user_keys) = fs::read_to_string(&ssh_path) {
                        let _key_count = user_keys
                            .lines()
                            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                            .count();

                        // Check for recent modifications
                        if let Ok(metadata) = fs::metadata(&ssh_path) {
                            if let Ok(modified) = metadata.modified() {
                                let age = std::time::SystemTime::now()
                                    .duration_since(modified)
                                    .unwrap_or_default();

                                if age.as_secs() < 24 * 3600 {
                                    // Modified in last 24 hours
                                    findings.push(
                                        Finding::high(
                                            "ssh_backdoor",
                                            "Recent SSH Key Addition",
                                            &format!(
                                                "SSH keys for user '{}' modified {} hours ago",
                                                username.to_string_lossy(),
                                                age.as_secs() / 3600
                                            ),
                                        )
                                        .with_remediation(&format!("Review {}", ssh_path)),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check SSH configuration for dangerous settings
    if let Ok(sshd_config) = fs::read_to_string("/etc/ssh/sshd_config") {
        for line in sshd_config.lines() {
            let line = line.trim();

            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            // PermitRootLogin yes is dangerous
            if line.contains("PermitRootLogin") && line.contains("yes") {
                findings.push(
                    Finding::high(
                        "ssh_config",
                        "Root Login via SSH Enabled",
                        "SSH configuration allows root login (PermitRootLogin yes)",
                    )
                    .with_remediation("Disable root SSH: Edit /etc/ssh/sshd_config, set 'PermitRootLogin no', restart SSH"),
                );
            }

            // PasswordAuthentication yes is less secure
            if line.contains("PasswordAuthentication") && line.contains("yes") {
                findings.push(
                    Finding::medium(
                        "ssh_config",
                        "Password Authentication Enabled",
                        "SSH allows password authentication (less secure than key-based auth)",
                    )
                    .with_remediation("Use key-based authentication: Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"),
                );
            }

            // PermitEmptyPasswords yes is critical
            if line.contains("PermitEmptyPasswords") && line.contains("yes") {
                findings.push(
                    Finding::critical(
                        "ssh_config",
                        "Empty Passwords Allowed",
                        "SSH configuration allows empty passwords!",
                    )
                    .with_remediation(
                        "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config immediately",
                    ),
                );
            }
        }
    }

    info!("  Found {} SSH security issues", findings.len());
    Ok(findings)
}

/// Detect SSH brute force attempts
pub async fn detect_brute_force_attempts() -> Result<Vec<Finding>> {
    info!("🔍 Detecting SSH brute force attempts...");
    let mut findings = Vec::new();

    // Common auth log locations
    let auth_logs = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"];

    // Regex patterns for SSH events (compile once, use for all logs)
    let failed_password_re =
        Regex::new(r"Failed password for (?:invalid user )?(\w+) from ([\d.]+)").unwrap();
    let accepted_key_re = Regex::new(r"Accepted publickey for (\w+) from ([\d.]+)").unwrap();
    let accepted_password_re = Regex::new(r"Accepted password for (\w+) from ([\d.]+)").unwrap();

    for log_path in &auth_logs {
        if let Ok(log_content) = fs::read_to_string(log_path) {
            debug!("Analyzing auth log: {}", log_path);

            // Track failed attempts per IP
            let mut failed_attempts: HashMap<String, Vec<String>> = HashMap::new();
            let mut successful_logins: Vec<(String, String)> = Vec::new();

            // Parse log file (analyze last 10000 lines for performance)
            let lines: Vec<&str> = log_content.lines().collect();
            let start_line = if lines.len() > 10000 {
                lines.len() - 10000
            } else {
                0
            };

            for line in &lines[start_line..] {
                // Track failed password attempts
                if let Some(captures) = failed_password_re.captures(line) {
                    let user = captures[1].to_string();
                    let ip = captures[2].to_string();

                    failed_attempts.entry(ip.clone()).or_default().push(user);
                }

                // Track successful logins
                if let Some(captures) = accepted_key_re.captures(line) {
                    let user = captures[1].to_string();
                    let ip = captures[2].to_string();
                    successful_logins.push((user, ip));
                } else if let Some(captures) = accepted_password_re.captures(line) {
                    let user = captures[1].to_string();
                    let ip = captures[2].to_string();
                    successful_logins.push((user, ip));
                }
            }

            // Analyze failed attempts
            for (ip, users) in &failed_attempts {
                let attempt_count = users.len();

                if attempt_count > 50 {
                    findings.push(
                        Finding::critical(
                            "brute_force",
                            "Active SSH Brute Force Attack",
                            &format!(
                                "IP {} has {} failed SSH login attempts. Attempted users: {:?}",
                                ip,
                                attempt_count,
                                users.iter().take(5).collect::<Vec<_>>()
                            ),
                        )
                        .with_remediation(&format!(
                            "Block IP immediately: sudo iptables -A INPUT -s {} -j DROP",
                            ip
                        )),
                    );
                } else if attempt_count > 10 {
                    findings.push(
                        Finding::high(
                            "brute_force",
                            "Possible SSH Brute Force Attack",
                            &format!("IP {} has {} failed SSH login attempts", ip, attempt_count),
                        )
                        .with_remediation(&format!(
                            "Monitor or block IP: sudo fail2ban-client set sshd banip {}",
                            ip
                        )),
                    );
                }
            }

            // Check for successful logins from suspicious IPs
            for (user, ip) in &successful_logins {
                // If IP had many failed attempts but then succeeded
                if let Some(failed) = failed_attempts.get(ip) {
                    if failed.len() > 5 {
                        findings.push(
                            Finding::critical(
                                "brute_force",
                                "Successful Login After Brute Force",
                                &format!(
                                    "User '{}' successfully logged in from {} after {} failed attempts!",
                                    user,
                                    ip,
                                    failed.len()
                                ),
                            )
                            .with_remediation(&format!("Investigate immediately: Check user '{}' for compromise, review /var/log/auth.log", user)),
                        );
                    }
                }

                // Check for root logins (always suspicious)
                if user == "root" {
                    findings.push(
                        Finding::high(
                            "ssh_login",
                            "Root SSH Login Detected",
                            &format!("Root user logged in via SSH from {}", ip),
                        )
                        .with_remediation("Disable root SSH login: Set 'PermitRootLogin no' in /etc/ssh/sshd_config"),
                    );
                }
            }

            break; // Only analyze the first log file found
        }
    }

    info!("  Found {} brute force indicators", findings.len());
    Ok(findings)
}

/// Check for SSH backdoors and trojaned binaries
pub async fn check_ssh_backdoors() -> Result<Vec<Finding>> {
    info!("🔍 Checking for SSH backdoors...");
    let mut findings = Vec::new();

    // Check if SSH binary has been modified
    let ssh_binaries = ["/usr/sbin/sshd", "/usr/bin/ssh"];

    for binary in &ssh_binaries {
        if let Ok(metadata) = fs::metadata(binary) {
            if let Ok(modified) = metadata.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();

                // If SSH binary was modified recently (last 7 days), it's suspicious
                if age.as_secs() < 7 * 24 * 3600 {
                    findings.push(
                        Finding::critical(
                            "ssh_backdoor",
                            "SSH Binary Recently Modified",
                            &format!(
                                "SSH binary {} was modified {} days ago - possible trojan",
                                binary,
                                age.as_secs() / 86400
                            ),
                        )
                        .with_remediation("Reinstall OpenSSH: sudo apt-get install --reinstall openssh-server openssh-client"),
                    );
                }
            }
        }
    }

    Ok(findings)
}
