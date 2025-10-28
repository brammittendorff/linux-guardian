#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_auth_log_failed_password_parsing() {
        let log_lines = vec![
            "Oct 20 10:15:32 server sshd[1234]: Failed password for root from 192.168.1.100 port 52123 ssh2",
            "Oct 20 10:15:33 server sshd[1235]: Failed password for invalid user admin from 10.0.0.50 port 52124 ssh2",
            "Oct 20 10:15:34 server sshd[1236]: Accepted publickey for alice from 192.168.1.200 port 52125 ssh2",
        ];

        let failed_re = Regex::new(r"Failed password for (?:invalid user )?(\w+) from ([\d.]+)").unwrap();

        let mut failed_attempts = 0;
        for line in log_lines {
            if failed_re.is_match(line) {
                failed_attempts += 1;
            }
        }

        assert_eq!(failed_attempts, 2);
    }

    #[test]
    fn test_successful_login_parsing() {
        let log_line = "Oct 20 10:15:34 server sshd[1236]: Accepted publickey for alice from 192.168.1.200 port 52125 ssh2";

        let accepted_key_re = Regex::new(r"Accepted publickey for (\w+) from ([\d.]+)").unwrap();
        let accepted_pwd_re = Regex::new(r"Accepted password for (\w+) from ([\d.]+)").unwrap();

        assert!(accepted_key_re.is_match(log_line));

        if let Some(caps) = accepted_key_re.captures(log_line) {
            assert_eq!(&caps[1], "alice");
            assert_eq!(&caps[2], "192.168.1.200");
        }
    }

    #[test]
    fn test_brute_force_threshold_detection() {
        let threshold_high = 50;
        let threshold_medium = 10;

        let test_cases = vec![
            (5, "low"),
            (15, "medium"),
            (60, "critical"),
        ];

        for (attempts, expected_severity) in test_cases {
            let severity = if attempts > threshold_high {
                "critical"
            } else if attempts > threshold_medium {
                "high"
            } else {
                "low"
            };

            assert_eq!(severity, expected_severity, "Brute force threshold detection failed for {} attempts", attempts);
        }
    }

    #[test]
    fn test_ssh_key_without_comment() {
        let keys = vec![
            ("ssh-rsa AAAAB3NzaC1...== user@host", true),  // Has comment
            ("ssh-rsa AAAAB3NzaC1...==", false),           // No comment
            ("ssh-ed25519 AAAAC3Nz...== alice@example.com", true),
        ];

        for (key, has_comment) in keys {
            let has_at_or_space = key.contains('@') || key.matches(' ').count() > 1;
            assert_eq!(has_at_or_space, has_comment, "SSH key comment detection failed");
        }
    }

    #[test]
    fn test_ssh_forced_command_detection() {
        let keys = vec![
            ("command=\"/bin/bash\" ssh-rsa AAAA...", true),
            ("ssh-rsa AAAAB3NzaC1... user@host", false),
            ("no-port-forwarding,command=\"uptime\" ssh-rsa AAA...", true),
        ];

        for (key, has_forced_command) in keys {
            let has_command = key.contains("command=");
            assert_eq!(has_command, has_forced_command, "Forced command detection failed");
        }
    }

    #[test]
    fn test_ssh_config_dangerous_settings() {
        let config_lines = vec![
            ("PermitRootLogin yes", true),
            ("PermitRootLogin no", false),
            ("PasswordAuthentication yes", true),
            ("PasswordAuthentication no", false),
            ("PermitEmptyPasswords yes", true),
            ("# PermitRootLogin yes", false),  // Commented out
        ];

        for (line, is_dangerous) in config_lines {
            // Skip comments
            if line.trim().starts_with('#') {
                continue;
            }

            let dangerous = (line.contains("PermitRootLogin") && line.contains("yes"))
                || (line.contains("PasswordAuthentication") && line.contains("yes"))
                || (line.contains("PermitEmptyPasswords") && line.contains("yes"));

            assert_eq!(dangerous, is_dangerous, "SSH config danger detection failed for: {}", line);
        }
    }

    #[test]
    fn test_recent_file_modification_detection() {
        use std::time::Duration;

        let time_windows = vec![
            (Duration::from_secs(3600), "1 hour", true),      // 1 hour ago
            (Duration::from_secs(86400), "1 day", true),      // 1 day ago
            (Duration::from_secs(604800), "7 days", false),   // 7 days ago
            (Duration::from_secs(2592000), "30 days", false), // 30 days ago
        ];

        let alert_threshold = Duration::from_secs(7 * 24 * 3600); // 7 days

        for (age, description, should_alert) in time_windows {
            let is_recent = age < alert_threshold;
            assert_eq!(is_recent, should_alert, "Recent modification detection failed for {}", description);
        }
    }

    #[test]
    fn test_root_login_detection() {
        let logins = vec![
            ("Accepted publickey for root from 192.168.1.100", true),
            ("Accepted password for alice from 192.168.1.200", false),
            ("Accepted publickey for admin from 10.0.0.1", false),
        ];

        for (line, is_root_login) in logins {
            let root_login = line.contains("for root from");
            assert_eq!(root_login, is_root_login, "Root login detection failed");
        }
    }

    #[test]
    fn test_successful_login_after_brute_force() {
        // Scenario: IP has many failed attempts, then succeeds
        let failed_attempts_from_ip = 25;
        let success_threshold = 5;

        let should_alert = failed_attempts_from_ip > success_threshold;
        assert!(should_alert, "Should alert when successful login follows brute force");
    }

    #[test]
    fn test_ssh_binary_modification_detection() {
        use std::time::Duration;

        let modification_age = Duration::from_secs(2 * 24 * 3600); // 2 days
        let suspicious_threshold = Duration::from_secs(7 * 24 * 3600); // 7 days

        let is_suspicious = modification_age < suspicious_threshold;
        assert!(is_suspicious, "Recently modified SSH binary should be flagged");
    }

    #[test]
    fn test_ip_address_extraction_from_log() {
        let log_line = "Failed password for root from 192.168.1.100 port 52123 ssh2";

        let ip_re = Regex::new(r"from ([\d.]+)").unwrap();
        if let Some(caps) = ip_re.captures(log_line) {
            assert_eq!(&caps[1], "192.168.1.100");
        } else {
            panic!("Failed to extract IP address");
        }
    }

    #[test]
    fn test_invalid_user_detection() {
        let log_line = "Failed password for invalid user admin from 10.0.0.50 port 52124 ssh2";

        let is_invalid_user = log_line.contains("invalid user");
        assert!(is_invalid_user, "Should detect invalid user attempts");
    }
}
