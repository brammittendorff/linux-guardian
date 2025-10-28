#[cfg(test)]
mod tests {
    #[test]
    fn test_known_miner_detection() {
        let known_miners = vec![
            "xmrig", "minerd", "cpuminer", "ccminer", "ethminer",
            "kinsing", "perfctl", "kdevtmpfsi",
        ];

        let processes = vec![
            ("xmrig", true),
            ("bash", false),
            ("kinsing_miner", true),
            ("perfctl", true),
            ("systemd", false),
        ];

        for (process_name, should_match) in processes {
            let process_lower = process_name.to_lowercase();
            let is_miner = known_miners.iter().any(|&miner| process_lower.contains(miner));
            assert_eq!(is_miner, should_match, "Process '{}' miner detection failed", process_name);
        }
    }

    #[test]
    fn test_mining_pool_detection() {
        let mining_pools = vec![
            "minexmr.com",
            "supportxmr.com",
            "pool.hashvault.pro",
            "xmrpool.eu",
        ];

        let cmdlines = vec![
            ("xmrig -o pool.minexmr.com:3333", true),
            ("/usr/bin/python script.py", false),
            ("miner --pool supportxmr.com", true),
            ("curl https://google.com", false),
        ];

        for (cmdline, should_match) in cmdlines {
            let cmdline_lower = cmdline.to_lowercase();
            let connects_to_pool = mining_pools.iter()
                .any(|&pool| cmdline_lower.contains(pool));
            assert_eq!(connects_to_pool, should_match, "Cmdline '{}' pool detection failed", cmdline);
        }
    }

    #[test]
    fn test_suspicious_process_locations() {
        let suspicious_paths = vec!["/tmp/", "/dev/shm/", "/var/tmp/"];

        let processes = vec![
            ("/tmp/malware", true),
            ("/usr/bin/python", false),
            ("/dev/shm/miner", true),
            ("/var/tmp/backdoor", true),
            ("/home/user/script.sh", false),
        ];

        for (path, should_be_suspicious) in processes {
            let is_suspicious = suspicious_paths.iter()
                .any(|&sus_path| path.starts_with(sus_path));
            assert_eq!(is_suspicious, should_be_suspicious, "Path '{}' suspicion detection failed", path);
        }
    }

    #[test]
    fn test_cpu_usage_threshold() {
        let high_cpu_threshold = 80.0;

        let processes = vec![
            ("miner", 95.0, true),
            ("chrome", 45.0, false),
            ("kworker", 85.0, true),
            ("idle", 2.0, false),
        ];

        for (name, cpu, should_flag) in processes {
            let is_high = cpu > high_cpu_threshold;
            assert_eq!(is_high, should_flag, "Process '{}' with {}% CPU flagging failed", name, cpu);
        }
    }

    #[test]
    fn test_deleted_binary_detection() {
        let paths = vec![
            ("/usr/bin/python (deleted)", true),
            ("/usr/bin/bash", false),
            ("/tmp/miner (deleted)", true),
        ];

        for (path, should_be_deleted) in paths {
            let is_deleted = path.contains("(deleted)");
            assert_eq!(is_deleted, should_be_deleted, "Path '{}' deleted detection failed", path);
        }
    }

    #[test]
    fn test_cron_miner_indicators() {
        let cron_entries = vec![
            ("*/5 * * * * /tmp/xmrig -o pool.minexmr.com", true),
            ("0 2 * * * /usr/bin/backup.sh", false),
            ("@reboot /dev/shm/miner", true),
            ("0 0 * * 0 apt-get update", false),
        ];

        let miner_keywords = vec!["xmrig", "miner", "pool", "stratum"];

        for (entry, should_be_suspicious) in cron_entries {
            let entry_lower = entry.to_lowercase();
            let is_suspicious = miner_keywords.iter()
                .any(|&keyword| entry_lower.contains(keyword));
            assert_eq!(is_suspicious, should_be_suspicious, "Cron entry suspicious detection failed");
        }
    }

    #[test]
    fn test_process_name_mimicry() {
        // Malware often mimics legitimate process names
        let suspicious_names = vec![
            "kworker",  // Real kernel workers don't run in userspace
            "[kthreadd]",
            "systemd",  // If from unusual location
        ];

        let processes = vec![
            ("kworker", true),
            ("[kthreadd]", true),
            ("python3", false),
            ("bash", false),
        ];

        for (name, might_be_mimicry) in processes {
            let is_suspicious_name = suspicious_names.iter()
                .any(|&sus| name.contains(sus));
            assert_eq!(is_suspicious_name, might_be_mimicry, "Name '{}' mimicry detection failed", name);
        }
    }

    #[test]
    fn test_cpu_calculation_logic() {
        // Simplified CPU calculation test
        let total_time: u64 = 1000; // ticks
        let uptime_ticks: u64 = 10000;

        let cpu_percentage = (total_time as f32 / uptime_ticks as f32) * 100.0;
        assert_eq!(cpu_percentage, 10.0);
    }
}
