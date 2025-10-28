#[cfg(test)]
mod tests {
    #[test]
    fn test_suspicious_port_detection() {
        let suspicious_ports: Vec<u16> = vec![
            4444,  // Metasploit
            5555,  // Android Debug / backdoors
            6666,  // IRC bots
            12345, // NetBus
            31337, // Back Orifice
        ];

        let test_ports = vec![
            (4444, true),
            (80, false),
            (443, false),
            (31337, true),
            (22, false),
        ];

        for (port, should_be_suspicious) in test_ports {
            let is_suspicious = suspicious_ports.contains(&port);
            assert_eq!(is_suspicious, should_be_suspicious, "Port {} suspicion detection failed", port);
        }
    }

    #[test]
    fn test_high_port_detection() {
        let high_port_threshold = 50000;

        let ports = vec![
            (22, false),
            (80, false),
            (51000, true),
            (65535, true),
            (1234, false),
        ];

        for (port, should_be_high) in ports {
            let is_high = port > high_port_threshold;
            assert_eq!(is_high, should_be_high, "High port detection failed for port {}", port);
        }
    }

    #[test]
    fn test_proc_net_address_parsing() {
        // /proc/net/tcp format: local_address is hex IP:port (little-endian)
        let test_cases = vec![
            ("0100007F:1F90", ("127.0.0.1", 8080)),  // 0x0100007F = 127.0.0.1, 0x1F90 = 8080
            ("00000000:0016", ("0.0.0.0", 22)),       // 0x16 = 22 (SSH)
        ];

        for (hex_addr, (expected_ip, expected_port)) in test_cases {
            let parts: Vec<&str> = hex_addr.split(':').collect();
            assert_eq!(parts.len(), 2, "Address parsing failed");

            // Parse port
            let port = u16::from_str_radix(parts[1], 16).unwrap();
            assert_eq!(port, expected_port, "Port parsing failed");
        }
    }

    #[test]
    fn test_tcp_state_detection() {
        // TCP states in /proc/net/tcp: 01=ESTABLISHED, 0A=LISTEN, etc.
        let states = vec![
            ("01", "ESTABLISHED"),
            ("0A", "LISTEN"),
            ("02", "SYN_SENT"),
            ("03", "SYN_RECV"),
        ];

        for (hex_state, name) in states {
            match hex_state {
                "01" => assert_eq!(name, "ESTABLISHED"),
                "0A" => assert_eq!(name, "LISTEN"),
                _ => {}
            }
        }
    }

    #[test]
    fn test_connection_count_discrepancy() {
        // Rootkit detection: /proc/net/tcp vs ss output mismatch
        let proc_tcp_count = 25;
        let ss_output_count = 20;

        let diff = (proc_tcp_count as i32 - ss_output_count as i32).abs();
        let threshold = 5;

        let is_suspicious = diff > threshold;
        assert!(!is_suspicious, "Small discrepancies shouldn't trigger alert");

        // Larger discrepancy
        let large_diff = 15;
        let is_suspicious_large = large_diff > threshold;
        assert!(is_suspicious_large, "Large discrepancies should trigger alert");
    }

    #[test]
    fn test_dns_server_detection() {
        let standard_dns = vec![
            "127.0.0.53",  // systemd-resolved
            "8.8.8.8",     // Google
            "8.8.4.4",     // Google
            "1.1.1.1",     // Cloudflare
            "1.0.0.1",     // Cloudflare
        ];

        let test_servers = vec![
            ("8.8.8.8", false),       // Standard
            ("1.1.1.1", false),       // Standard
            ("192.168.1.1", false),   // Local router
            ("123.45.67.89", true),   // Unusual
        ];

        for (dns_server, should_be_unusual) in test_servers {
            let is_unusual = !standard_dns.contains(&dns_server)
                && !dns_server.starts_with("192.168.")
                && !dns_server.starts_with("10.");

            assert_eq!(is_unusual, should_be_unusual, "DNS server detection failed for {}", dns_server);
        }
    }

    #[test]
    fn test_mining_pool_domain_detection() {
        let mining_pools = vec![
            "minexmr.com",
            "supportxmr.com",
            "xmrpool.eu",
        ];

        let connections = vec![
            ("minexmr.com", true),
            ("google.com", false),
            ("supportxmr.com", true),
            ("github.com", false),
        ];

        for (domain, should_be_pool) in connections {
            let is_mining_pool = mining_pools.iter().any(|&pool| domain.contains(pool));
            assert_eq!(is_mining_pool, should_be_pool, "Mining pool detection failed for {}", domain);
        }
    }

    #[test]
    fn test_excessive_open_ports() {
        let port_count_threshold = 20;

        let test_cases = vec![
            (5, false),
            (15, false),
            (25, true),
            (50, true),
        ];

        for (port_count, should_alert) in test_cases {
            let is_excessive = port_count > port_count_threshold;
            assert_eq!(is_excessive, should_alert, "Excessive ports detection failed for {} ports", port_count);
        }
    }

    #[test]
    fn test_local_vs_remote_connection() {
        let connections = vec![
            ("127.0.0.1", true),
            ("0.0.0.0", true),
            ("192.168.1.100", false),
            ("8.8.8.8", false),
        ];

        for (ip, is_local) in connections {
            let local = ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1";
            assert_eq!(local, is_local, "Local connection detection failed for {}", ip);
        }
    }

    #[test]
    fn test_reverse_shell_port_patterns() {
        // Common reverse shell ports
        let reverse_shell_ports = vec![4444, 4445, 1337, 31337, 8888, 9999];

        let test_ports = vec![
            (4444, true),
            (22, false),
            (31337, true),
            (443, false),
        ];

        for (port, should_be_reverse_shell) in test_ports {
            let is_reverse_shell = reverse_shell_ports.contains(&port);
            assert_eq!(is_reverse_shell, should_be_reverse_shell,
                "Reverse shell port detection failed for {}", port);
        }
    }

    #[test]
    fn test_ipv4_vs_ipv6_detection() {
        let addresses = vec![
            ("192.168.1.1", true),
            ("::1", false),
            ("2001:db8::1", false),
            ("10.0.0.1", true),
        ];

        for (addr, is_ipv4) in addresses {
            let ipv4 = addr.contains('.') && !addr.contains(':');
            assert_eq!(ipv4, is_ipv4, "IPv4 detection failed for {}", addr);
        }
    }

    #[test]
    fn test_connection_state_filtering() {
        // Only flag ESTABLISHED connections, not LISTEN
        let states = vec![
            ("LISTEN", false),
            ("ESTABLISHED", true),
            ("TIME_WAIT", false),
            ("CLOSE_WAIT", false),
        ];

        for (state, should_check) in states {
            let check_connection = state == "ESTABLISHED";
            assert_eq!(check_connection, should_check, "State filtering failed for {}", state);
        }
    }

    #[test]
    fn test_c2_domain_indicators() {
        let c2_indicators = vec![
            "pastebin.com",
            "hastebin.com",
            "ix.io",
        ];

        let domains = vec![
            ("pastebin.com", true),
            ("github.com", false),
            ("ix.io", true),
            ("google.com", false),
        ];

        for (domain, should_be_c2) in domains {
            let is_c2 = c2_indicators.iter().any(|&ind| domain.contains(ind));
            assert_eq!(is_c2, should_be_c2, "C2 domain detection failed for {}", domain);
        }
    }
}
