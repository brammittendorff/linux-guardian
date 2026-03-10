use crate::models::Finding;
use anyhow::Result;
use chrono::Utc;
use procfs::net::TcpState;
use std::collections::HashMap;
use std::fs;
use tracing::{debug, info};

use super::connections::{get_process_by_inode, is_suspicious_network_process};
use super::get_connection_history_path;
use super::services::fingerprint_service;
use super::{BeaconPattern, ConnectionHistory, ConnectionSnapshot};

/// Check for DNS tunneling indicators
pub async fn detect_dns_tunneling() -> Result<Vec<Finding>> {
    info!("Checking for DNS tunneling...");
    let mut findings = Vec::new();

    // Check DNS query logs if available
    // This is a simplified check
    let resolv_conf = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();

    // Check for unusual DNS servers
    for line in resolv_conf.lines() {
        if line.starts_with("nameserver") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let dns_server = parts[1];

                // Warn about non-standard DNS servers
                if dns_server != "127.0.0.53"
                    && dns_server != "8.8.8.8"
                    && dns_server != "8.8.4.4"
                    && dns_server != "1.1.1.1"
                    && dns_server != "1.0.0.1"
                    && !dns_server.starts_with("192.168.")
                    && !dns_server.starts_with("10.")
                {
                    findings.push(
                        Finding::medium(
                            "suspicious_network",
                            "Unusual DNS Server",
                            &format!("Non-standard DNS server configured: {}", dns_server),
                        )
                        .with_remediation("Verify DNS server is legitimate and not malicious"),
                    );
                }
            }
        }
    }

    Ok(findings)
}

/// Check for reverse shell indicators using procfs
pub async fn detect_reverse_shells() -> Result<Vec<Finding>> {
    info!("Checking for reverse shell indicators...");
    let mut findings = Vec::new();

    // Get all TCP connections using procfs
    if let Ok(tcp_entries) = procfs::net::tcp() {
        for entry in tcp_entries {
            // Only check ESTABLISHED connections
            if entry.state == TcpState::Established {
                // Skip localhost connections
                if entry.remote_address.ip().is_loopback() {
                    continue;
                }

                // Map inode to process
                if let Some((pid, exe, cmdline)) = get_process_by_inode(entry.inode) {
                    // Check if this process is suspicious
                    if let Some(reason) = is_suspicious_network_process(&exe, &cmdline) {
                        let remote_port = entry.remote_address.port();

                        // Common legitimate ports (HTTPS, HTTP, DNS, etc.)
                        let common_ports = [80, 443, 53, 22, 25, 587, 465, 993, 995];

                        // If connecting to common ports, require stronger evidence
                        if common_ports.contains(&remote_port) {
                            // Only flag if there's STRONG evidence (interactive shell, /dev/tcp, netcat)
                            if !reason.contains("REVERSE SHELL")
                                && !reason.contains("Netcat")
                                && !reason.contains("/dev/tcp")
                            {
                                continue; // Skip - likely false positive
                            }
                        }

                        let service_name = fingerprint_service(entry.local_address.port())
                            .unwrap_or_else(|| exe.clone());

                        findings.push(
                            Finding::critical(
                                "reverse_shell",
                                "Potential Reverse Shell Detected",
                                &format!(
                                    "{}: Process '{}' (PID {}) has ESTABLISHED connection from {}:{} to {}:{}. Command: {}",
                                    reason,
                                    service_name,
                                    pid,
                                    entry.local_address.ip(),
                                    entry.local_address.port(),
                                    entry.remote_address.ip(),
                                    remote_port,
                                    cmdline
                                ),
                            )
                            .with_remediation(&format!(
                                "URGENT: Kill process: sudo kill -9 {} && Investigate: sudo lsof -p {}",
                                pid, pid
                            )),
                        );
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        debug!("No reverse shell indicators detected");
    }

    Ok(findings)
}

/// Collect current connection statistics
pub(super) async fn collect_connection_stats() -> Result<HashMap<String, ConnectionSnapshot>> {
    let mut connections = HashMap::new();

    // Get TCP connections with traffic stats from /proc/net/tcp
    if let Ok(tcp_entries) = procfs::net::tcp() {
        for entry in tcp_entries {
            if entry.state == TcpState::Established {
                let conn_key = format!(
                    "{}:{}<->{}:{}",
                    entry.local_address.ip(),
                    entry.local_address.port(),
                    entry.remote_address.ip(),
                    entry.remote_address.port()
                );

                // Get process info
                let (pid, process_name) =
                    if let Some((p, exe, _)) = get_process_by_inode(entry.inode) {
                        (p, exe)
                    } else {
                        (-1, "unknown".to_string())
                    };

                // Get traffic stats from /proc/net/netstat or snmp
                let (tx_bytes, rx_bytes, tx_packets, rx_packets) =
                    get_connection_traffic_stats(&entry);

                let snapshot = ConnectionSnapshot {
                    local_addr: entry.local_address.ip().to_string(),
                    local_port: entry.local_address.port(),
                    remote_addr: entry.remote_address.ip().to_string(),
                    remote_port: entry.remote_address.port(),
                    pid,
                    process_name,
                    tx_bytes,
                    rx_bytes,
                    tx_packets,
                    rx_packets,
                    timestamp: Utc::now(),
                };

                connections.insert(conn_key, snapshot);
            }
        }
    }

    Ok(connections)
}

/// Get traffic statistics for a connection
fn get_connection_traffic_stats(entry: &procfs::net::TcpNetEntry) -> (u64, u64, u64, u64) {
    // Try to get stats from /proc/net/tcp (limited info available)
    // For better stats, we'd need to use netlink or eBPF

    // Basic stats available in /proc/net/tcp
    let tx_queue = entry.tx_queue;
    let rx_queue = entry.rx_queue;

    // Estimate based on queue sizes (this is approximate)
    // For production, use eBPF or netlink for accurate byte counts
    (tx_queue as u64, rx_queue as u64, 0, 0)
}

/// Detect data exfiltration based on high outbound traffic
pub(super) fn detect_data_exfiltration(snapshot: &ConnectionSnapshot) -> Option<Finding> {
    // Thresholds for suspicious data transfer
    const HIGH_UPLOAD_THRESHOLD: u64 = 100 * 1024 * 1024; // 100 MB
    const SUSPICIOUS_RATIO: f64 = 10.0; // TX:RX ratio > 10:1 is suspicious

    let tx_mb = snapshot.tx_bytes as f64 / (1024.0 * 1024.0);
    let rx_mb = snapshot.rx_bytes as f64 / (1024.0 * 1024.0);

    // Check for high outbound traffic
    if snapshot.tx_bytes > HIGH_UPLOAD_THRESHOLD {
        let ratio = if rx_mb > 0.0 { tx_mb / rx_mb } else { tx_mb };

        if ratio > SUSPICIOUS_RATIO {
            return Some(
                Finding::critical(
                    "data_exfiltration",
                    "Potential Data Exfiltration Detected",
                    &format!(
                        "Process '{}' (PID {}) has high outbound traffic to {}:{}. \
                         Uploaded: {:.2} MB, Downloaded: {:.2} MB (ratio: {:.1}:1). \
                         This pattern is consistent with data exfiltration.",
                        snapshot.process_name,
                        snapshot.pid,
                        snapshot.remote_addr,
                        snapshot.remote_port,
                        tx_mb,
                        rx_mb,
                        ratio
                    ),
                )
                .with_remediation(&format!(
                    "Investigate immediately: sudo lsof -p {} && sudo tcpdump -i any host {}",
                    snapshot.pid, snapshot.remote_addr
                )),
            );
        }
    }

    None
}

/// Detect beaconing patterns (C2 communication)
pub(super) fn detect_beaconing_patterns(
    history: &HashMap<String, ConnectionHistory>,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for conn_history in history.values() {
        if conn_history.snapshots.len() < 5 {
            continue; // Need at least 5 data points
        }

        // Calculate intervals between connections
        let mut intervals = Vec::new();
        for window in conn_history.snapshots.windows(2) {
            let interval = (window[1].timestamp - window[0].timestamp).num_seconds() as f64;
            if interval > 0.0 {
                intervals.push(interval);
            }
        }

        if intervals.is_empty() {
            continue;
        }

        // Calculate average interval and regularity
        let avg_interval: f64 = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance: f64 = intervals
            .iter()
            .map(|x| (x - avg_interval).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();

        // Coefficient of variation (lower = more regular)
        let cv = if avg_interval > 0.0 {
            std_dev / avg_interval
        } else {
            1.0
        };

        // Regularity score: 1.0 = perfect, 0.0 = random
        let regularity_score = 1.0 - cv.min(1.0);

        // Beaconing detection thresholds
        const MIN_REGULARITY: f64 = 0.7; // 70% regularity
        const MIN_INTERVAL: f64 = 5.0; // At least 5 seconds between beacons
        const MAX_INTERVAL: f64 = 3600.0; // At most 1 hour between beacons

        if regularity_score > MIN_REGULARITY
            && (MIN_INTERVAL..=MAX_INTERVAL).contains(&avg_interval)
        {
            let snapshot = &conn_history.snapshots[0];

            findings.push(
                Finding::critical(
                    "c2_beaconing",
                    "C2 Beaconing Pattern Detected",
                    &format!(
                        "Process '{}' (PID {}) shows regular beaconing to {}:{} every {:.1} seconds. \
                         Regularity: {:.0}%. Pattern count: {}. \
                         This is consistent with Command & Control (C2) communication.",
                        snapshot.process_name,
                        snapshot.pid,
                        snapshot.remote_addr,
                        snapshot.remote_port,
                        avg_interval,
                        regularity_score * 100.0,
                        intervals.len()
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Kill process: sudo kill -9 {} && Block IP: sudo ufw deny from {}",
                    snapshot.pid, snapshot.remote_addr
                )),
            );
        }

        // Suppress unused variable warning for BeaconPattern - it is defined in mod.rs for
        // potential future use.
        let _ = BeaconPattern {
            connection_key: String::new(),
            interval_seconds: Vec::new(),
            avg_interval: 0.0,
            regularity_score: 0.0,
            packet_count: 0,
        };
    }

    Ok(findings)
}

/// Load connection history from disk
pub(super) fn load_connection_history() -> Result<HashMap<String, ConnectionHistory>> {
    let path = get_connection_history_path();

    if !path.exists() {
        return Ok(HashMap::new());
    }

    let data = fs::read_to_string(&path)?;
    let history: HashMap<String, ConnectionHistory> = serde_json::from_str(&data)?;

    // Clean up old entries (keep last 24 hours)
    let cutoff = Utc::now() - chrono::Duration::hours(24);
    let filtered: HashMap<String, ConnectionHistory> = history
        .into_iter()
        .filter_map(|(k, mut v)| {
            v.snapshots.retain(|s| s.timestamp > cutoff);
            if !v.snapshots.is_empty() {
                Some((k, v))
            } else {
                None
            }
        })
        .collect();

    Ok(filtered)
}

/// Save connection history to disk
pub(super) fn save_connection_history(history: &HashMap<String, ConnectionHistory>) -> Result<()> {
    let path = get_connection_history_path();

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let data = serde_json::to_string_pretty(history)?;
    fs::write(&path, data)?;

    Ok(())
}
