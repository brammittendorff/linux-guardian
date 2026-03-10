use crate::models::Finding;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

pub mod connections;
pub mod services;
pub mod traffic;

// Re-export the 4 public async functions so callers use the same paths as before
pub use traffic::{detect_dns_tunneling, detect_reverse_shells};

/// Known malicious/suspicious ports with descriptions
pub(super) const SUSPICIOUS_PORTS: &[(u16, &str)] = &[
    (1337, "Elite/Hacker port"),
    (1999, "BackDoor trojan"),
    (3389, "RDP - often brute-forced"),
    (4444, "Metasploit default"),
    (4445, "Metasploit alternative"),
    (5555, "Android Debug Bridge / backdoors"),
    (5900, "VNC - often insecure"),
    (6666, "IRC bots"),
    (6667, "IRC"),
    (6668, "IRC"),
    (6969, "Backdoors"),
    (7777, "Backdoors / Gaming servers"),
    (8080, "HTTP Proxy / Web backdoor"),
    (8888, "Alternative HTTP / Backdoor"),
    (9001, "Tor / Backdoor"),
    (9999, "Backdoors"),
    (12345, "NetBus trojan"),
    (31337, "Back Orifice / Elite"),
    (54321, "Backdoors"),
    (65535, "Max port - unusual usage"),
];

/// Connection snapshot for traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ConnectionSnapshot {
    pub(super) local_addr: String,
    pub(super) local_port: u16,
    pub(super) remote_addr: String,
    pub(super) remote_port: u16,
    pub(super) pid: i32,
    pub(super) process_name: String,
    pub(super) tx_bytes: u64,
    pub(super) rx_bytes: u64,
    pub(super) tx_packets: u64,
    pub(super) rx_packets: u64,
    pub(super) timestamp: DateTime<Utc>,
}

/// Connection history for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ConnectionHistory {
    pub(super) snapshots: Vec<ConnectionSnapshot>,
    pub(super) first_seen: DateTime<Utc>,
    pub(super) last_seen: DateTime<Utc>,
}

/// Beaconing pattern detection result
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct BeaconPattern {
    pub(super) connection_key: String,
    pub(super) interval_seconds: Vec<f64>,
    pub(super) avg_interval: f64,
    pub(super) regularity_score: f64, // 0.0 = random, 1.0 = perfect regularity
    pub(super) packet_count: usize,
}

/// Path to store connection history
pub(super) fn get_connection_history_path() -> PathBuf {
    // Use user's home directory cache, fall back to /tmp if HOME not set
    if let Ok(home) = std::env::var("HOME") {
        let cache_dir = PathBuf::from(home).join(".cache/linux-guardian");
        // Create directory if it doesn't exist
        let _ = std::fs::create_dir_all(&cache_dir);
        cache_dir.join("connection_history.json")
    } else {
        PathBuf::from("/tmp/linux-guardian-connection_history.json")
    }
}

/// Analyze network connections for suspicious activity
pub async fn analyze_connections() -> Result<Vec<Finding>> {
    info!("Analyzing network connections...");
    let mut findings = Vec::new();

    // Detect network exposure type (for CVSS 4.0 scoring)
    let internet_exposed = connections::detect_internet_exposure().await;

    // Parse TCP connections
    findings.extend(connections::analyze_tcp_connections(internet_exposed).await?);

    // Parse UDP connections
    findings.extend(connections::analyze_udp_connections().await?);

    // Check for hidden network connections
    findings.extend(connections::detect_hidden_connections().await?);

    // Check for reverse shells (process-based detection)
    findings.extend(traffic::detect_reverse_shells().await?);

    // Check for DNS tunneling
    findings.extend(traffic::detect_dns_tunneling().await?);

    info!("  Found {} network security issues", findings.len());
    Ok(findings)
}

/// Analyze network traffic patterns for data exfiltration and C2 beaconing
pub async fn analyze_traffic_patterns() -> Result<Vec<Finding>> {
    info!("Analyzing network traffic patterns...");
    let mut findings = Vec::new();

    // Get current connections with traffic stats
    let current_connections = traffic::collect_connection_stats().await?;

    // Load historical data
    let mut history = traffic::load_connection_history()?;

    // Analyze each connection
    for (conn_key, snapshot) in &current_connections {
        // Check for high data transfer (exfiltration)
        if let Some(exfil_finding) = traffic::detect_data_exfiltration(snapshot) {
            findings.push(exfil_finding);
        }

        // Add to history
        history
            .entry(conn_key.clone())
            .or_insert_with(|| ConnectionHistory {
                snapshots: Vec::new(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            })
            .snapshots
            .push(snapshot.clone());
    }

    // Detect beaconing patterns from historical data
    findings.extend(traffic::detect_beaconing_patterns(&history)?);

    // Save updated history
    traffic::save_connection_history(&history)?;

    if findings.is_empty() {
        info!("No suspicious traffic patterns detected");
    } else {
        info!("  Found {} suspicious traffic patterns", findings.len());
    }

    Ok(findings)
}
