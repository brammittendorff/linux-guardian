use crate::models::Finding;
use anyhow::Result;
use chrono::{DateTime, Utc};
use procfs::net::TcpState;
use procfs::process::FDTarget;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info};

/// Known malicious/suspicious ports with descriptions
const SUSPICIOUS_PORTS: &[(u16, &str)] = &[
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

/// Known C2 and malicious domains (sample list)
#[allow(dead_code)]
const MALICIOUS_INDICATORS: &[&str] = &[
    "pastebin.com", // Often used for C2
    "hastebin.com",
    "pastebin.pl",
    "ix.io",
    "vpn",
    "tor",
];

/// Known mining pools (from cryptominer detector)
#[allow(dead_code)]
const MINING_POOLS: &[&str] = &[
    "minexmr.com",
    "supportxmr.com",
    "pool.hashvault.pro",
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
    "monerohash.com",
    "viaxmr.com",
    "monero.crypto-pool.fr",
    "xmrpool.eu",
    "nanopool.org",
    "f2pool.com",
];

/// Connection snapshot for traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionSnapshot {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    pid: i32,
    process_name: String,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
    timestamp: DateTime<Utc>,
}

/// Connection history for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionHistory {
    snapshots: Vec<ConnectionSnapshot>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// Beaconing pattern detection result
#[derive(Debug)]
#[allow(dead_code)]
struct BeaconPattern {
    connection_key: String,
    interval_seconds: Vec<f64>,
    avg_interval: f64,
    regularity_score: f64, // 0.0 = random, 1.0 = perfect regularity
    packet_count: usize,
}

/// Path to store connection history
fn get_connection_history_path() -> PathBuf {
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
    info!("🔍 Analyzing network connections...");
    let mut findings = Vec::new();

    // Detect network exposure type (for CVSS 4.0 scoring)
    let internet_exposed = detect_internet_exposure().await;

    // Parse TCP connections
    findings.extend(analyze_tcp_connections(internet_exposed).await?);

    // Parse UDP connections
    findings.extend(analyze_udp_connections().await?);

    // Check for hidden network connections
    findings.extend(detect_hidden_connections().await?);

    // Check for reverse shells (process-based detection)
    findings.extend(detect_reverse_shells().await?);

    // Check for DNS tunneling
    findings.extend(detect_dns_tunneling().await?);

    info!("  Found {} network security issues", findings.len());
    Ok(findings)
}

/// Detect if system is Internet-facing (CVSS 4.0 AV:N vs AV:A)
async fn detect_internet_exposure() -> bool {
    // Check if we have a public IP address on any interface
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                if let Some(ip_part) = line.split_whitespace().nth(1) {
                    if let Some(ip) = ip_part.split('/').next() {
                        if is_public_ip(ip) {
                            debug!("Detected public IP: {} - system is Internet-exposed", ip);
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Check for default route indicating Internet connectivity
    // (If no public IP but has Internet route, assume NAT/behind router = LAN only)
    debug!("No public IP detected - assuming LAN-only exposure");
    false
}

/// Check if an IP address is public (not private/reserved)
fn is_public_ip(ip: &str) -> bool {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return false;
    }

    let first: u8 = octets[0].parse().unwrap_or(0);
    let second: u8 = octets[1].parse().unwrap_or(0);

    // Private ranges (RFC 1918)
    if first == 10 {
        return false; // 10.0.0.0/8
    }
    if first == 172 && (16..=31).contains(&second) {
        return false; // 172.16.0.0/12
    }
    if first == 192 && second == 168 {
        return false; // 192.168.0.0/16
    }

    // Localhost
    if first == 127 {
        return false; // 127.0.0.0/8
    }

    // Link-local
    if first == 169 && second == 254 {
        return false; // 169.254.0.0/16
    }

    // Multicast/reserved
    if first >= 224 {
        return false;
    }

    true // Public IP
}

/// Analyze TCP connections
async fn analyze_tcp_connections(internet_exposed: bool) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let tcp_content = fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let _tcp6_content = fs::read_to_string("/proc/net/tcp6").unwrap_or_default();

    // Track listening ports
    let mut listening_ports = HashSet::new();
    let mut established_connections: Vec<(String, u16, String, u16)> = Vec::new();

    // Parse IPv4 TCP
    for line in tcp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local_addr = parts[1];
        let remote_addr = parts[2];
        let state = parts[3];

        // Parse addresses
        if let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
            (parse_proc_addr(local_addr), parse_proc_addr(remote_addr))
        {
            // Check for LISTEN state (0A)
            if state == "0A" {
                listening_ports.insert(local_port);

                // Warn about unexpected high-numbered ports
                if local_port > 50000 && local_port != 51820 {
                    // 51820 is WireGuard
                    findings.push(
                        Finding::medium(
                            "suspicious_network",
                            "High-Numbered Port Listening",
                            &format!(
                                "Service listening on unusual high port: {} - verify legitimacy",
                                local_port
                            ),
                        )
                        .with_remediation(&format!("Check process: sudo lsof -i :{}", local_port)),
                    );
                }
            }

            // Check for ESTABLISHED connections (01)
            if state == "01" && remote_ip != "0.0.0.0" && remote_ip != "127.0.0.1" {
                established_connections.push((
                    local_ip.clone(),
                    local_port,
                    remote_ip.clone(),
                    remote_port,
                ));

                // Check for connections to suspicious ports
                if let Some((port, description)) =
                    SUSPICIOUS_PORTS.iter().find(|(p, _)| *p == remote_port)
                {
                    findings.push(
                        Finding::high(
                            "suspicious_network",
                            "Connection to Suspicious Port",
                            &format!(
                                "Established connection to suspicious port {}:{} - {}. Commonly used by malware.",
                                remote_ip, port, description
                            ),
                        )
                        .with_remediation("Investigate process making this connection"),
                    );
                }
            }
        }
    }

    // Check for ports exposed on all interfaces (0.0.0.0 = LAN accessible!)
    let mut lan_exposed_ports = Vec::new();
    let mut ports_to_test = Vec::new();

    // First pass: collect all ports that need testing
    for line in tcp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local_addr = parts[1];
        let state = parts[3];

        // Check for LISTEN state (0A)
        if state == "0A" {
            if let Some((local_ip, local_port)) = parse_proc_addr(local_addr) {
                // Check if listening on all interfaces (0.0.0.0 = LAN accessible!)
                if local_ip == "0.0.0.0" || local_ip == "::" {
                    lan_exposed_ports.push(local_port);

                    // Skip well-known safe services
                    let safe_ports = [22, 631]; // SSH, CUPS (localhost usually)
                    if !safe_ports.contains(&local_port) {
                        ports_to_test.push((local_ip.clone(), local_port));
                    }
                }
            }
        }
    }

    // Batch operations for much better performance
    let ports_only: Vec<u16> = ports_to_test.iter().map(|(_, port)| *port).collect();
    let reachability_results = test_ports_parallel("0.0.0.0", &ports_only).await;
    let service_fingerprints = fingerprint_services_batch(&ports_only);

    // Second pass: generate findings with pre-computed results
    for (_local_ip, local_port) in ports_to_test {
        let is_reachable = reachability_results
            .get(&local_port)
            .copied()
            .unwrap_or(false);
        let service_info = service_fingerprints
            .get(&local_port)
            .cloned()
            .unwrap_or_else(|| "Unknown service".to_string());

        // CVSS 4.0: AV:N (Network) vs AV:A (Adjacent)
        if internet_exposed {
            let severity = if is_reachable {
                "CONFIRMED reachable"
            } else {
                "possibly firewalled"
            };

            findings.push(
                Finding::critical(
                    "network_exposure",
                    "Service Exposed to Internet",
                    &format!(
                        "Port {} is listening on all interfaces (0.0.0.0) with public IP ({})! \
                         Service: {}. \
                         Remotely accessible from ANYWHERE on the Internet. \
                         CVSS 4.0: AV:N (Network Attack Vector)",
                        local_port, severity, service_info
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Investigate and restrict access: sudo lsof -i :{} && sudo ufw enable && sudo ufw deny {}",
                    local_port, local_port
                )),
            );
        } else {
            let status = if is_reachable {
                "Reachable"
            } else {
                "Listening but may be firewalled"
            };

            findings.push(
                Finding::high(
                    "network_exposure",
                    "Service Exposed on LAN",
                    &format!(
                        "Port {} is listening on all interfaces (0.0.0.0). Status: {}. \
                         Service: {}. \
                         Accessible from your local network. \
                         CVSS 4.0: AV:A (Adjacent Network Attack Vector)",
                        local_port, status, service_info
                    ),
                )
                .with_remediation(&format!(
                    "Investigate: sudo lsof -i :{} && sudo ufw enable (to block external access)",
                    local_port
                )),
            );
        }
    }

    if lan_exposed_ports.len() > 5
        && findings
            .iter()
            .filter(|f| f.category == "network_exposure")
            .count()
            > 0
    {
        // CVSS 4.0: Multiple exposure increases severity
        if internet_exposed {
            findings.push(
                Finding::critical(
                    "network_exposure",
                    "Multiple Services Exposed to Internet",
                    &format!(
                        "{} ports listening on all interfaces (0.0.0.0) with public IP: {:?}. \
                         Remotely accessible from ANYWHERE on the Internet! \
                         CVSS 4.0: AV:N (Network) - Large attack surface",
                        lan_exposed_ports.len(),
                        lan_exposed_ports.iter().take(10).collect::<Vec<_>>()
                    ),
                )
                .with_remediation("URGENT: Enable firewall immediately: sudo ufw enable && sudo ufw default deny incoming"),
            );
        } else {
            findings.push(
                Finding::high(
                    "network_exposure",
                    "Multiple Services Exposed on LAN",
                    &format!(
                        "{} ports listening on all interfaces (0.0.0.0): {:?}. \
                         CVSS 4.0: AV:A (Adjacent) - Accessible from local network",
                        lan_exposed_ports.len(),
                        lan_exposed_ports.iter().take(10).collect::<Vec<_>>()
                    ),
                )
                .with_remediation("Enable firewall to restrict access: sudo ufw enable && sudo ufw default deny incoming"),
            );
        }
    }

    // Check for too many listening ports
    if listening_ports.len() > 20 {
        findings.push(
            Finding::medium(
                "suspicious_network",
                "Excessive Open Ports",
                &format!(
                    "System has {} listening ports - large attack surface",
                    listening_ports.len()
                ),
            )
            .with_remediation("Review and close unnecessary services: sudo netstat -tulpn"),
        );
    }

    debug!(
        "Found {} listening ports ({} on 0.0.0.0/LAN), {} established connections",
        listening_ports.len(),
        lan_exposed_ports.len(),
        established_connections.len()
    );

    Ok(findings)
}

/// Analyze UDP connections
async fn analyze_udp_connections() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let udp_content = fs::read_to_string("/proc/net/udp").unwrap_or_default();

    // Parse UDP
    for line in udp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let local_addr = parts[1];

        if let Some((local_ip, local_port)) = parse_proc_addr(local_addr) {
            // Check for suspicious UDP ports
            if let Some((port, description)) =
                SUSPICIOUS_PORTS.iter().find(|(p, _)| *p == local_port)
            {
                findings.push(
                    Finding::medium(
                        "suspicious_network",
                        "Suspicious UDP Port",
                        &format!(
                            "UDP service on suspicious port {}:{} - {}",
                            local_ip, port, description
                        ),
                    )
                    .with_remediation(&format!("Investigate: sudo lsof -i udp:{}", local_port)),
                );
            }
        }
    }

    Ok(findings)
}

/// Detect hidden network connections (rootkit indicator)
async fn detect_hidden_connections() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Compare /proc/net output with netstat/ss output
    // This is a simplified check - a real implementation would be more thorough

    // Count connections from /proc
    let tcp_content = fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let proc_tcp_count = tcp_content.lines().count() - 1; // Subtract header

    // Try to use ss or netstat
    let output = std::process::Command::new("ss").args(["-tan"]).output();

    if let Ok(output) = output {
        let ss_output = String::from_utf8_lossy(&output.stdout);
        let ss_count = ss_output.lines().count().saturating_sub(1);

        // If there's a significant discrepancy, it might indicate hidden connections
        let diff = (proc_tcp_count as i32 - ss_count as i32).abs();
        if diff > 5 {
            findings.push(
                Finding::high(
                    "rootkit",
                    "Connection Count Mismatch",
                    &format!(
                        "Discrepancy between /proc/net/tcp ({}) and ss output ({}) - possible hidden connections",
                        proc_tcp_count, ss_count
                    ),
                )
                .with_remediation("Investigate for rootkit: Compare 'ss -tan' with /proc/net/tcp"),
            );
        }
    }

    Ok(findings)
}

/// Parse /proc/net address format (hex IP:port)
fn parse_proc_addr(addr: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    // Parse hex IP
    let ip_hex = parts[0];
    let port_hex = parts[1];

    // Parse port
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // Parse IP (little-endian hex)
    if ip_hex.len() == 8 {
        // IPv4
        let ip_num = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = format!(
            "{}.{}.{}.{}",
            ip_num & 0xFF,
            (ip_num >> 8) & 0xFF,
            (ip_num >> 16) & 0xFF,
            (ip_num >> 24) & 0xFF
        );
        Some((ip, port))
    } else {
        // IPv6 or other - simplified handling
        Some(("::".to_string(), port))
    }
}

/// Map inode to process information using procfs crate
fn get_process_by_inode(inode: u64) -> Option<(i32, String, String)> {
    // Iterate through all processes
    if let Ok(all_procs) = procfs::process::all_processes() {
        for proc in all_procs.flatten() {
            // Check file descriptors
            if let Ok(fds) = proc.fd() {
                for fd_info in fds.flatten() {
                    // Check if this fd is a socket with matching inode
                    if let FDTarget::Socket(sock_inode) = fd_info.target {
                        if sock_inode == inode {
                            // Found the process!
                            let cmdline = proc
                                .cmdline()
                                .ok()
                                .and_then(|c| {
                                    if c.is_empty() {
                                        None
                                    } else {
                                        Some(c.join(" "))
                                    }
                                })
                                .unwrap_or_else(|| "unknown".to_string());

                            let exe = proc
                                .exe()
                                .ok()
                                .and_then(|p| p.to_str().map(|s| s.to_string()))
                                .unwrap_or_else(|| {
                                    proc.stat()
                                        .ok()
                                        .map(|s| s.comm)
                                        .unwrap_or_else(|| "unknown".to_string())
                                });

                            return Some((proc.pid, exe, cmdline));
                        }
                    }
                }
            }
        }
    }

    None
}

/// Check if a process name is suspicious for having network connections
/// Check if a network connection is suspicious based on process AND connection characteristics
fn is_suspicious_network_process(process_name: &str, cmdline: &str) -> Option<&'static str> {
    // First, check for legitimate application patterns (whitelist)
    let legitimate_patterns = [
        "--type=utility",          // Chromium/Electron utility processes
        "--type=renderer",         // Chromium/Electron renderer
        "--type=gpu-process",      // Chromium/Electron GPU
        "--user-data-dir=",        // Browser/Electron apps
        "--enable-crash-reporter", // Electron apps with crash reporting
        "/opt/google/chrome",      // Chrome
        "/usr/share/discord",      // Discord
        "/usr/share/code",         // VS Code
        "/opt/slack",              // Slack
        "firefox",                 // Firefox
        "thunderbird",             // Thunderbird
    ];

    for pattern in &legitimate_patterns {
        if cmdline.contains(pattern) {
            return None; // Legitimate app, not suspicious
        }
    }

    // Now check for actually suspicious patterns
    // These are STRONG indicators of reverse shells
    if cmdline.contains("-i") && cmdline.contains("/dev/tcp") {
        return Some("Interactive shell redirected to /dev/tcp - REVERSE SHELL");
    }

    if cmdline.contains("bash -i") || cmdline.contains("sh -i") {
        return Some("Interactive shell with network connection - potential reverse shell");
    }

    if cmdline.contains("/dev/tcp/") || cmdline.contains("/dev/udp/") {
        return Some("Shell using /dev/tcp or /dev/udp redirection - reverse shell technique");
    }

    // Netcat/socat are highly suspicious
    if process_name.contains("nc")
        || process_name.contains("ncat")
        || process_name.contains("netcat")
        || process_name.contains("socat")
    {
        return Some("Netcat/Socat - commonly used for reverse shells");
    }

    // Script interpreters with inline code execution (-c, -e)
    if (process_name.contains("python")
        || process_name.contains("perl")
        || process_name.contains("php"))
        && (cmdline.contains(" -c ") || cmdline.contains(" -e "))
    {
        return Some("Script interpreter with inline code and network connection");
    }

    // Raw shell processes with network connections (but not part of legitimate apps)
    // Only flag if it's JUST a shell, not part of a larger command
    if (process_name == "bash" || process_name == "sh" || process_name == "zsh" || process_name == "dash")
        && !cmdline.contains("--") // Not a flag-based command
        && !cmdline.contains(".sh") // Not running a script file
        && cmdline.len() < 50
    // Short command line = suspicious
    {
        return Some("Raw shell with network connection and short command line");
    }

    None
}

/// Test if a port is actually reachable from external network
fn test_port_reachability(ip: &str, port: u16) -> bool {
    // Only test if it's listening on 0.0.0.0 (all interfaces)
    if ip != "0.0.0.0" && ip != "::" {
        return false;
    }

    // Get the actual IP to test against
    let test_ips = get_local_ips();

    for test_ip in test_ips {
        // Try to connect to ourselves
        let addr_str = format!("{}:{}", test_ip, port);
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            // Reduced timeout for local connections: 100ms instead of 500ms
            match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
                Ok(_) => {
                    debug!("Port {} is reachable on {}", port, test_ip);
                    return true;
                }
                Err(_) => {
                    // Connection failed - might be firewalled
                    continue;
                }
            }
        }
    }

    false
}

/// Test multiple ports in parallel (much faster)
async fn test_ports_parallel(ip: &str, ports: &[u16]) -> HashMap<u16, bool> {
    use futures::future::join_all;

    let ip_owned = ip.to_string();
    let futures: Vec<_> = ports
        .iter()
        .map(|&port| {
            let ip = ip_owned.clone();
            tokio::spawn(async move { (port, test_port_reachability(&ip, port)) })
        })
        .collect();

    let results = join_all(futures).await;
    results.into_iter().filter_map(|r| r.ok()).collect()
}

/// Batch fingerprint all services at once (much faster than individual lsof calls)
fn fingerprint_services_batch(ports: &[u16]) -> HashMap<u16, String> {
    let mut result = HashMap::new();

    // Single lsof call for ALL TCP ports
    if let Ok(output) = std::process::Command::new("lsof")
        .args(["-iTCP", "-sTCP:LISTEN", "-n", "-P"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 9 {
                    let command = parts[0];
                    let user = parts[2];
                    let name = parts[8]; // NAME column has format like *:8080 or *:http

                    // Extract port from NAME column
                    if let Some(port_str) = name.split(':').next_back() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if ports.contains(&port) {
                                let service_info = match command.to_lowercase().as_str() {
                                    "nginx" => "Nginx web server",
                                    "apache2" | "httpd" => "Apache web server",
                                    "sshd" => "OpenSSH server",
                                    "mysqld" => "MySQL database",
                                    "postgres" => "PostgreSQL database",
                                    "redis-ser" | "redis" => "Redis server",
                                    "docker-pr" => {
                                        // Docker proxy detected - try to identify actual service via banner
                                        if let Some(banner) = grab_banner(port) {
                                            let actual_service = identify_service_from_banner(&banner, port);
                                            // Only use banner if it's more specific than generic Docker proxy
                                            if !actual_service.contains("Unknown") && !actual_service.is_empty() {
                                                result.insert(port, format!("{} (Docker container)", actual_service));
                                                continue;
                                            }
                                        }
                                        "Docker proxy"
                                    }
                                    "bzfs" => "BZFlag game server",
                                    "python" | "python3" => "Python application",
                                    "node" => "Node.js application",
                                    "java" => "Java application",
                                    "nc" | "ncat" | "netcat" => "⚠️  NETCAT - Potential backdoor!",
                                    "bash" | "sh" | "zsh" => "⚠️  SHELL - Potential reverse shell!",
                                    _ => command,
                                };
                                result.insert(port, format!("{} (user: {})", service_info, user));
                            }
                        }
                    }
                }
            }
        }
    }

    // For ports not found by lsof, try banner grabbing or use port-based detection
    for &port in ports {
        if let std::collections::hash_map::Entry::Vacant(e) = result.entry(port) {
            let banner = grab_banner(port).unwrap_or_default();
            // Always identify service - will use port-based fallback if banner is empty
            let identified_service = identify_service_from_banner(&banner, port);
            e.insert(identified_service);
        }
    }

    result
}

/// Identify service from banner text
fn identify_service_from_banner(banner: &str, port: u16) -> String {
    let banner_lower = banner.to_lowercase();

    // Check for specific service signatures in headers
    if banner_lower.contains("server: minio") {
        return "MinIO S3-compatible object storage".to_string();
    }

    if banner_lower.contains("mailhog") {
        return "MailHog (email testing tool)".to_string();
    }

    if banner_lower.contains("220 ") && banner_lower.contains("smtp") {
        if banner_lower.contains("mailhog") {
            return "MailHog SMTP server (email testing)".to_string();
        }
        return format!("SMTP mail server - {}", banner.trim());
    }

    if banner_lower.contains("nginx") {
        if let Some(version) = extract_version(&banner_lower, "nginx/") {
            return format!("Nginx web server v{}", version);
        }
        return "Nginx web server".to_string();
    }

    if banner_lower.contains("apache") {
        return "Apache web server".to_string();
    }

    if banner_lower.contains("postgresql") || banner_lower.contains("postgres") {
        return "PostgreSQL database".to_string();
    }

    if banner_lower.contains("mysql") {
        return "MySQL database".to_string();
    }

    if banner_lower.contains("redis") {
        return "Redis server".to_string();
    }

    if banner_lower.contains("mongodb") {
        return "MongoDB database".to_string();
    }

    if banner_lower.contains("ssh-") {
        return "OpenSSH server".to_string();
    }

    // Check for Server header pattern
    if banner_lower.contains("server:") {
        for line in banner.lines() {
            if line.to_lowercase().starts_with("server:") {
                let server = line.split(':').nth(1).unwrap_or("").trim();
                if !server.is_empty() {
                    return format!("HTTP server: {}", server);
                }
            }
        }
    }

    if banner_lower.contains("http/") {
        return format!("HTTP server - {}", banner.lines().next().unwrap_or(banner).trim());
    }

    // VNC protocol detection
    if banner_lower.starts_with("rfb ") {
        return format!("VNC server ({})", banner.trim());
    }

    // Selenium Grid detection
    if banner_lower.contains("selenium") {
        return "Selenium Grid (browser automation)".to_string();
    }

    // Check by port number if banner is unclear
    match port {
        80 | 8080 | 8000 => {
            if !banner.is_empty() && banner.len() < 100 {
                format!("HTTP service - {}", banner.trim())
            } else {
                "HTTP web server".to_string()
            }
        }
        443 | 8443 => "HTTPS service".to_string(),
        5432 => {
            // PostgreSQL - check if banner contains postgres or just use port knowledge
            if banner_lower.contains("postgres") || banner_lower.contains("postgresql") {
                "PostgreSQL database".to_string()
            } else if !banner.is_empty() && banner.len() < 50 {
                format!("PostgreSQL database - {}", banner.trim())
            } else {
                "PostgreSQL database (port 5432)".to_string()
            }
        }
        3306 => "MySQL database".to_string(),
        6379 => "Redis server".to_string(),
        27017 => "MongoDB".to_string(),
        5900..=5999 => format!("VNC server - {}", banner.trim()),
        1025 => "SMTP server (likely MailHog)".to_string(),
        8025 => "MailHog HTTP API (email testing)".to_string(),
        9000 => "MinIO API (S3-compatible storage)".to_string(),
        9001 => "MinIO Console (web UI)".to_string(),
        4442 | 4443 => "Selenium Grid Node (browser automation)".to_string(),
        4444 => {
            // Selenium Hub typically on 4444
            if banner_lower.contains("selenium") || banner_lower.contains("grid") {
                "Selenium Grid Hub (browser automation)".to_string()
            } else if !banner.is_empty() && banner.len() < 100 {
                format!("Selenium Grid Hub - {}", banner.trim())
            } else {
                "Selenium Grid Hub (port 4444)".to_string()
            }
        }
        _ => {
            // Return banner with "Unknown service" prefix for truly unknown services
            if banner.is_empty() || banner.chars().all(|c| !c.is_ascii_alphanumeric()) {
                "Unknown service".to_string()
            } else {
                format!("Unknown: {}", banner.trim())
            }
        }
    }
}

/// Extract version number from banner text
fn extract_version(text: &str, prefix: &str) -> Option<String> {
    if let Some(start) = text.find(prefix) {
        let after_prefix = &text[start + prefix.len()..];
        let version: String = after_prefix
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() {
            return Some(version);
        }
    }
    None
}

/// Fingerprint a service on a port by checking process and banner grabbing
fn fingerprint_service(port: u16) -> Option<String> {
    // First, try to identify the process using lsof
    if let Ok(output) = std::process::Command::new("lsof")
        .args(["-i", &format!(":{}", port), "-n", "-P"])
        .output()
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines().skip(1) {
                // lsof output format: COMMAND  PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    let command = parts[0];
                    let user = if parts.len() >= 3 {
                        parts[2]
                    } else {
                        "unknown"
                    };

                    // Identify common services
                    let service_info = match command.to_lowercase().as_str() {
                        "nginx" => "Nginx web server",
                        "apache2" | "httpd" => "Apache web server",
                        "sshd" => "OpenSSH server",
                        "mysqld" => "MySQL database",
                        "postgres" => "PostgreSQL database",
                        "redis-ser" | "redis" => "Redis server",
                        "docker-pr" => "Docker proxy",
                        "bzfs" => "BZFlag game server",
                        "python" | "python3" => "Python application",
                        "node" => "Node.js application",
                        "java" => "Java application",
                        "nc" | "ncat" | "netcat" => "⚠️  NETCAT - Potential backdoor!",
                        "bash" | "sh" | "zsh" => "⚠️  SHELL - Potential reverse shell!",
                        _ => command,
                    };

                    return Some(format!("{} (user: {})", service_info, user));
                }
            }
        }
    }

    // Fallback: Try banner grabbing for common protocols
    if let Some(banner) = grab_banner(port) {
        return Some(identify_service_from_banner(&banner, port));
    }

    None
}

/// Attempt to grab a banner from a service
fn grab_banner(port: u16) -> Option<String> {
    let test_ips = get_local_ips();

    for test_ip in test_ips {
        let addr_str = format!("{}:{}", test_ip, port);
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .ok()?;

                // Read banner (some services send immediately)
                let mut buffer = [0u8; 1024];
                use std::io::Read;

                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n.min(200)]);
                        let banner = banner.trim().replace('\n', " ").replace('\r', "");
                        if !banner.is_empty() {
                            return Some(banner);
                        }
                    }
                    _ => {}
                }

                // Try sending HTTP request - many services respond to HTTP
                // Try this for common HTTP ports and any high-numbered ports
                if port == 80 || port == 443 || port >= 8000 {
                    use std::io::Write;
                    // Send HTTP HEAD request (lighter than GET)
                    stream.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n").ok()?;
                    stream.flush().ok()?;

                    if let Ok(n) = stream.read(&mut buffer) {
                        if n > 0 {
                            let response = String::from_utf8_lossy(&buffer[..n.min(1024)]);
                            if response.contains("HTTP/") {
                                let mut headers = Vec::new();

                                // Extract Server and other identifying headers
                                for line in response.lines() {
                                    let line_lower = line.to_lowercase();
                                    if line_lower.starts_with("server:") {
                                        headers.push(line.trim().to_string());
                                    } else if line_lower.starts_with("x-powered-by:") {
                                        headers.push(line.trim().to_string());
                                    } else if line_lower.starts_with("x-application:") {
                                        headers.push(line.trim().to_string());
                                    }
                                }

                                if !headers.is_empty() {
                                    return Some(headers.join("; "));
                                }
                                return Some("HTTP server".to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Get list of local IP addresses to test reachability
fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();

    // Try to get IP addresses from ip command
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                if let Some(ip_part) = line.split_whitespace().nth(1) {
                    if let Some(ip) = ip_part.split('/').next() {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }

    // Fallback to localhost if no IPs found
    if ips.is_empty() {
        ips.push("127.0.0.1".to_string());
    }

    ips
}

/// Check for DNS tunneling indicators
pub async fn detect_dns_tunneling() -> Result<Vec<Finding>> {
    info!("🔍 Checking for DNS tunneling...");
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
    info!("🔍 Checking for reverse shell indicators...");
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

/// Analyze network traffic patterns for data exfiltration and C2 beaconing
pub async fn analyze_traffic_patterns() -> Result<Vec<Finding>> {
    info!("🔍 Analyzing network traffic patterns...");
    let mut findings = Vec::new();

    // Get current connections with traffic stats
    let current_connections = collect_connection_stats().await?;

    // Load historical data
    let mut history = load_connection_history()?;

    // Analyze each connection
    for (conn_key, snapshot) in &current_connections {
        // Check for high data transfer (exfiltration)
        if let Some(exfil_finding) = detect_data_exfiltration(snapshot) {
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
    findings.extend(detect_beaconing_patterns(&history)?);

    // Save updated history
    save_connection_history(&history)?;

    if findings.is_empty() {
        debug!("No suspicious traffic patterns detected");
    } else {
        info!("  Found {} suspicious traffic patterns", findings.len());
    }

    Ok(findings)
}

/// Collect current connection statistics
async fn collect_connection_stats() -> Result<HashMap<String, ConnectionSnapshot>> {
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
fn detect_data_exfiltration(snapshot: &ConnectionSnapshot) -> Option<Finding> {
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
fn detect_beaconing_patterns(history: &HashMap<String, ConnectionHistory>) -> Result<Vec<Finding>> {
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
    }

    Ok(findings)
}

/// Load connection history from disk
fn load_connection_history() -> Result<HashMap<String, ConnectionHistory>> {
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
fn save_connection_history(history: &HashMap<String, ConnectionHistory>) -> Result<()> {
    let path = get_connection_history_path();

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let data = serde_json::to_string_pretty(history)?;
    fs::write(&path, data)?;

    Ok(())
}
