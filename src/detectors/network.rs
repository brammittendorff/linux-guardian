use crate::models::Finding;
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use tracing::{debug, info};

/// Known malicious/suspicious ports
const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Metasploit default
    5555,  // Android Debug Bridge / backdoors
    6666,  // IRC bots
    6667,  // IRC
    6668,  // IRC
    6969,  // Backdoors
    7777,  // Backdoors
    8080,  // Common proxy/backdoor
    9999,  // Backdoors
    12345, // NetBus
    31337, // Back Orifice
    54321, // Backdoors
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

                // Check if it's a suspicious port
                if SUSPICIOUS_PORTS.contains(&local_port) {
                    findings.push(
                        Finding::high(
                            "suspicious_network",
                            "Suspicious Port Listening",
                            &format!(
                                "Service listening on suspicious port: {} (commonly used by malware/backdoors)",
                                local_port
                            ),
                        )
                        .with_remediation(&format!("Investigate: sudo lsof -i :{} && sudo netstat -tulpn | grep {}", local_port, local_port)),
                    );
                }

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
                if SUSPICIOUS_PORTS.contains(&remote_port) {
                    findings.push(
                        Finding::high(
                            "suspicious_network",
                            "Connection to Suspicious Port",
                            &format!(
                                "Established connection to suspicious port: {}:{} (commonly used by malware)",
                                remote_ip, remote_port
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
                        // CVSS 4.0: AV:N (Network) vs AV:A (Adjacent)
                        if internet_exposed {
                            findings.push(
                                Finding::critical(
                                    "network_exposure",
                                    "Service Exposed to Internet",
                                    &format!(
                                        "Port {} is listening on all interfaces (0.0.0.0) with public IP! \
                                         Remotely accessible from ANYWHERE on the Internet. \
                                         CVSS 4.0: AV:N (Network Attack Vector)",
                                        local_port
                                    ),
                                )
                                .with_remediation(&format!(
                                    "URGENT: Investigate and restrict access: sudo lsof -i :{} && sudo ufw enable && sudo ufw deny {}",
                                    local_port, local_port
                                )),
                            );
                        } else {
                            findings.push(
                                Finding::high(
                                    "network_exposure",
                                    "Service Exposed on LAN",
                                    &format!(
                                        "Port {} is listening on all interfaces (0.0.0.0). Accessible from your local network. \
                                         CVSS 4.0: AV:A (Adjacent Network Attack Vector)",
                                        local_port
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate: sudo lsof -i :{} && sudo ufw enable (to block external access)",
                                    local_port
                                )),
                            );
                        }
                    }
                }
            }
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
            if SUSPICIOUS_PORTS.contains(&local_port) {
                findings.push(
                    Finding::medium(
                        "suspicious_network",
                        "Suspicious UDP Port",
                        &format!(
                            "UDP service on suspicious port: {}:{}",
                            local_ip, local_port
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

/// Check for reverse shell indicators
pub async fn detect_reverse_shells() -> Result<Vec<Finding>> {
    info!("🔍 Checking for reverse shell indicators...");
    let findings = Vec::new();

    // Check for established connections from shell processes
    let _shell_processes = ["bash", "sh", "zsh", "fish", "dash"];

    if let Ok(tcp_content) = fs::read_to_string("/proc/net/tcp") {
        // Look for processes with suspicious network behavior
        for line in tcp_content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let state = parts[3];

            // Check for ESTABLISHED connections (01)
            if state == "01" {
                // In a full implementation, we would map the inode to a PID
                // and check if it's a shell process
                // This is simplified for now
            }
        }
    }

    Ok(findings)
}
