use crate::models::Finding;
use anyhow::Result;
use parking_lot::Mutex;
use procfs::process::FDTarget;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::OnceLock;
use tracing::debug;

use super::services::{fingerprint_services_batch, test_ports_parallel};
use super::SUSPICIOUS_PORTS;

/// A parsed TCP/UDP connection entry
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Connection {
    pub(super) local_ip: String,
    pub(super) local_port: u16,
    pub(super) remote_ip: String,
    pub(super) remote_port: u16,
    pub(super) state: String,
}

/// Detect if system is Internet-facing (CVSS 4.0 AV:N vs AV:A)
pub(super) async fn detect_internet_exposure() -> bool {
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
    true
}

/// Analyze TCP connections
pub(super) async fn analyze_tcp_connections(internet_exposed: bool) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let tcp_content = fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let _tcp6_content = fs::read_to_string("/proc/net/tcp6").unwrap_or_default();

    let mut listening_ports = HashSet::new();
    let mut established_connections: Vec<(String, u16, String, u16)> = Vec::new();

    // Parse IPv4 TCP — first pass for established/suspicious connections
    for line in tcp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr = parts[1];
        let remote_addr = parts[2];
        let state = parts[3];

        if let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
            (parse_proc_addr(local_addr), parse_proc_addr(remote_addr))
        {
            if state == "0A" {
                listening_ports.insert(local_port);
                if local_port > 50000 && local_port != 51820 {
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
            if state == "01" && remote_ip != "0.0.0.0" && remote_ip != "127.0.0.1" {
                established_connections.push((
                    local_ip.clone(),
                    local_port,
                    remote_ip.clone(),
                    remote_port,
                ));
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

    // Collect ports listening on all interfaces
    let mut lan_exposed_ports = Vec::new();
    let mut ports_to_test = Vec::new();

    for line in tcp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr = parts[1];
        let state = parts[3];

        if state == "0A" {
            if let Some((local_ip, local_port)) = parse_proc_addr(local_addr) {
                if local_ip == "0.0.0.0" || local_ip == "::" {
                    lan_exposed_ports.push(local_port);
                    let safe_ports = [22, 631];
                    if !safe_ports.contains(&local_port) {
                        ports_to_test.push((local_ip.clone(), local_port));
                    }
                }
            }
        }
    }

    // Batch port reachability + service fingerprinting
    let ports_only: Vec<u16> = ports_to_test.iter().map(|(_, port)| *port).collect();
    let reachability_results = test_ports_parallel("0.0.0.0", &ports_only).await;
    let service_fingerprints = fingerprint_services_batch(&ports_only);

    for (_local_ip, local_port) in ports_to_test {
        let is_reachable = reachability_results
            .get(&local_port)
            .copied()
            .unwrap_or(false);
        let service_info = service_fingerprints
            .get(&local_port)
            .cloned()
            .unwrap_or_else(|| "Unknown service".to_string());

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
pub(super) async fn analyze_udp_connections() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let udp_content = fs::read_to_string("/proc/net/udp").unwrap_or_default();

    for line in udp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr = parts[1];
        if let Some((local_ip, local_port)) = parse_proc_addr(local_addr) {
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
pub(super) async fn detect_hidden_connections() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let proc_connections = parse_proc_connections();
    let procfs_connections = parse_procfs_connections();

    let mut hidden_connections = Vec::new();
    for proc_conn in &proc_connections {
        if is_likely_formatting_difference(proc_conn) {
            continue;
        }
        let found = procfs_connections
            .iter()
            .any(|procfs_conn| connections_match(proc_conn, procfs_conn));
        if !found {
            hidden_connections.push(proc_conn.clone());
        }
    }

    if hidden_connections.len() > 5 {
        let example_conns: Vec<String> = hidden_connections
            .iter()
            .take(3)
            .map(|c| {
                format!(
                    "{}:{} -> {}:{}",
                    c.local_ip, c.local_port, c.remote_ip, c.remote_port
                )
            })
            .collect();

        findings.push(
            Finding::high(
                "rootkit",
                "Hidden Network Connections Detected",
                &format!(
                    "{} connections visible in /proc/net/tcp but hidden from procfs crate view - possible rootkit. Examples: {}",
                    hidden_connections.len(),
                    example_conns.join(", ")
                ),
            )
            .with_remediation("Investigate for rootkit: Check processes for hidden connections, scan with rkhunter/chkrootkit"),
        );
    }

    Ok(findings)
}

/// Parse /proc/net/tcp and /proc/net/tcp6 into a set of connections
fn parse_proc_connections() -> HashSet<Connection> {
    let mut connections = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            if let Some(conn) = parse_proc_line(line) {
                connections.insert(conn);
            }
        }
    }
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        for line in content.lines().skip(1) {
            if let Some(conn) = parse_proc_line(line) {
                connections.insert(conn);
            }
        }
    }
    connections
}

/// Parse a single line from /proc/net/tcp
fn parse_proc_line(line: &str) -> Option<Connection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let local = parse_proc_addr(parts[1])?;
    let remote = parse_proc_addr(parts[2])?;
    let state = parts[3];
    Some(Connection {
        local_ip: local.0,
        local_port: local.1,
        remote_ip: remote.0,
        remote_port: remote.1,
        state: state.to_string(),
    })
}

/// Parse connections from procfs crate (our "second view" for cross-referencing)
fn parse_procfs_connections() -> HashSet<Connection> {
    let mut connections = HashSet::new();
    if let Ok(tcp_entries) = procfs::net::tcp() {
        for entry in tcp_entries {
            let state = match entry.state {
                procfs::net::TcpState::Established => "ESTAB",
                procfs::net::TcpState::Listen => "LISTEN",
                procfs::net::TcpState::SynSent => "SYN-SENT",
                procfs::net::TcpState::SynRecv => "SYN-RECV",
                procfs::net::TcpState::FinWait1 => "FIN-WAIT-1",
                procfs::net::TcpState::FinWait2 => "FIN-WAIT-2",
                procfs::net::TcpState::TimeWait => "TIME-WAIT",
                procfs::net::TcpState::Close => "CLOSE",
                procfs::net::TcpState::CloseWait => "CLOSE-WAIT",
                procfs::net::TcpState::LastAck => "LAST-ACK",
                procfs::net::TcpState::Closing => "CLOSING",
                _ => "UNKNOWN",
            };
            connections.insert(Connection {
                local_ip: entry.local_address.ip().to_string(),
                local_port: entry.local_address.port(),
                remote_ip: entry.remote_address.ip().to_string(),
                remote_port: entry.remote_address.port(),
                state: state.to_string(),
            });
        }
    }
    if let Ok(tcp6_entries) = procfs::net::tcp6() {
        for entry in tcp6_entries {
            connections.insert(Connection {
                local_ip: entry.local_address.ip().to_string(),
                local_port: entry.local_address.port(),
                remote_ip: entry.remote_address.ip().to_string(),
                remote_port: entry.remote_address.port(),
                state: "ESTAB".to_string(), // simplified
            });
        }
    }
    connections
}

/// Check if two connections match (ignoring state format differences)
fn connections_match(proc_conn: &Connection, ss_conn: &Connection) -> bool {
    proc_conn.local_ip == ss_conn.local_ip
        && proc_conn.local_port == ss_conn.local_port
        && proc_conn.remote_ip == ss_conn.remote_ip
        && proc_conn.remote_port == ss_conn.remote_port
}

/// Check if connection difference is likely just a formatting issue
fn is_likely_formatting_difference(conn: &Connection) -> bool {
    // IPv6 connections: our parse_proc_addr doesn't fully parse IPv6 hex
    // addresses, so all IPv6 connections show as "::" and won't match the
    // procfs crate's parsed addresses.  This is a parsing limitation, not
    // a rootkit.  Docker containers commonly use IPv6.
    if conn.local_ip == "::" || conn.remote_ip == "::" {
        return true;
    }
    if (conn.state == "0A" || conn.state == "LISTEN") && conn.local_ip == "0.0.0.0" {
        return true;
    }
    if conn.remote_ip == "0.0.0.0" && conn.remote_port == 0 {
        return true;
    }
    if conn.state == "06"
        || conn.state == "08"
        || conn.state == "TIME-WAIT"
        || conn.state == "CLOSE-WAIT"
    {
        return true;
    }
    false
}

/// Parse /proc/net address format (hex IP:port)
pub(super) fn parse_proc_addr(addr: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_hex = parts[0];
    let port_hex = parts[1];
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ip_hex.len() == 8 {
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
        Some(("::".to_string(), port))
    }
}

/// Cached inode-to-process mapping for fast lookups
struct InodeCache {
    map: HashMap<u64, (i32, String, String)>, // inode -> (pid, exe, cmdline)
}

static INODE_CACHE: OnceLock<Mutex<InodeCache>> = OnceLock::new();

/// Build the inode-to-PID mapping by scanning /proc/*/fd/ once
fn build_inode_cache() -> InodeCache {
    let mut map = HashMap::new();

    if let Ok(all_procs) = procfs::process::all_processes() {
        for proc in all_procs.flatten() {
            if let Ok(fds) = proc.fd() {
                let pid = proc.pid;
                // Lazily compute exe and cmdline only if we find socket inodes
                let mut exe_cached = None;
                let mut cmdline_cached = None;

                for fd_info in fds.flatten() {
                    if let FDTarget::Socket(sock_inode) = fd_info.target {
                        // Lazily compute exe
                        let exe = exe_cached.get_or_insert_with(|| {
                            proc.exe()
                                .ok()
                                .and_then(|p| p.to_str().map(|s| s.to_string()))
                                .unwrap_or_else(|| {
                                    proc.stat()
                                        .ok()
                                        .map(|s| s.comm)
                                        .unwrap_or_else(|| "unknown".to_string())
                                })
                        });
                        let cmdline = cmdline_cached.get_or_insert_with(|| {
                            proc.cmdline()
                                .ok()
                                .and_then(|c| {
                                    if c.is_empty() {
                                        None
                                    } else {
                                        Some(c.join(" "))
                                    }
                                })
                                .unwrap_or_else(|| "unknown".to_string())
                        });

                        map.insert(sock_inode, (pid, exe.clone(), cmdline.clone()));
                    }
                }
            }
        }
    }

    InodeCache { map }
}

/// Map inode to process information using cached mapping
pub(super) fn get_process_by_inode(inode: u64) -> Option<(i32, String, String)> {
    let cache = INODE_CACHE.get_or_init(|| Mutex::new(build_inode_cache()));
    let guard = cache.lock();
    guard.map.get(&inode).cloned()
}

/// Invalidate the inode cache (call at start of each scan)
pub(super) fn invalidate_inode_cache() {
    if let Some(cache) = INODE_CACHE.get() {
        let mut guard = cache.lock();
        *guard = build_inode_cache();
    }
}

/// Check if a network connection is suspicious based on process AND connection characteristics
pub(super) fn is_suspicious_network_process(
    process_name: &str,
    cmdline: &str,
) -> Option<&'static str> {
    let legitimate_patterns = [
        "--type=utility",
        "--type=renderer",
        "--type=gpu-process",
        "--user-data-dir=",
        "--enable-crash-reporter",
        "/opt/google/chrome",
        "/usr/share/discord",
        "/usr/share/code",
        "/opt/slack",
        "firefox",
        "thunderbird",
    ];

    for pattern in &legitimate_patterns {
        if cmdline.contains(pattern) {
            return None;
        }
    }

    if cmdline.contains("-i") && cmdline.contains("/dev/tcp") {
        return Some("Interactive shell redirected to /dev/tcp - REVERSE SHELL");
    }
    if cmdline.contains("bash -i") || cmdline.contains("sh -i") {
        return Some("Interactive shell with network connection - potential reverse shell");
    }
    if cmdline.contains("/dev/tcp/") || cmdline.contains("/dev/udp/") {
        return Some("Shell using /dev/tcp or /dev/udp redirection - reverse shell technique");
    }
    if process_name.contains("nc")
        || process_name.contains("ncat")
        || process_name.contains("netcat")
        || process_name.contains("socat")
    {
        return Some("Netcat/Socat - commonly used for reverse shells");
    }
    if (process_name.contains("python")
        || process_name.contains("perl")
        || process_name.contains("php"))
        && (cmdline.contains(" -c ") || cmdline.contains(" -e "))
    {
        return Some("Script interpreter with inline code and network connection");
    }
    if (process_name == "bash"
        || process_name == "sh"
        || process_name == "zsh"
        || process_name == "dash")
        && !cmdline.contains("--")
        && !cmdline.contains(".sh")
        && cmdline.len() < 50
    {
        return Some("Raw shell with network connection and short command line");
    }

    None
}
