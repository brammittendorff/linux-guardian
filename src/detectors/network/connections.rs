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

/// Detect hidden network connections (rootkit indicator).
///
/// Compares two independent data sources:
///   1. /proc/net/tcp (procfs — virtual filesystem)
///   2. `ss -tna` (netlink — kernel socket API)
///
/// A rootkit that hides connections must hook BOTH interfaces. If connections
/// appear in one source but not the other, that's suspicious. However, on
/// high-traffic servers (Plex, web servers) connections are created/destroyed
/// rapidly, so we must account for the race condition between the two reads.
///
/// Strategy:
/// - Read both sources as close together as possible
/// - Only flag if a LISTENING socket is hidden (these are stable, not transient)
/// - For ESTABLISHED connections, require a large discrepancy to flag
pub(super) async fn detect_hidden_connections() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Read both sources back-to-back to minimize race window
    let proc_connections = parse_proc_connections();
    let ss_connections = parse_ss_connections();

    // If ss failed to run, we can't compare
    if ss_connections.is_empty() {
        debug!("Could not get ss output, skipping hidden connection detection");
        return Ok(findings);
    }

    // Check for LISTENING sockets in /proc/net/tcp that are NOT in ss output.
    // Listening sockets are stable (not transient) so hiding them is a strong
    // rootkit indicator.
    let mut hidden_listeners = Vec::new();
    for proc_conn in &proc_connections {
        // Only check listeners (state "0A" = LISTEN in /proc/net/tcp hex)
        if proc_conn.state != "0A" {
            continue;
        }
        // Skip IPv6 (formatting differences cause false matches)
        if proc_conn.local_ip == "::" || proc_conn.local_ip.contains(':') {
            continue;
        }
        let found_in_ss = ss_connections
            .iter()
            .any(|ss_conn| connections_match(proc_conn, ss_conn));
        if !found_in_ss {
            hidden_listeners.push(proc_conn.clone());
        }
    }

    if !hidden_listeners.is_empty() {
        let example_conns: Vec<String> = hidden_listeners
            .iter()
            .take(5)
            .map(|c| format!("{}:{}", c.local_ip, c.local_port))
            .collect();

        findings.push(
            Finding::high(
                "rootkit",
                "Hidden Listening Sockets Detected",
                &format!(
                    "{} listening socket(s) visible in /proc/net/tcp but hidden from \
                     netlink (ss). A rootkit may be hiding network services. \
                     Hidden listeners: {}",
                    hidden_listeners.len(),
                    example_conns.join(", ")
                ),
            )
            .with_remediation(
                "Investigate for rootkit: sudo ss -tlnp && cat /proc/net/tcp && scan with rkhunter/chkrootkit",
            ),
        );
    }

    // Also check reverse: ss shows connections that /proc/net/tcp doesn't.
    // This would indicate procfs is being tampered with to hide connections.
    let mut hidden_from_proc = Vec::new();
    for ss_conn in &ss_connections {
        // Only check listeners for the same stability reason
        if !ss_conn.state.contains("LISTEN") {
            continue;
        }
        if ss_conn.local_ip == "::" || ss_conn.local_ip.contains(':') {
            continue;
        }
        let found_in_proc = proc_connections
            .iter()
            .any(|proc_conn| connections_match(ss_conn, proc_conn));
        if !found_in_proc {
            hidden_from_proc.push(ss_conn.clone());
        }
    }

    if !hidden_from_proc.is_empty() {
        let example_conns: Vec<String> = hidden_from_proc
            .iter()
            .take(5)
            .map(|c| format!("{}:{}", c.local_ip, c.local_port))
            .collect();

        findings.push(
            Finding::critical(
                "rootkit",
                "Procfs Tampering — Connections Hidden from /proc/net/tcp",
                &format!(
                    "{} listening socket(s) visible via netlink (ss) but MISSING from \
                     /proc/net/tcp. This is a strong rootkit indicator — something is \
                     intercepting procfs reads. Hidden: {}",
                    hidden_from_proc.len(),
                    example_conns.join(", ")
                ),
            )
            .with_remediation(
                "URGENT: Possible kernel rootkit. Run from live USB: rkhunter, chkrootkit, or compare against known-good kernel.",
            ),
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

/// Parse connections from `ss` (uses netlink — independent from procfs).
/// This gives us a second data source to cross-reference against /proc/net/tcp.
fn parse_ss_connections() -> HashSet<Connection> {
    let mut connections = HashSet::new();

    // ss -tna: TCP, numeric, all states (including LISTEN)
    let output = match std::process::Command::new("ss").args(["-tna"]).output() {
        Ok(o) => o,
        Err(e) => {
            debug!("Failed to run ss: {}", e);
            return connections;
        }
    };

    if !output.status.success() {
        debug!("ss exited with non-zero status");
        return connections;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        // ss output format: State Recv-Q Send-Q Local Address:Port Peer Address:Port
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let state = parts[0];
        let local = parts[3];
        let remote = parts[4];

        if let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
            (parse_ss_addr(local), parse_ss_addr(remote))
        {
            connections.insert(Connection {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state: state.to_string(),
            });
        }
    }

    connections
}

/// Parse ss address format (ip:port or [ip]:port or *:port)
fn parse_ss_addr(addr: &str) -> Option<(String, u16)> {
    // Handle formats: "0.0.0.0:22", "127.0.0.1:631", "*:*", "[::]:22"
    if addr == "*:*" {
        return Some(("0.0.0.0".to_string(), 0));
    }

    // Find the last ':' to split IP from port
    let last_colon = addr.rfind(':')?;
    let ip_part = &addr[..last_colon];
    let port_str = &addr[last_colon + 1..];

    let port = if port_str == "*" {
        0
    } else {
        port_str.parse::<u16>().ok()?
    };

    // Clean up IP: remove brackets for IPv6
    let mut ip = ip_part
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    // Strip interface suffix: ss can output "127.0.0.53%lo" or "0.0.0.0%docker0"
    // /proc/net/tcp never includes these, so we must strip them for matching
    if let Some(pct) = ip.find('%') {
        ip.truncate(pct);
    }

    // Normalize: ss uses "*" for wildcard, /proc/net/tcp uses "0.0.0.0"
    let ip = if ip == "*" { "0.0.0.0".to_string() } else { ip };

    Some((ip, port))
}

/// Check if two connections match (ignoring state format differences)
fn connections_match(proc_conn: &Connection, ss_conn: &Connection) -> bool {
    proc_conn.local_ip == ss_conn.local_ip
        && proc_conn.local_port == ss_conn.local_port
        && proc_conn.remote_ip == ss_conn.remote_ip
        && proc_conn.remote_port == ss_conn.remote_port
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
    // Check for netcat/socat by exact binary name (not substring!)
    // Substring matching causes false positives: "Encoder" contains "nc",
    // "rpcbind" contains "nc", etc.
    let proc_base = process_name.rsplit('/').next().unwrap_or(process_name);
    if proc_base == "nc"
        || proc_base == "ncat"
        || proc_base == "netcat"
        || proc_base == "socat"
        || proc_base == "nc.openbsd"
        || proc_base == "nc.traditional"
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
