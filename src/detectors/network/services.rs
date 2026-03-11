use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;
use tracing::debug;

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
pub(super) async fn test_ports_parallel(ip: &str, ports: &[u16]) -> HashMap<u16, bool> {
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
pub(super) fn fingerprint_services_batch(ports: &[u16]) -> HashMap<u16, String> {
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
                                            let actual_service =
                                                identify_service_from_banner(&banner, port);
                                            // Only use banner if it's more specific than generic Docker proxy
                                            if !actual_service.contains("Unknown")
                                                && !actual_service.is_empty()
                                            {
                                                result.insert(
                                                    port,
                                                    format!(
                                                        "{} (Docker container)",
                                                        actual_service
                                                    ),
                                                );
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
        return format!(
            "HTTP server - {}",
            banner.lines().next().unwrap_or(banner).trim()
        );
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
pub(super) fn fingerprint_service(port: u16) -> Option<String> {
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

/// Attempt to grab a banner from a service.
///
/// Uses short timeouts (200ms connect, 500ms read) to avoid blocking the scan.
/// Most local services respond in <10ms; anything slower is not worth waiting for.
fn grab_banner(port: u16) -> Option<String> {
    // Connect to localhost directly — no need to enumerate all local IPs
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
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

    // Try sending HTTP request for likely HTTP ports
    if port == 80 || port == 443 || port >= 8000 {
        use std::io::Write;
        stream
            .write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .ok()?;
        stream.flush().ok()?;

        if let Ok(n) = stream.read(&mut buffer) {
            if n > 0 {
                let response = String::from_utf8_lossy(&buffer[..n.min(1024)]);
                if response.contains("HTTP/") {
                    let mut headers = Vec::new();
                    for line in response.lines() {
                        let line_lower = line.to_lowercase();
                        if line_lower.starts_with("server:")
                            || line_lower.starts_with("x-powered-by:")
                            || line_lower.starts_with("x-application:")
                        {
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

    None
}

/// Get list of local IP addresses to test reachability
pub(super) fn get_local_ips() -> Vec<String> {
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
