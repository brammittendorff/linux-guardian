use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerContext {
    pub is_mail_server: bool,
    pub is_web_server: bool,
    pub is_virtualmin: bool,
    pub is_database_server: bool,
    pub detected_services: Vec<String>,
}

impl ServerContext {
    /// Auto-detect server type based on installed packages and running services
    pub fn detect() -> Self {
        let mut context = ServerContext::default();
        let mut services = Vec::new();

        // Check for mail server packages
        if Self::has_package("postfix")
            || Self::has_package("dovecot")
            || Self::has_package("exim4")
            || Self::has_package("sendmail")
        {
            context.is_mail_server = true;
            services.push("mail".to_string());
        }

        // Check for web server packages
        if Self::has_package("apache2")
            || Self::has_package("nginx")
            || Self::has_package("lighttpd")
            || Self::has_package("httpd")
        {
            context.is_web_server = true;
            services.push("web".to_string());
        }

        // Check for Virtualmin/Webmin
        if Self::has_package("webmin")
            || Self::has_package("virtualmin")
            || Path::new("/etc/webmin").exists()
        {
            context.is_virtualmin = true;
            services.push("virtualmin".to_string());
        }

        // Check for database servers
        if Self::has_package("mysql-server")
            || Self::has_package("mariadb-server")
            || Self::has_package("postgresql")
        {
            context.is_database_server = true;
            services.push("database".to_string());
        }

        context.detected_services = services;
        context
    }

    /// Check if a package is installed (works on Debian/Ubuntu and RHEL-based)
    fn has_package(name: &str) -> bool {
        // Try dpkg (Debian/Ubuntu)
        if let Ok(output) = std::process::Command::new("dpkg")
            .args(["-l", name])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains(&format!("ii  {}", name)) {
                    return true;
                }
            }
        }

        // Try rpm (RHEL/CentOS/Fedora)
        if let Ok(output) = std::process::Command::new("rpm")
            .args(["-q", name])
            .output()
        {
            if output.status.success() {
                return true;
            }
        }

        false
    }

    /// Get expected open ports for this server type
    pub fn expected_ports(&self) -> HashSet<u16> {
        let mut ports = HashSet::new();

        if self.is_mail_server {
            ports.extend(&[25, 587, 465, 110, 143, 993, 995]); // SMTP, POP3, IMAP
        }

        if self.is_web_server {
            ports.extend(&[80, 443, 8080, 8443]); // HTTP, HTTPS
        }

        if self.is_virtualmin {
            ports.extend(&[10000, 20000]); // Webmin, Usermin
        }

        if self.is_database_server {
            ports.extend(&[3306, 5432]); // MySQL, PostgreSQL
        }

        // SSH is always expected
        ports.insert(22);

        ports
    }

    /// Check if a port is expected for this server type
    pub fn is_port_expected(&self, port: u16) -> bool {
        self.expected_ports().contains(&port)
    }

    /// Get services that legitimately run as root
    pub fn expected_root_services(&self) -> HashSet<String> {
        let mut services = HashSet::new();

        // Always expected
        services.insert("fail2ban".to_string());
        services.insert("named".to_string());
        services.insert("systemd-resolved".to_string());

        if self.is_mail_server {
            services.insert("master".to_string()); // Postfix
            services.insert("dovecot".to_string());
        }

        if self.is_web_server {
            services.insert("nginx".to_string());
            services.insert("apache2".to_string());
            services.insert("httpd".to_string());
        }

        if self.is_virtualmin {
            services.insert("miniserv.".to_string());
            services.insert("perl".to_string()); // Webmin uses Perl
        }

        services
    }

    /// Check if PHP-FPM JIT is expected (not code injection)
    pub fn is_php_jit_expected(&self) -> bool {
        self.is_web_server || self.is_virtualmin
    }
}

/// Configuration for suppressions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuppressionConfig {
    /// Ports to ignore in network exposure checks
    #[serde(default)]
    pub ignore_ports: HashSet<u16>,

    /// CVEs to suppress (user acknowledges/plans to update later)
    #[serde(default)]
    pub ignore_cves: HashSet<String>,

    /// Services allowed to run as root
    #[serde(default)]
    pub allow_root_services: HashSet<String>,

    /// Process names with expected RWX memory (JIT compilers)
    #[serde(default)]
    pub allow_rwx_processes: HashSet<String>,

    /// Kernel modules allowed to have debug parameters
    #[serde(default)]
    pub allow_debug_modules: HashSet<String>,

    /// DNS servers to trust
    #[serde(default)]
    pub trusted_dns_servers: HashSet<String>,
}

impl SuppressionConfig {
    /// Load from TOML file
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: SuppressionConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Try to load from default locations
    pub fn load_default() -> Self {
        let paths = vec![
            "/etc/linux-guardian/suppressions.toml",
            "/etc/linux-guardian.toml",
            "linux-guardian.toml",
            ".linux-guardian.toml",
        ];

        for path in paths {
            if let Ok(config) = Self::load(Path::new(path)) {
                return config;
            }
        }

        Self::default()
    }

    /// Merge with server context to create comprehensive suppression list
    pub fn merge_with_context(&mut self, context: &ServerContext) {
        // Add expected ports
        self.ignore_ports.extend(context.expected_ports());

        // Add expected root services
        self.allow_root_services
            .extend(context.expected_root_services());

        // Add PHP-FPM if web server
        if context.is_php_jit_expected() {
            self.allow_rwx_processes.insert("php-fpm".to_string());
        }
    }

    /// Generate example config file
    pub fn example_toml() -> String {
        r#"# Linux Guardian Suppression Configuration
# Place this file at /etc/linux-guardian.toml or ./linux-guardian.toml

# Ports to ignore in network exposure checks
ignore_ports = [22, 80, 443]

# CVEs to suppress (acknowledge but don't alert)
ignore_cves = ["CVE-2024-XXXXX"]

# Services allowed to run as root
allow_root_services = ["fail2ban", "nginx"]

# Processes allowed to have RWX memory (JIT compilers)
allow_rwx_processes = ["php-fpm", "node", "java"]

# Kernel modules allowed to have debug parameters
allow_debug_modules = []

# Trusted DNS servers
trusted_dns_servers = ["8.8.8.8", "1.1.1.1"]
"#
        .to_string()
    }
}
