use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::time::Instant;
use tracing::{info, Level};

use linux_guardian::detectors;
use linux_guardian::models::{OutputStyle, ScanCategory, ScanMode};
use linux_guardian::output;
use linux_guardian::utils::privilege::{
    check_privileges, get_detector_privilege_info, group_detectors_by_privilege,
};

#[derive(Parser, Debug)]
#[command(name = "linux-guardian")]
#[command(author = "Linux Guardian Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Comprehensive Linux security scanner for detecting rootkits, malware, and active attacks", long_about = None)]
struct Args {
    /// Scan mode: fast (10-30s), comprehensive (1-3min), deep (5-15min)
    #[arg(short, long, value_enum, default_value = "fast")]
    mode: ScanMode,

    /// Category filter: all, malware, hardening, privacy, compliance, development, network
    #[arg(short, long, value_enum)]
    category: Option<ScanCategory>,

    /// Output style: terminal, json, simple, summary
    #[arg(short, long, value_enum, default_value = "terminal")]
    output: OutputStyle,

    /// Minimum severity to show: low, medium, high, critical
    #[arg(long)]
    min_severity: Option<String>,

    /// Only show active threats (not hardening suggestions)
    #[arg(long)]
    threats_only: bool,

    /// Show security score
    #[arg(long)]
    score: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Only show findings (suppress info messages)
    #[arg(short, long)]
    quiet: bool,

    /// Skip privilege checks (some detectors will be disabled)
    #[arg(long)]
    skip_privilege_check: bool,

    /// Update CVE database (downloads CISA KEV + NVD feeds to SQLite)
    #[arg(long)]
    update_cve_db: bool,

    /// Show CVE database statistics
    #[arg(long)]
    cve_db_stats: bool,

    /// Hide CVE database findings (show only system issues and verified CVEs)
    #[arg(long)]
    no_cve_db: bool,

    /// Update malware hash database (downloads MalwareBazaar hashes)
    #[arg(long)]
    update_malware_db: bool,

    /// Show malware hash database statistics
    #[arg(long)]
    malware_db_stats: bool,

    /// Skip malware hash database checks
    #[arg(long)]
    no_malware_db: bool,

    /// Deep malware scan: scan ALL files (disables filtering, much slower)
    #[arg(long)]
    deep_malware_scan: bool,

    /// Show detailed privilege requirements for all detectors
    #[arg(long)]
    show_privilege_info: bool,

    /// Treat system as a mail server (suppress mail-related warnings)
    #[arg(long)]
    mail_server: bool,

    /// Treat system as a web server (suppress web-related warnings)
    #[arg(long)]
    web_server: bool,

    /// Treat system as a database server
    #[arg(long)]
    database_server: bool,

    /// Auto-detect server type (enabled by default)
    #[arg(long, default_value = "true")]
    auto_detect: bool,

    /// Path to suppression config file
    #[arg(long)]
    config: Option<String>,

    /// Generate example suppression config file
    #[arg(long)]
    generate_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else if args.quiet {
        Level::WARN
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Handle config generation
    if args.generate_config {
        println!(
            "{}",
            linux_guardian::server_context::SuppressionConfig::example_toml()
        );
        return Ok(());
    }

    // Handle privilege info display
    if args.show_privilege_info {
        print_privilege_info_table();
        return Ok(());
    }

    // Handle malware hash database operations
    if args.update_malware_db {
        if let Err(e) = detectors::malware_hash_db::update_malware_database().await {
            eprintln!("❌ Malware hash database update failed: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.malware_db_stats {
        if let Err(e) = detectors::malware_hash_db::show_malware_db_stats().await {
            eprintln!("❌ Failed to show malware database stats: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    // Handle CVE database operations
    if args.update_cve_db {
        if let Err(e) = linux_guardian::cve_db::update_database().await {
            eprintln!("❌ CVE database update failed: {}", e);
            std::process::exit(1);
        }
        println!("✅ CVE database updated successfully!");
        return Ok(());
    }

    if args.cve_db_stats {
        match linux_guardian::cve_db::get_database_stats() {
            Ok(stats) => {
                println!("📊 CVE Database Statistics:");
                println!("   Total CVEs: {}", stats.total_cves);
                println!("   Critical (CVSS >= 9.0): {}", stats.critical_cves);
                println!("   Actively Exploited: {}", stats.actively_exploited);
                if let Some(last_update) = stats.last_update {
                    println!("   Last Updated: {}", last_update);
                } else {
                    println!("   Last Updated: Never (run --update-cve-db)");
                }
                println!("\n   Database: /var/cache/linux-guardian/cve.db");
            }
            Err(e) => {
                eprintln!("❌ Failed to get database stats: {}", e);
                eprintln!("   Run --update-cve-db to initialize database");
            }
        }
        return Ok(());
    }

    // Display banner
    if !args.quiet && args.output == OutputStyle::Terminal {
        print_banner();
    }

    // Check privileges and show detailed information
    let is_root = check_privileges();
    if !is_root && !args.skip_privilege_check && !args.quiet {
        print_privilege_warning(&args.mode);
    }

    // Build server context
    let mut server_context = if args.auto_detect {
        linux_guardian::server_context::ServerContext::detect()
    } else {
        linux_guardian::server_context::ServerContext::default()
    };

    // Override with manual flags
    if args.mail_server {
        server_context.is_mail_server = true;
    }
    if args.web_server {
        server_context.is_web_server = true;
    }
    if args.database_server {
        server_context.is_database_server = true;
    }

    // Load suppression config
    let mut suppression_config = if let Some(ref config_path) = args.config {
        linux_guardian::server_context::SuppressionConfig::load(std::path::Path::new(config_path))
            .unwrap_or_else(|e| {
                eprintln!("⚠️  Failed to load config from {}: {}", config_path, e);
                linux_guardian::server_context::SuppressionConfig::default()
            })
    } else {
        linux_guardian::server_context::SuppressionConfig::load_default()
    };

    // Merge server context with suppressions
    suppression_config.merge_with_context(&server_context);

    // Show detected context if not quiet
    if !args.quiet
        && args.output == OutputStyle::Terminal
        && !server_context.detected_services.is_empty()
    {
        println!(
            "🔍 Detected server type: {}",
            server_context.detected_services.join(", ")
        );
        println!(
            "   {} ports and {} services whitelisted",
            suppression_config.ignore_ports.len(),
            suppression_config.allow_root_services.len()
        );
        println!();
    }

    info!("Starting security scan in {:?} mode", args.mode);
    let start = Instant::now();

    // Run the scan
    let findings = run_scan(&args, is_root, &server_context, &suppression_config).await?;

    let duration = start.elapsed();

    // Apply filters
    let mut filtered_findings = findings;

    // Filter by CVE database option
    if args.no_cve_db {
        filtered_findings
            .retain(|f| f.category != "cve_database" && f.category != "cve_knowledge_base");
    }

    // Filter by malware hash database option
    if args.no_malware_db {
        filtered_findings.retain(|f| f.category != "malware_hash_match");
    }

    // Filter by category
    if let Some(category) = args.category {
        filtered_findings.retain(|f| f.matches_category(category));
    }

    // Filter by severity
    if let Some(ref min_sev) = args.min_severity {
        filtered_findings.retain(|f| f.matches_severity(min_sev));
    }

    // Filter threats only
    if args.threats_only {
        filtered_findings.retain(|f| f.is_threat());
    }

    // Output results
    output::print_findings(
        &filtered_findings,
        args.output,
        args.score,
        args.output == OutputStyle::Summary,
    );

    if !args.quiet {
        println!(
            "\n  ⏱️  Scan completed in {:.2}s ({:?} mode)",
            duration.as_secs_f32(),
            args.mode
        );
    }

    // Exit with appropriate code
    let critical_count = filtered_findings
        .iter()
        .filter(|f| f.severity == "critical")
        .count();
    if critical_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

async fn run_scan(
    args: &Args,
    is_root: bool,
    server_context: &linux_guardian::server_context::ServerContext,
    suppression_config: &linux_guardian::server_context::SuppressionConfig,
) -> Result<Vec<linux_guardian::models::Finding>> {
    use detectors::{
        binary_validation, bootloader, container_security, credential_theft, cryptominer,
        cve_database, cve_database_sqlite, cve_knowledge_base, disk_encryption, file_permissions,
        firewall, kernel_hardening, malware_hashes, mandatory_access_control, network,
        package_integrity, privilege_escalation, process, ssh, updates,
    };

    let mut findings = Vec::new();

    match args.mode {
        ScanMode::Fast => {
            info!("Running fast scan (9 critical checks + malware hash check in high-risk locations)...\n");

            // Run all fast checks in parallel
            let mut handles = vec![
                tokio::spawn(cve_knowledge_base::check_cve_knowledge_base()),
                tokio::spawn(cve_database::check_known_exploited_vulnerabilities()),
                tokio::spawn(privilege_escalation::scan_suid_binaries(is_root)),
                tokio::spawn(cryptominer::detect_cpu_anomalies()),
                tokio::spawn(ssh::check_unauthorized_keys()),
                tokio::spawn(ssh::detect_brute_force_attempts()),
                tokio::spawn(process::detect_suspicious_processes()),
                tokio::spawn(network::analyze_connections()),
                tokio::spawn(network::analyze_traffic_patterns()),
            ];

            // Add fast malware hash check (only /tmp, /var/tmp, /dev/shm)
            if !args.no_malware_db {
                let deep_scan = args.deep_malware_scan;
                handles.push(tokio::spawn(async move {
                    detectors::malware_hash_db::check_malware_hashes_fast(deep_scan).await
                }));
            }

            // Collect results
            for handle in handles {
                if let Ok(Ok(mut detector_findings)) = handle.await {
                    findings.append(&mut detector_findings);
                }
            }
        }
        ScanMode::Comprehensive => {
            info!("Running comprehensive scan (all security checks + expanded malware hash scan)...\n");

            // Run all fast checks
            findings.extend(run_fast_checks(is_root).await?);

            // Add comprehensive-only checks
            let mut comp_handles = vec![
                tokio::spawn(cve_database_sqlite::check_cve_database()),
                tokio::spawn(firewall::check_firewall()),
                tokio::spawn(updates::check_security_updates()),
                tokio::spawn(mandatory_access_control::check_mandatory_access_control()),
                tokio::spawn(kernel_hardening::check_kernel_hardening()),
                tokio::spawn(disk_encryption::check_disk_encryption()),
                tokio::spawn(bootloader::check_bootloader_security()),
                tokio::spawn(file_permissions::check_file_permissions()),
                tokio::spawn(credential_theft::detect_credential_theft()), // Cookie/password theft
                tokio::spawn(credential_theft::check_credential_permissions()), // SSH key permissions
                tokio::spawn(credential_theft::scan_exposed_credentials()), // API keys in configs
                tokio::spawn(container_security::check_container_security()), // Docker security
            ];

            // Add comprehensive malware hash check (user dirs + web apps)
            if !args.no_malware_db {
                let deep_scan = args.deep_malware_scan;
                comp_handles.push(tokio::spawn(async move {
                    detectors::malware_hash_db::check_malware_hashes_comprehensive(deep_scan).await
                }));
            }

            for handle in comp_handles {
                if let Ok(Ok(mut detector_findings)) = handle.await {
                    findings.append(&mut detector_findings);
                }
            }
        }
        ScanMode::Deep => {
            info!("Running deep scan (comprehensive + package integrity)...\n");

            // Run comprehensive checks
            findings.extend(run_fast_checks(is_root).await?);

            let mut comp_handles = vec![
                tokio::spawn(cve_database_sqlite::check_cve_database()),
                tokio::spawn(firewall::check_firewall()),
                tokio::spawn(updates::check_security_updates()),
                tokio::spawn(mandatory_access_control::check_mandatory_access_control()),
                tokio::spawn(kernel_hardening::check_kernel_hardening()),
                tokio::spawn(disk_encryption::check_disk_encryption()),
                tokio::spawn(bootloader::check_bootloader_security()),
                tokio::spawn(file_permissions::check_file_permissions()),
                tokio::spawn(credential_theft::detect_credential_theft()), // Cookie/password theft
                tokio::spawn(credential_theft::check_credential_permissions()), // SSH key permissions
                tokio::spawn(credential_theft::scan_exposed_credentials()), // API keys in configs
                tokio::spawn(container_security::check_container_security()), // Docker security
                tokio::spawn(package_integrity::verify_package_integrity()), // Deep only (slow!)
                tokio::spawn(binary_validation::validate_critical_binaries()), // Binary verification
                tokio::spawn(malware_hashes::scan_malware_hashes()), // Hash-based malware detection
                tokio::spawn(malware_hashes::scan_elf_anomalies()),  // ELF binary analysis
                // NEW: Advanced rootkit & exploit detection
                tokio::spawn(detectors::ebpf::detect_ebpf_programs()), // eBPF rootkits
                tokio::spawn(detectors::ebpf::detect_ebpf_maps()),     // eBPF data exfiltration
                tokio::spawn(detectors::kernel_modules::detect_kernel_modules()), // Kernel rootkits
                tokio::spawn(detectors::kernel_modules::check_module_parameters()), // Module tampering
                tokio::spawn(detectors::systemd_security::detect_systemd_tampering()), // Systemd backdoors
                tokio::spawn(detectors::systemd_security::check_systemd_timers()), // Persistence
                tokio::spawn(detectors::systemd_security::check_init_scripts()),   // Legacy init
                tokio::spawn(detectors::cron_backdoor::detect_cron_backdoors()), // Cron persistence
                tokio::spawn(detectors::cron_backdoor::check_at_jobs()),         // At jobs
                tokio::spawn(detectors::process_capabilities::detect_dangerous_capabilities()), // CAP_SYS_ADMIN
                tokio::spawn(detectors::process_capabilities::check_file_capabilities()), // SUID alternatives
                tokio::spawn(detectors::memory_security::detect_memory_injection()), // Code injection
                tokio::spawn(detectors::memory_security::check_core_dumps()), // Exploitation evidence
            ];

            // Add malware hash database check (slow, only in deep mode)
            if !args.no_malware_db {
                let deep_scan = args.deep_malware_scan;
                comp_handles.push(tokio::spawn(async move {
                    detectors::malware_hash_db::check_malware_hashes(deep_scan).await
                }));
            }

            for handle in comp_handles {
                if let Ok(Ok(mut detector_findings)) = handle.await {
                    findings.append(&mut detector_findings);
                }
            }
        }
    }

    // Apply suppressions and adjust severities
    findings = apply_suppressions(findings, server_context, suppression_config);
    findings = adjust_finding_severities(findings, server_context, suppression_config);

    Ok(findings)
}

async fn run_fast_checks(is_root: bool) -> Result<Vec<linux_guardian::models::Finding>> {
    let mut findings = Vec::new();

    let handles = vec![
        tokio::spawn(detectors::cve_knowledge_base::check_cve_knowledge_base()), // Comprehensive CVE checking
        tokio::spawn(detectors::cve_database::check_known_exploited_vulnerabilities()), // CISA KEV
        tokio::spawn(detectors::privilege_escalation::scan_suid_binaries(is_root)),
        tokio::spawn(detectors::cryptominer::detect_cpu_anomalies()),
        tokio::spawn(detectors::ssh::check_unauthorized_keys()),
        tokio::spawn(detectors::ssh::detect_brute_force_attempts()),
        tokio::spawn(detectors::process::detect_suspicious_processes()),
        tokio::spawn(detectors::network::analyze_connections()),
        tokio::spawn(detectors::network::analyze_traffic_patterns()),
    ];

    for handle in handles {
        if let Ok(Ok(mut detector_findings)) = handle.await {
            findings.append(&mut detector_findings);
        }
    }

    Ok(findings)
}

fn print_banner() {
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_cyan()
    );
    println!(
        "{}",
        "║         🛡️  LINUX GUARDIAN - Security Scanner 🛡️          ║".bright_cyan()
    );
    println!(
        "{}",
        "║              Real-time Threat Detection 2025              ║".bright_cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_cyan()
    );
    println!();
}

// Helper functions

fn print_privilege_warning(mode: &ScanMode) {
    let (no_root, partial_root, requires_root) = group_detectors_by_privilege();

    println!("{}", "⚠️  Running without root privileges".yellow().bold());
    println!();

    println!("{}", "✅ FULL FUNCTIONALITY (no root needed):".green());
    println!(
        "   {} detectors will run with complete features",
        no_root.len()
    );
    println!("   • CVE database checks");
    println!("   • Network connection analysis");
    println!("   • Kernel hardening checks");
    println!("   • Disk encryption detection");
    println!();

    println!(
        "{}",
        "⚠️  PARTIAL FUNCTIONALITY (limited without root):".yellow()
    );
    println!(
        "   {} detectors will run with reduced features",
        partial_root.len()
    );
    println!("   • SSH: config analysis only (no auth log analysis)");
    println!("   • Firewall: basic status (no full ruleset)");
    println!("   • Process: own processes only (not all users)");
    println!("   • Container: basic checks (limited Docker access)");
    println!();

    println!("{}", "❌ DISABLED (requires root):".red());
    println!(
        "   {} detector(s) will be completely skipped",
        requires_root.len()
    );
    println!("   • Privilege Escalation: SUID/capability scanning");
    println!();

    match mode {
        ScanMode::Fast => {
            println!(
                "{}",
                "📝 Note: Fast mode uses mostly non-privileged checks".cyan()
            );
        }
        ScanMode::Comprehensive | ScanMode::Deep => {
            println!(
                "{}",
                "📝 Note: Run with sudo for complete system analysis in this mode".cyan()
            );
        }
    }

    println!(
        "   Run {} for detailed breakdown",
        "--show-privilege-info".bright_cyan()
    );
    println!();
}

fn print_privilege_info_table() {
    println!(
        "{}",
        "🔐 Detector Privilege Requirements".bold().bright_cyan()
    );
    println!();

    let (no_root, partial_root, requires_root) = group_detectors_by_privilege();

    // NO ROOT REQUIRED
    println!("{}", "✅ NO ROOT REQUIRED".green().bold());
    println!(
        "{}",
        "   These detectors work fully without root privileges:".green()
    );
    println!();
    for detector in &no_root {
        let info = get_detector_privilege_info(detector);
        println!("   • {}", format!("{:30}", detector).bright_white());
        if !info.works_without_root.is_empty() {
            for feature in info.works_without_root {
                println!("     {}", format!("✓ {}", feature).dimmed());
            }
        }
    }
    println!();

    // PARTIAL ROOT
    println!("{}", "⚠️  PARTIAL ROOT ACCESS".yellow().bold());
    println!(
        "{}",
        "   These detectors work partially without root:".yellow()
    );
    println!();
    for detector in &partial_root {
        let info = get_detector_privilege_info(detector);
        println!("   • {}", format!("{:30}", detector).bright_white().bold());

        if !info.works_without_root.is_empty() {
            println!("     {} (without root):", "Available".green());
            for feature in info.works_without_root {
                println!("       {}", format!("✓ {}", feature).green());
            }
        }

        if !info.requires_root_for.is_empty() {
            println!("     {} (requires root):", "Limited".yellow());
            for feature in info.requires_root_for {
                println!("       {}", format!("⚠ {}", feature).yellow());
            }
        }
        println!();
    }

    // REQUIRES ROOT
    println!("{}", "❌ ROOT REQUIRED".red().bold());
    println!("{}", "   These detectors require root privileges:".red());
    println!();
    for detector in &requires_root {
        let info = get_detector_privilege_info(detector);
        println!("   • {}", format!("{:30}", detector).bright_white().bold());
        for reason in info.requires_root_for {
            println!("     {}", format!("✗ {}", reason).red());
        }
    }
    println!();

    println!("{}", "💡 RECOMMENDATIONS:".cyan().bold());
    println!("   • For desktop users: Most checks work without root");
    println!("   • For servers: Run with sudo for complete coverage");
    println!("   • For security audits: Root access is recommended");
    println!();
    println!(
        "   Run: {} for non-root scan",
        "linux-guardian --mode fast".bright_cyan()
    );
    println!(
        "   Run: {} for complete scan",
        "sudo linux-guardian --mode comprehensive".bright_cyan()
    );
    println!();
}

/// Apply context-aware suppressions to findings
fn apply_suppressions(
    findings: Vec<linux_guardian::models::Finding>,
    _server_context: &linux_guardian::server_context::ServerContext,
    suppression_config: &linux_guardian::server_context::SuppressionConfig,
) -> Vec<linux_guardian::models::Finding> {
    findings
        .into_iter()
        .filter(|finding| {
            // Suppress CVEs in ignore list
            if let Some(ref cve) = finding.cve {
                if suppression_config.ignore_cves.contains(cve) {
                    return false;
                }
            }

            // Suppress network exposure for expected ports
            if finding.category == "network_exposure" {
                // Extract port from description (e.g., "Port 25 is listening...")
                if let Some(port_str) = finding.description.split_whitespace().nth(1) {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if suppression_config.ignore_ports.contains(&port) {
                            return false;
                        }
                    }
                }
            }

            // Suppress root services that are expected
            if finding.category == "systemd_root_service" {
                for service_name in &suppression_config.allow_root_services {
                    if finding.description.contains(service_name) {
                        return false;
                    }
                }
            }

            // Suppress PHP-FPM JIT memory if web server
            if finding.category == "memory_injection" {
                for process_name in &suppression_config.allow_rwx_processes {
                    if finding.description.contains(process_name) {
                        return false;
                    }
                }
            }

            // Suppress debug module parameters if whitelisted
            if finding.category == "suspicious_module_param" {
                for module_name in &suppression_config.allow_debug_modules {
                    if finding.description.contains(module_name) {
                        return false;
                    }
                }
            }

            // Suppress DNS server warnings for trusted servers
            if finding.category == "suspicious_network" && finding.title.contains("DNS Server") {
                for dns_server in &suppression_config.trusted_dns_servers {
                    if finding.description.contains(dns_server) {
                        return false;
                    }
                }
            }

            // Suppress systemd backdoor warnings for known good services (clamav)
            if finding.category == "systemd_backdoor"
                && finding.description.contains("clamav-clamonacc")
            {
                // ClamAV on-access scanner legitimately uses bash -c
                return false;
            }

            true
        })
        .collect()
}

/// Adjust finding severities based on context
/// For example, disk encryption is CRITICAL for laptops but MEDIUM for datacenter servers
fn adjust_finding_severities(
    mut findings: Vec<linux_guardian::models::Finding>,
    server_context: &linux_guardian::server_context::ServerContext,
    _suppression_config: &linux_guardian::server_context::SuppressionConfig,
) -> Vec<linux_guardian::models::Finding> {
    for finding in &mut findings {
        // Disk encryption less critical for servers (physical security assumed)
        if finding.category == "encryption"
            && finding.title.contains("Disk Encryption")
            && (server_context.is_mail_server
                || server_context.is_web_server
                || server_context.is_database_server)
            && finding.severity == "critical"
        {
            finding.severity = "medium".to_string();
        }

        // GRUB password less critical on servers in secure datacenters
        if finding.category == "bootloader"
            && finding.title.contains("Password")
            && (server_context.is_mail_server || server_context.is_web_server)
            && (finding.severity == "high" || finding.severity == "critical")
        {
            finding.severity = "medium".to_string();
        }

        // Connection count mismatch might be normal with IPv6, containers, etc.
        if finding.category == "rootkit"
            && finding.title.contains("Connection Count Mismatch")
            && finding.severity == "high"
        {
            finding.severity = "medium".to_string();
        }
    }

    findings
}
