use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::time::Instant;
use tracing::{info, Level};

use linux_guardian::detectors;
use linux_guardian::models::{OutputStyle, ScanCategory, ScanMode};
use linux_guardian::output;
use linux_guardian::utils::privilege::{
    check_privileges, get_detector_privilege_info, group_detectors_by_privilege,
};

mod commands;

#[derive(Parser, Debug)]
#[command(name = "linux-guardian")]
#[command(version)]
#[command(about = "Fast Linux security scanner", long_about = None)]
pub(crate) struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Deep scan (all checks, slower)
    #[arg(short, long)]
    deep: bool,

    /// JSON output
    #[arg(short, long)]
    json: bool,

    /// Only show active threats
    #[arg(short, long)]
    threats_only: bool,

    /// Minimum severity: low, medium, high, critical
    #[arg(short, long)]
    severity: Option<String>,

    /// Filter by category: malware, hardening, network, etc.
    #[arg(short, long, value_enum)]
    category: Option<ScanCategory>,

    /// Quiet mode (findings only)
    #[arg(short, long)]
    quiet: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Path to suppression config
    #[arg(long)]
    pub(crate) config: Option<String>,

    /// Skip malware hash checks
    #[arg(long)]
    pub(crate) no_malware: bool,

    /// Skip CVE database checks
    #[arg(long)]
    no_cve: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// First-time setup: download all databases and verify system
    Setup,
    /// Update all databases (CVE + malware hashes)
    Update,
    /// Show database statistics
    Stats,
    /// Generate example suppression config
    Config,
    /// Show privilege requirements for all detectors
    Privileges,
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

    // Handle subcommands
    match args.command {
        Some(Command::Setup) => {
            return commands::run_setup().await;
        }
        Some(Command::Update) => {
            return commands::run_update().await;
        }
        Some(Command::Stats) => {
            return commands::run_stats().await;
        }
        Some(Command::Config) => {
            return commands::run_config();
        }
        Some(Command::Privileges) => {
            return commands::run_privileges();
        }
        None => {} // Default: run scan
    }

    // Determine scan mode
    let mode = if args.deep {
        ScanMode::Deep
    } else {
        ScanMode::Fast
    };

    // Determine output style
    let output_style = if args.json {
        OutputStyle::Json
    } else {
        OutputStyle::Terminal
    };

    // Display banner
    if !args.quiet && output_style == OutputStyle::Terminal {
        print_banner();
    }

    // Check privileges
    let is_root = check_privileges();
    if !is_root && !args.quiet && output_style == OutputStyle::Terminal {
        print_privilege_warning(&mode);
    }

    // Build server context (always auto-detect)
    let server_context = linux_guardian::server_context::ServerContext::detect();

    // Load suppression config
    let mut suppression_config = if let Some(ref config_path) = args.config {
        linux_guardian::server_context::SuppressionConfig::load(std::path::Path::new(config_path))
            .unwrap_or_else(|e| {
                eprintln!("Failed to load config {}: {}", config_path, e);
                linux_guardian::server_context::SuppressionConfig::default()
            })
    } else {
        linux_guardian::server_context::SuppressionConfig::load_default()
    };

    suppression_config.merge_with_context(&server_context);

    // Show detected context
    if !args.quiet
        && output_style == OutputStyle::Terminal
        && !server_context.detected_services.is_empty()
    {
        println!(
            "Detected: {} ({}p/{}s suppressed)\n",
            server_context.detected_services.join(", "),
            suppression_config.ignore_ports.len(),
            suppression_config.allow_root_services.len()
        );
    }

    // Show tips about missing databases
    if !args.quiet && output_style == OutputStyle::Terminal {
        if !cve_database_exists() {
            println!(
                "{}",
                "Tip: No CVE database. Run 'linux-guardian update' for vulnerability detection."
                    .yellow()
            );
            println!();
        }
        if !malware_database_exists() {
            println!(
                "{}",
                "Tip: No malware database. Run 'linux-guardian update' for malware hash detection."
                    .yellow()
            );
            println!();
        }
    }

    info!("Starting security scan in {:?} mode", mode);
    let start = Instant::now();

    // Run the scan
    let findings = run_scan(&args, mode, is_root, &server_context, &suppression_config).await?;

    let duration = start.elapsed();

    // Apply filters
    let mut filtered_findings = findings;

    if args.no_cve {
        filtered_findings
            .retain(|f| f.category != "cve_database" && f.category != "cve_knowledge_base");
    }

    if args.no_malware {
        filtered_findings.retain(|f| f.category != "malware_hash_match");
    }

    if let Some(category) = args.category {
        filtered_findings.retain(|f| f.matches_category(category));
    }

    if let Some(ref min_sev) = args.severity {
        filtered_findings.retain(|f| f.matches_severity(min_sev));
    }

    if args.threats_only {
        filtered_findings.retain(|f| f.is_threat());
    }

    // Output results
    output::print_findings(&filtered_findings, output_style, false, false);

    if !args.quiet {
        println!(
            "\n  Scan completed in {:.2}s ({:?} mode)",
            duration.as_secs_f32(),
            mode
        );

        if output_style == OutputStyle::Terminal && matches!(mode, ScanMode::Fast) {
            println!(
                "  {}",
                "Tip: linux-guardian --deep for thorough scan | linux-guardian update for vulnerability data"
                    .dimmed()
            );
        }
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

pub(crate) async fn run_scan(
    args: &Args,
    mode: ScanMode,
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

    match mode {
        ScanMode::Fast => {
            info!("Running fast scan...\n");

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
                tokio::spawn(detectors::memory_threats::detect_fileless_malware()),
                tokio::spawn(detectors::memory_threats::detect_process_masquerading()),
                tokio::spawn(detectors::memory_threats::detect_ld_preload_injection()),
            ];

            if !args.no_malware {
                handles.push(tokio::spawn(async move {
                    detectors::malware_hash_db::check_malware_hashes_fast(false).await
                }));
            }

            for handle in handles {
                if let Ok(Ok(mut detector_findings)) = handle.await {
                    findings.append(&mut detector_findings);
                }
            }
        }
        ScanMode::Comprehensive | ScanMode::Deep => {
            info!("Running deep scan...\n");

            // Fast checks first
            findings.extend(run_fast_checks(is_root).await?);

            let mut handles = vec![
                tokio::spawn(cve_database_sqlite::check_cve_database()),
                tokio::spawn(firewall::check_firewall()),
                tokio::spawn(updates::check_security_updates()),
                tokio::spawn(mandatory_access_control::check_mandatory_access_control()),
                tokio::spawn(kernel_hardening::check_kernel_hardening()),
                tokio::spawn(disk_encryption::check_disk_encryption()),
                tokio::spawn(bootloader::check_bootloader_security()),
                tokio::spawn(file_permissions::check_file_permissions()),
                tokio::spawn(credential_theft::detect_credential_theft()),
                tokio::spawn(credential_theft::check_credential_permissions()),
                tokio::spawn(credential_theft::scan_exposed_credentials()),
                tokio::spawn(container_security::check_container_security()),
                tokio::spawn(package_integrity::verify_package_integrity()),
                tokio::spawn(binary_validation::validate_critical_binaries()),
                tokio::spawn(malware_hashes::scan_malware_hashes()),
                tokio::spawn(malware_hashes::scan_elf_anomalies()),
                tokio::spawn(detectors::ebpf::detect_ebpf_programs()),
                tokio::spawn(detectors::ebpf::detect_ebpf_maps()),
                tokio::spawn(detectors::kernel_modules::detect_kernel_modules()),
                tokio::spawn(detectors::kernel_modules::check_module_parameters()),
                tokio::spawn(detectors::systemd_security::detect_systemd_tampering()),
                tokio::spawn(detectors::systemd_security::check_systemd_timers()),
                tokio::spawn(detectors::systemd_security::check_init_scripts()),
                tokio::spawn(detectors::cron_backdoor::detect_cron_backdoors()),
                tokio::spawn(detectors::cron_backdoor::check_at_jobs()),
                tokio::spawn(detectors::process_capabilities::detect_dangerous_capabilities()),
                tokio::spawn(detectors::process_capabilities::check_file_capabilities()),
                tokio::spawn(detectors::memory_security::detect_memory_injection()),
                tokio::spawn(detectors::memory_security::check_core_dumps()),
                tokio::spawn(detectors::memory_threats::deep_scan_process_memory(is_root)),
                tokio::spawn(detectors::memory_threats::detect_process_hollowing(is_root)),
            ];

            if !args.no_malware {
                handles.push(tokio::spawn(async move {
                    detectors::malware_hash_db::check_malware_hashes(false).await
                }));
            }

            for handle in handles {
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
        tokio::spawn(detectors::cve_knowledge_base::check_cve_knowledge_base()),
        tokio::spawn(detectors::cve_database::check_known_exploited_vulnerabilities()),
        tokio::spawn(detectors::privilege_escalation::scan_suid_binaries(is_root)),
        tokio::spawn(detectors::cryptominer::detect_cpu_anomalies()),
        tokio::spawn(detectors::ssh::check_unauthorized_keys()),
        tokio::spawn(detectors::ssh::detect_brute_force_attempts()),
        tokio::spawn(detectors::process::detect_suspicious_processes()),
        tokio::spawn(detectors::network::analyze_connections()),
        tokio::spawn(detectors::network::analyze_traffic_patterns()),
        tokio::spawn(detectors::memory_threats::detect_fileless_malware()),
        tokio::spawn(detectors::memory_threats::detect_process_masquerading()),
        tokio::spawn(detectors::memory_threats::detect_ld_preload_injection()),
    ];

    for handle in handles {
        if let Ok(Ok(mut detector_findings)) = handle.await {
            findings.append(&mut detector_findings);
        }
    }

    Ok(findings)
}

pub(crate) fn print_banner() {
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_cyan()
    );
    println!(
        "{}",
        "║             LINUX GUARDIAN - Security Scanner             ║".bright_cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_cyan()
    );
    println!();
}

fn print_privilege_warning(mode: &ScanMode) {
    let (no_root, partial_root, requires_root) = group_detectors_by_privilege();

    println!("{}", "Running without root privileges".yellow().bold());
    println!(
        "  {} full, {} partial, {} disabled",
        no_root.len(),
        partial_root.len(),
        requires_root.len()
    );

    match mode {
        ScanMode::Fast => {
            println!(
                "{}",
                "  Fast mode uses mostly non-privileged checks".dimmed()
            );
        }
        _ => {
            println!("{}", "  Run with sudo for complete analysis".dimmed());
        }
    }

    println!(
        "  Run {} for details",
        "linux-guardian privileges".bright_cyan()
    );
    println!();
}

pub(crate) fn print_privilege_info_table() {
    let (no_root, partial_root, requires_root) = group_detectors_by_privilege();

    println!(
        "{}",
        "Detector Privilege Requirements\n".bold().bright_cyan()
    );

    println!("{}", "NO ROOT REQUIRED:".green().bold());
    for detector in &no_root {
        println!("  {}", detector);
    }
    println!();

    println!("{}", "PARTIAL (limited without root):".yellow().bold());
    for detector in &partial_root {
        let info = get_detector_privilege_info(detector);
        println!("  {}", format!("{:30}", detector).bold());
        for feature in info.works_without_root {
            println!("    {}", format!("+ {}", feature).green());
        }
        for feature in info.requires_root_for {
            println!("    {}", format!("- {}", feature).yellow());
        }
    }
    println!();

    println!("{}", "ROOT REQUIRED:".red().bold());
    for detector in &requires_root {
        let info = get_detector_privilege_info(detector);
        for reason in info.requires_root_for {
            println!("  {} - {}", detector, reason);
        }
    }
    println!();
}

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

            // Suppress debug module parameters if allowed in config
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

            // Suppress ClamAV on-access scanner (legitimate bash -c usage)
            if finding.category == "systemd_backdoor"
                && finding.description.contains("clamav-clamonacc")
            {
                return false;
            }

            true
        })
        .collect()
}

fn adjust_finding_severities(
    mut findings: Vec<linux_guardian::models::Finding>,
    server_context: &linux_guardian::server_context::ServerContext,
    _suppression_config: &linux_guardian::server_context::SuppressionConfig,
) -> Vec<linux_guardian::models::Finding> {
    for finding in &mut findings {
        // Disk encryption less critical for servers
        if finding.category == "encryption"
            && finding.title.contains("Disk Encryption")
            && (server_context.is_mail_server
                || server_context.is_web_server
                || server_context.is_database_server)
            && finding.severity == "critical"
        {
            finding.severity = "medium".to_string();
        }

        // GRUB password less critical on servers
        if finding.category == "bootloader"
            && finding.title.contains("Password")
            && (server_context.is_mail_server || server_context.is_web_server)
            && (finding.severity == "high" || finding.severity == "critical")
        {
            finding.severity = "medium".to_string();
        }

        // Connection count mismatch might be normal
        if finding.category == "rootkit"
            && finding.title.contains("Connection Count Mismatch")
            && finding.severity == "high"
        {
            finding.severity = "medium".to_string();
        }
    }

    findings
}

pub(crate) fn cve_database_exists() -> bool {
    let mut paths = vec![std::path::PathBuf::from("/var/cache/linux-guardian/cve.db")];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(std::path::PathBuf::from(home).join(".cache/linux-guardian/cve.db"));
    }
    paths.iter().any(|p| {
        p.exists()
            && std::fs::metadata(p)
                .map(|m| m.len() > 100_000)
                .unwrap_or(false)
    })
}

pub(crate) fn malware_database_exists() -> bool {
    let mut paths = vec![std::path::PathBuf::from(
        "/var/cache/linux-guardian/malware_hashes.csv",
    )];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(std::path::PathBuf::from(home).join(".cache/linux-guardian/malware_hashes.csv"));
    }
    paths.iter().any(|p| p.exists())
}
