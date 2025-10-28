use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::time::Instant;
use tracing::{info, Level};

use linux_guardian::detectors;
use linux_guardian::models::{OutputStyle, ScanCategory, ScanMode, UserProfile};
use linux_guardian::output;
use linux_guardian::utils::privilege::check_privileges;

#[derive(Parser, Debug)]
#[command(name = "linux-guardian")]
#[command(author = "Linux Guardian Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Comprehensive Linux security scanner for detecting rootkits, malware, and active attacks", long_about = None)]
struct Args {
    /// Scan mode: fast (10-30s), comprehensive (1-3min), deep (5-15min)
    #[arg(short, long, value_enum, default_value = "fast")]
    mode: ScanMode,

    /// User profile: auto, desktop, gaming, developer, server, paranoid
    #[arg(short, long, value_enum)]
    profile: Option<UserProfile>,

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

    // Detect profile if auto or show suggestion
    let profile = args.profile.unwrap_or(UserProfile::Auto);
    if profile == UserProfile::Auto && !args.quiet {
        println!("{}", detect_profile_message());
    }

    // Check privileges
    let is_root = check_privileges();
    if !is_root && !args.skip_privilege_check {
        eprintln!(
            "{}",
            "⚠️  WARNING: Not running as root. Some security checks will be limited.".yellow()
        );
        eprintln!(
            "{}",
            "   Run with sudo for complete system analysis.\n".yellow()
        );
    }

    info!("Starting security scan in {:?} mode", args.mode);
    let start = Instant::now();

    // Run the scan
    let findings = run_scan(&args, is_root).await?;

    let duration = start.elapsed();

    // Apply filters
    let mut filtered_findings = findings;

    // Filter by CVE database option
    if args.no_cve_db {
        filtered_findings
            .retain(|f| f.category != "cve_database" && f.category != "cve_knowledge_base");
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

async fn run_scan(args: &Args, is_root: bool) -> Result<Vec<linux_guardian::models::Finding>> {
    use detectors::{
        binary_validation, bootloader, container_security, credential_theft, cryptominer,
        cve_database, cve_database_sqlite, cve_knowledge_base, disk_encryption, file_permissions,
        firewall, kernel_hardening, malware_hashes, mandatory_access_control, network,
        package_integrity, privilege_escalation, process, ssh, updates,
    };

    let mut findings = Vec::new();

    match args.mode {
        ScanMode::Fast => {
            info!("Running fast scan (9 critical checks + CVE databases)...\n");

            // Run all fast checks in parallel
            let handles = vec![
                tokio::spawn(cve_knowledge_base::check_cve_knowledge_base()),
                tokio::spawn(cve_database::check_known_exploited_vulnerabilities()),
                tokio::spawn(privilege_escalation::scan_suid_binaries(is_root)),
                tokio::spawn(cryptominer::detect_cpu_anomalies()),
                tokio::spawn(ssh::check_unauthorized_keys()),
                tokio::spawn(ssh::detect_brute_force_attempts()),
                tokio::spawn(process::detect_suspicious_processes()),
                tokio::spawn(network::analyze_connections()),
            ];

            // Collect results
            for handle in handles {
                if let Ok(Ok(mut detector_findings)) = handle.await {
                    findings.append(&mut detector_findings);
                }
            }
        }
        ScanMode::Comprehensive => {
            info!("Running comprehensive scan (all security checks)...\n");

            // Run all fast checks
            findings.extend(run_fast_checks(is_root).await?);

            // Add comprehensive-only checks
            let comp_handles = vec![
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

            let comp_handles = vec![
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
            ];

            for handle in comp_handles {
                if let Ok(Ok(mut detector_findings)) = handle.await {
                    findings.append(&mut detector_findings);
                }
            }
        }
    }

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

fn detect_profile_message() -> String {
    // Simple auto-detection logic
    let has_display = std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

    if has_display {
        "Tip: Detected desktop environment. Try --profile desktop for tailored results".to_string()
    } else {
        "Tip: Detected server environment. Try --profile server for full checks".to_string()
    }
}
