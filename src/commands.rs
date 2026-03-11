use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::io::{self, Write};
use std::time::Instant;

use linux_guardian::detectors;
use linux_guardian::models::{OutputStyle, ScanMode};
use linux_guardian::output;
use linux_guardian::utils::privilege::check_privileges;

pub(crate) fn prompt_yn(question: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{} {} ", question, hint);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_lowercase();
    if input.is_empty() {
        return default_yes;
    }
    input.starts_with('y')
}

pub(crate) async fn run_setup() -> Result<()> {
    println!("{}", "Linux Guardian - Setup\n".bold().bright_cyan());

    // 1. Check databases
    let has_cve = crate::cve_database_exists();
    let has_malware = crate::malware_database_exists();

    println!(
        "CVE database: {}",
        if has_cve {
            "installed".green()
        } else {
            "not found".yellow()
        }
    );
    println!(
        "Malware hash database: {}",
        if has_malware {
            "installed".green()
        } else {
            "not found".yellow()
        }
    );
    println!();

    // 2. Download/update CVE database
    let cve_prompt = if has_cve {
        "Update CVE database? (~50MB, CISA KEV + NVD)"
    } else {
        "Download CVE database? (~50MB, CISA KEV + NVD)"
    };
    if prompt_yn(cve_prompt, !has_cve) {
        println!();
        if let Err(e) = linux_guardian::cve_db::update_database().await {
            eprintln!("{}", format!("CVE database failed: {}", e).red());
        } else {
            println!("{}", "CVE database ready.".green());
        }
        println!();
    }

    // 3. Download/update malware hash database
    let malware_prompt = if has_malware {
        "Update malware hash database? (~200MB, 4M+ signatures from MalwareBazaar)"
    } else {
        "Download malware hash database? (~200MB, 4M+ signatures from MalwareBazaar)"
    };
    if prompt_yn(malware_prompt, !has_malware) {
        println!();
        if let Err(e) = detectors::malware_hash_db::update_malware_database().await {
            eprintln!("{}", format!("Malware database failed: {}", e).red());
        } else {
            println!("{}", "Malware hash database ready.".green());
        }
        println!();
    }

    // 4. Show privilege info
    let is_root = check_privileges();
    println!();
    if is_root {
        println!("Running as: {}", "root (full access)".green());
    } else {
        println!("Running as: {}", "non-root (limited)".yellow());
        println!("  Most checks work fine without root.");
        println!("  Run with sudo for complete coverage.");
    }

    // 5. Offer to run first scan
    println!();
    if prompt_yn("Run a quick scan now?", true) {
        println!();
        // Re-parse with no args to run default scan
        let scan_args = crate::Args::parse_from(["linux-guardian"]);
        let server_context = linux_guardian::server_context::ServerContext::detect();
        let mut suppression_config =
            linux_guardian::server_context::SuppressionConfig::load_default();
        suppression_config.merge_with_context(&server_context);

        crate::print_banner();
        let start = Instant::now();
        let findings = crate::run_scan(
            &scan_args,
            ScanMode::Fast,
            is_root,
            &server_context,
            &suppression_config,
        )
        .await?;
        let duration = start.elapsed();

        output::print_findings(&findings, OutputStyle::Terminal, false, false);
        println!("\n  Scan completed in {:.2}s", duration.as_secs_f32());
    }

    println!("\n{}", "Setup complete!".green().bold());
    println!("  linux-guardian          # fast scan");
    println!("  linux-guardian --deep   # full scan");
    println!("  linux-guardian update   # update databases");

    Ok(())
}

pub(crate) async fn run_update() -> Result<()> {
    println!("Updating all databases...\n");
    if let Err(e) = linux_guardian::cve_db::update_database().await {
        eprintln!("CVE database update failed: {}", e);
        std::process::exit(1);
    }
    println!("CVE database updated.\n");
    if let Err(e) = detectors::malware_hash_db::update_malware_database().await {
        eprintln!("Malware hash database update failed: {}", e);
        std::process::exit(1);
    }
    println!("\nAll databases updated.");
    Ok(())
}

pub(crate) async fn run_stats() -> Result<()> {
    match linux_guardian::cve_db::get_database_stats() {
        Ok(stats) => {
            println!("CVE Database:");
            println!("  Total CVEs: {}", stats.total_cves);
            println!("  Critical (CVSS >= 9.0): {}", stats.critical_cves);
            println!("  Actively Exploited: {}", stats.actively_exploited);
            if let Some(last_update) = stats.last_update {
                println!("  Last Updated: {}", last_update);
            } else {
                println!("  Last Updated: Never (run: linux-guardian update)");
            }
        }
        Err(e) => {
            eprintln!("No CVE database: {} (run: linux-guardian update)", e);
        }
    }
    println!();
    if let Err(e) = detectors::malware_hash_db::show_malware_db_stats().await {
        eprintln!("No malware database: {} (run: linux-guardian update)", e);
    }
    Ok(())
}

pub(crate) fn run_config() -> Result<()> {
    println!(
        "{}",
        linux_guardian::server_context::SuppressionConfig::example_toml()
    );
    Ok(())
}

pub(crate) fn run_privileges() -> Result<()> {
    crate::print_privilege_info_table();
    Ok(())
}
