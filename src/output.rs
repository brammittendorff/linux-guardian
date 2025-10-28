/// Output formatting for different modes
use crate::models::{Finding, OutputStyle, SecurityScore};
use colored::Colorize;

pub fn print_findings(
    findings: &[Finding],
    style: OutputStyle,
    show_score: bool,
    show_summary_only: bool,
) {
    match style {
        OutputStyle::Json => print_json(findings),
        OutputStyle::Simple => print_simple(findings, show_score, show_summary_only),
        OutputStyle::Summary => print_summary_only(findings),
        OutputStyle::Terminal => print_terminal(findings, show_score, show_summary_only),
    }
}

fn print_json(findings: &[Finding]) {
    println!("{}", serde_json::to_string_pretty(findings).unwrap());
}

fn print_summary_only(findings: &[Finding]) {
    let score = SecurityScore::calculate(findings);

    println!("\n{}", "═".repeat(60));
    println!("{}", "  SECURITY HEALTH SCORE".bold());
    println!("{}", "═".repeat(60));

    print_score_bar(score.overall);

    println!("\n{}", "Breakdown:".bold());
    println!(
        "  🟢 Malware Detection:     {}/100",
        score.malware_detection
    );
    println!("  🟡 System Hardening:      {}/100", score.system_hardening);
    println!("  🔵 Privacy:               {}/100", score.privacy);
    println!("  🟠 Network Security:      {}/100", score.network_security);

    println!("\n{}", "Issues:".bold());
    println!("  🔴 Critical: {}", score.critical_count);
    println!("  🟠 High:     {}", score.high_count);
    println!("  🟡 Medium:   {}", score.medium_count);
    println!("  ⚪ Low:      {}", score.low_count);

    let threats = findings.iter().filter(|f| f.is_threat()).count();
    if threats > 0 {
        println!("\n⚠️  {} active threats detected!", threats);
    } else {
        println!("\n✓ No active threats detected");
    }
}

fn print_simple(findings: &[Finding], show_score: bool, show_summary_only: bool) {
    if show_score || show_summary_only {
        print_summary_only(findings);
        if show_summary_only {
            return;
        }
        println!();
    }

    // Separate threats from hardening suggestions
    let threats: Vec<_> = findings.iter().filter(|f| f.is_threat()).collect();
    let hardening: Vec<_> = findings.iter().filter(|f| !f.is_threat()).collect();

    if !threats.is_empty() {
        println!("{}", "═".repeat(60));
        println!("{}", "  🚨 ACTIVE THREATS (Fix Immediately)".red().bold());
        println!("{}", "═".repeat(60));

        for (i, finding) in threats.iter().enumerate() {
            println!("\n[{}] {}", i + 1, finding.title.bold());
            println!("    What happened: {}", finding.description);
            println!("    Risk: {}", get_simple_risk(&finding.severity));
            if let Some(remediation) = &finding.remediation {
                println!("    Fix: {}", remediation.green());
            }
        }
    } else {
        println!("{}", "═".repeat(60));
        println!("{}", "  ✓ No Active Threats Detected".green().bold());
        println!("{}", "═".repeat(60));
    }

    if !hardening.is_empty() {
        println!("\n{}", "═".repeat(60));
        println!("{}", "  💡 Security Suggestions (Optional)".blue().bold());
        println!("{}", "═".repeat(60));
        println!("\nThese are ways to improve your security:");
        println!("(You're not hacked, but these make you safer)\n");

        for (i, finding) in hardening.iter().take(5).enumerate() {
            println!("[{}] {}", i + 1, finding.title);
            if let Some(remediation) = &finding.remediation {
                println!("    → {}", remediation);
            }
        }

        if hardening.len() > 5 {
            println!("\n    ... and {} more suggestions", hardening.len() - 5);
            println!("    (Run with --verbose to see all)");
        }
    }
}

fn print_terminal(findings: &[Finding], show_score: bool, show_summary_only: bool) {
    if show_score || show_summary_only {
        print_summary_only(findings);
        if show_summary_only {
            return;
        }
        println!();
    }

    // Group by severity
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == "critical")
        .collect();
    let high: Vec<_> = findings.iter().filter(|f| f.severity == "high").collect();
    let medium: Vec<_> = findings.iter().filter(|f| f.severity == "medium").collect();
    let low: Vec<_> = findings.iter().filter(|f| f.severity == "low").collect();

    println!("Security Findings:");
    println!("{}", "═".repeat(60));

    // Print by severity (low to critical, so critical appears at bottom)
    for finding in &low {
        print_finding(finding, "⚪ LOW");
    }
    for finding in &medium {
        print_finding(finding, "🟡 MEDIUM");
    }
    for finding in &high {
        print_finding(finding, "🟠 HIGH");
    }
    for finding in &critical {
        print_finding(finding, "🔴 CRITICAL");
    }

    // Summary
    println!("{}", "═".repeat(60));
    println!("Summary:");
    println!("  🔴 Critical: {}", critical.len());
    println!("  🟠 High:     {}", high.len());
    println!("  🟡 Medium:   {}", medium.len());
    println!("  ⚪ Low:      {}", low.len());
}

fn print_finding(finding: &Finding, severity_label: &str) {
    println!("\n{} {}", severity_label, finding.title.bold());
    println!("  Category: {}", finding.category);
    println!("  {}", finding.description);

    if let Some(remediation) = &finding.remediation {
        println!("  💡 Remediation: {}", remediation.green());
    }

    if let Some(cve) = &finding.cve {
        println!("  🔗 CVE: {}", cve);
    }
}

fn print_score_bar(score: u32) {
    let rating = match score {
        90..=100 => ("Excellent", "green"),
        75..=89 => ("Good", "yellow"),
        60..=74 => ("Fair", "yellow"),
        40..=59 => ("Poor", "red"),
        _ => ("Critical", "red"),
    };

    let bar_length = (score as usize * 40) / 100;
    let bar = "█".repeat(bar_length);
    let empty = "░".repeat(40 - bar_length);

    println!("\nOverall Score: {}/100 ({})", score, rating.0.bold());
    println!("{}{} {}%", bar.color(rating.1), empty, score);
}

fn get_simple_risk(severity: &str) -> &str {
    match severity {
        "critical" => "Very High - Fix Now!",
        "high" => "High - Fix Today",
        "medium" => "Medium - Fix This Week",
        "low" => "Low - Optional",
        _ => "Unknown",
    }
}

pub fn print_progress(message: &str, percent: usize) {
    let bar_length = (percent * 30) / 100;
    let bar = "▓".repeat(bar_length);
    let empty = "░".repeat(30 - bar_length);

    print!("\r{} {}{} {}%  ", message, bar, empty, percent);
    use std::io::Write;
    std::io::stdout().flush().unwrap();

    if percent >= 100 {
        println!(); // New line when complete
    }
}
