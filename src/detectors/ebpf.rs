use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Detect suspicious eBPF programs (rootkits can hide here)
pub async fn detect_ebpf_programs() -> Result<Vec<Finding>> {
    info!("🔍 Checking for suspicious eBPF programs...");
    let mut findings = Vec::new();

    // Check if bpftool is available
    if Command::new("bpftool").arg("--version").output().is_err() {
        debug!("bpftool not available, skipping eBPF detection");
        return Ok(findings);
    }

    // List all loaded eBPF programs
    let output = match Command::new("bpftool").args(["prog", "list"]).output() {
        Ok(o) => o,
        Err(e) => {
            debug!("Failed to run bpftool: {}", e);
            return Ok(findings);
        }
    };

    if !output.status.success() {
        debug!("bpftool prog list failed (may need root)");
        return Ok(findings);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let programs: Vec<&str> = stdout.lines().collect();

    debug!("Found {} eBPF programs loaded", programs.len());

    // Suspicious indicators
    let suspicious_names = ["rootkit", "backdoor", "hide", "stealth", "keylog", "exfil"];

    for line in &programs {
        // Parse eBPF program info
        if line.is_empty() {
            continue;
        }

        // Check for suspicious program names
        let line_lower = line.to_lowercase();
        for suspicious in &suspicious_names {
            if line_lower.contains(suspicious) {
                findings.push(
                    Finding::critical(
                        "ebpf_rootkit",
                        "Suspicious eBPF Program Detected",
                        &format!(
                            "eBPF program with suspicious name detected: {}. This could be a rootkit!",
                            line.trim()
                        ),
                    )
                    .with_remediation("Investigate: sudo bpftool prog show && sudo bpftool prog dump xlated <id>"),
                );
            }
        }

        // Check for programs without a known owner/process
        if line.contains("name (null)") || line.contains("unknown") {
            findings.push(
                Finding::high(
                    "ebpf_unknown",
                    "Unnamed eBPF Program Detected",
                    &format!(
                        "eBPF program without clear ownership: {}. Could indicate malware.",
                        line.trim()
                    ),
                )
                .with_remediation("Investigate: sudo bpftool prog show"),
            );
        }
    }

    // Check for excessive number of eBPF programs (potential DoS or hiding activity)
    if programs.len() > 50 {
        findings.push(
            Finding::medium(
                "ebpf_excessive",
                "Excessive eBPF Programs Loaded",
                &format!(
                    "{} eBPF programs loaded. High count could indicate suspicious activity or rootkit.",
                    programs.len()
                ),
            )
            .with_remediation("Review all programs: sudo bpftool prog list"),
        );
    }

    if findings.is_empty() {
        debug!(
            "eBPF check passed: {} programs, none suspicious",
            programs.len()
        );
    }

    Ok(findings)
}

/// Check for eBPF maps (can store hidden data)
pub async fn detect_ebpf_maps() -> Result<Vec<Finding>> {
    info!("🔍 Checking for suspicious eBPF maps...");
    let mut findings = Vec::new();

    if Command::new("bpftool").arg("--version").output().is_err() {
        return Ok(findings);
    }

    let output = match Command::new("bpftool").args(["map", "list"]).output() {
        Ok(o) => o,
        Err(_) => return Ok(findings),
    };

    if !output.status.success() {
        return Ok(findings);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let maps: Vec<&str> = stdout.lines().collect();

    debug!("Found {} eBPF maps", maps.len());

    // Unusually large maps could store exfiltrated data
    for line in maps {
        if line.contains("max_entries") {
            // Try to parse max_entries value
            if let Some(entries_str) = line.split("max_entries").nth(1) {
                if let Some(num_str) = entries_str.split_whitespace().next() {
                    if let Ok(entries) = num_str.parse::<u64>() {
                        if entries > 100000 {
                            findings.push(
                                Finding::medium(
                                    "ebpf_large_map",
                                    "Unusually Large eBPF Map",
                                    &format!(
                                        "eBPF map with {} entries detected. Could be used to store exfiltrated data.",
                                        entries
                                    ),
                                )
                                .with_remediation("Investigate: sudo bpftool map dump id <id>"),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}
