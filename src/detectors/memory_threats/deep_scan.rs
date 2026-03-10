use super::utils::{parse_address_range, read_process_memory};
use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::collections::HashMap;
use std::fs;
use tracing::{debug, info};

/// Deep memory scan: read process memory for ELF headers in anonymous regions
/// Requires root (reads /proc/PID/mem)
pub async fn deep_scan_process_memory(is_root: bool) -> Result<Vec<Finding>> {
    if !is_root {
        debug!("Skipping deep memory scan (requires root)");
        return Ok(Vec::new());
    }

    info!("🔍 Deep scanning process memory for injected code...");
    let mut findings = Vec::new();

    let processes = match all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            debug!("Could not enumerate processes: {}", e);
            return Ok(findings);
        }
    };

    for process_result in processes {
        let process = match process_result {
            Ok(p) => p,
            Err(_) => continue,
        };

        let pid = process.pid;
        let comm = process
            .stat()
            .ok()
            .map(|s| s.comm.clone())
            .unwrap_or_default();

        // Skip kernel threads and our own process
        if comm.starts_with('[') && comm.ends_with(']') {
            continue;
        }
        if pid <= 1 || pid == std::process::id() as i32 {
            continue;
        }

        let maps_path = format!("/proc/{}/maps", pid);
        let maps = match fs::read_to_string(&maps_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Find anonymous executable regions (potential injected code)
        let mut suspicious_regions = Vec::new();
        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let perms = parts[1];
            let has_path = parts.len() > 5;

            // Look for executable anonymous memory (no file backing)
            if perms.contains('x') && !has_path {
                let region_name = if parts.len() > 5 { parts[5] } else { "" };
                if region_name == "[vdso]" || region_name == "[vvar]" || region_name == "[vsyscall]"
                {
                    continue;
                }

                if let Some((start, end)) = parse_address_range(parts[0]) {
                    let size = end - start;
                    if (4096..=100 * 1024 * 1024).contains(&size) {
                        suspicious_regions.push((start, size.min(4096)));
                    }
                }
            }
        }

        // Skip if likely JIT (many anonymous executable regions)
        if suspicious_regions.len() > 10 {
            debug!(
                "Process {} (PID: {}) has {} anonymous exec regions, likely JIT",
                comm,
                pid,
                suspicious_regions.len()
            );
            continue;
        }

        // Read first bytes of each suspicious region
        for (addr, read_size) in &suspicious_regions {
            match read_process_memory(pid, *addr, *read_size as usize) {
                Ok(data) => {
                    // Check for ELF magic: \x7fELF
                    if data.len() >= 4
                        && data[0] == 0x7f
                        && data[1] == b'E'
                        && data[2] == b'L'
                        && data[3] == b'F'
                    {
                        findings.push(
                            Finding::critical(
                                "memory_injection",
                                "Injected ELF Binary in Process Memory",
                                &format!(
                                    "Process '{}' (PID: {}) has an ELF binary loaded in anonymous \
                                     memory at 0x{:x}. Strong indicator of code injection.",
                                    comm, pid, addr
                                ),
                            )
                            .with_remediation(&format!("Kill immediately: sudo kill -9 {}", pid))
                            .with_details(serde_json::json!({
                                "pid": pid,
                                "comm": comm,
                                "address": format!("0x{:x}", addr),
                                "technique": "process_injection",
                                "mitre_attack": "T1055"
                            })),
                        );
                    }

                    // Check for shellcode patterns
                    if let Some(pattern) = detect_shellcode_patterns(&data) {
                        findings.push(
                            Finding::critical(
                                "memory_injection",
                                "Shellcode Detected in Process Memory",
                                &format!(
                                    "Process '{}' (PID: {}) has shellcode pattern ({}) in \
                                     anonymous memory at 0x{:x}.",
                                    comm, pid, pattern, addr
                                ),
                            )
                            .with_remediation(&format!("Kill immediately: sudo kill -9 {}", pid))
                            .with_details(serde_json::json!({
                                "pid": pid,
                                "comm": comm,
                                "address": format!("0x{:x}", addr),
                                "pattern": pattern,
                                "mitre_attack": "T1055"
                            })),
                        );
                    }

                    // Check for suspicious strings
                    check_suspicious_strings(&data, pid, &comm, *addr, &mut findings);
                }
                Err(_) => {
                    debug!(
                        "Could not read memory of process {} (PID: {}) at 0x{:x}",
                        comm, pid, addr
                    );
                }
            }
        }
    }

    if findings.is_empty() {
        debug!("No injected code found in process memory");
    }

    Ok(findings)
}

/// Detect process hollowing by comparing in-memory text segment vs on-disk binary
/// Requires root
pub async fn detect_process_hollowing(is_root: bool) -> Result<Vec<Finding>> {
    if !is_root {
        debug!("Skipping process hollowing detection (requires root)");
        return Ok(Vec::new());
    }

    info!("🔍 Checking for process hollowing...");
    let mut findings = Vec::new();

    let processes = match all_processes() {
        Ok(procs) => procs,
        Err(e) => {
            debug!("Could not enumerate processes: {}", e);
            return Ok(findings);
        }
    };

    for process_result in processes {
        let process = match process_result {
            Ok(p) => p,
            Err(_) => continue,
        };

        let pid = process.pid;
        let comm = process
            .stat()
            .ok()
            .map(|s| s.comm.clone())
            .unwrap_or_default();

        if comm.starts_with('[') && comm.ends_with(']') {
            continue;
        }
        if pid <= 1 || pid == std::process::id() as i32 {
            continue;
        }

        let exe_link = format!("/proc/{}/exe", pid);
        let exe_path = match fs::read_link(&exe_link) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if exe_path.to_string_lossy().contains("(deleted)") {
            continue;
        }

        let maps_path = format!("/proc/{}/maps", pid);
        let maps = match fs::read_to_string(&maps_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Find the first r-xp mapped region matching the binary (text segment)
        let exe_str = exe_path.to_string_lossy();
        let text_region = maps.lines().find(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() > 5 && parts[1].starts_with("r-x") && line.contains(exe_str.as_ref())
        });

        let text_addr = match text_region {
            Some(line) => {
                let parts: Vec<&str> = line.split_whitespace().collect();
                parse_address_range(parts[0]).map(|(start, _)| start)
            }
            None => continue,
        };

        let text_addr = match text_addr {
            Some(a) => a,
            None => continue,
        };

        let mem_data = match read_process_memory(pid, text_addr, 4096) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let disk_data = match fs::read(&exe_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Compare ELF headers (first 64 bytes)
        if mem_data.len() >= 64 && disk_data.len() >= 64 && mem_data[..64] != disk_data[..64] {
            findings.push(
                Finding::critical(
                    "process_hollowing",
                    "Process Hollowing Detected",
                    &format!(
                        "Process '{}' (PID: {}) has modified ELF header in memory compared \
                         to on-disk binary {}. Indicates process hollowing.",
                        comm, pid, exe_str
                    ),
                )
                .with_remediation(&format!(
                    "Kill immediately: sudo kill -9 {} && verify: sha256sum '{}'",
                    pid, exe_str
                ))
                .with_details(serde_json::json!({
                    "pid": pid,
                    "comm": comm,
                    "exe": exe_str.to_string(),
                    "technique": "process_hollowing",
                    "mitre_attack": "T1055.012"
                })),
            );
        }
    }

    if findings.is_empty() {
        debug!("No process hollowing detected");
    }

    Ok(findings)
}

/// Detect common shellcode patterns in memory
fn detect_shellcode_patterns(data: &[u8]) -> Option<&'static str> {
    if data.len() < 16 {
        return None;
    }

    // NOP sled detection (20+ consecutive NOPs)
    let mut nop_count = 0;
    for &byte in data {
        if byte == 0x90 {
            nop_count += 1;
            if nop_count >= 20 {
                return Some("NOP sled");
            }
        } else {
            nop_count = 0;
        }
    }

    // Common x86_64 shellcode patterns
    for window in data.windows(4) {
        if window == [0x48, 0x31, 0xf6, 0x48] {
            return Some("x86_64 execve setup");
        }
    }

    // Multiple syscall instructions in a small region
    let mut syscall_count = 0;
    for window in data.windows(2) {
        if window == [0x0f, 0x05] || window == [0xcd, 0x80] {
            syscall_count += 1;
        }
    }
    if syscall_count >= 3 && data.len() < 4096 {
        return Some("multiple syscall instructions");
    }

    None
}

/// Check for suspicious strings in executable memory
fn check_suspicious_strings(
    data: &[u8],
    pid: i32,
    comm: &str,
    addr: u64,
    findings: &mut Vec<Finding>,
) {
    let mut strings = Vec::new();
    let mut current = String::new();
    for &byte in data {
        if (0x20..0x7f).contains(&byte) {
            current.push(byte as char);
        } else {
            if current.len() >= 6 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        strings.push(current);
    }

    let suspicious_indicators: HashMap<&str, &str> = [
        ("/bin/sh", "shell execution"),
        ("/bin/bash", "shell execution"),
        ("stratum+tcp://", "cryptomining pool"),
        ("stratum+ssl://", "cryptomining pool"),
        ("/dev/tcp/", "bash reverse shell"),
        ("socket", "network socket"),
        ("connect", "network connection"),
    ]
    .iter()
    .copied()
    .collect();

    for s in &strings {
        let s_lower = s.to_lowercase();
        for (indicator, desc) in &suspicious_indicators {
            if s_lower.contains(&indicator.to_lowercase()) {
                findings.push(
                    Finding::high(
                        "memory_injection",
                        "Suspicious String in Executable Memory",
                        &format!(
                            "Process '{}' (PID: {}) has {} indicator ('{}') in anonymous \
                             executable memory at 0x{:x}.",
                            comm, pid, desc, indicator, addr
                        ),
                    )
                    .with_remediation(&format!(
                        "Investigate: sudo kill -9 {} if unauthorized",
                        pid
                    )),
                );
                return; // One finding per region is enough
            }
        }
    }
}
