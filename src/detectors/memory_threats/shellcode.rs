use crate::models::Finding;
use std::collections::HashMap;

/// Detect common shellcode patterns in memory
pub(super) fn detect_shellcode_patterns(data: &[u8]) -> Option<&'static str> {
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
pub(super) fn check_suspicious_strings(
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
