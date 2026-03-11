use super::allowlists::*;
use super::elf_parser::*;
use super::shellcode::*;
use super::utils::{parse_address_range, read_process_memory};
use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
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

/// Detect process hollowing by comparing .text section hashes between
/// in-memory and on-disk binaries.
///
/// # Why .text section comparison?
///
/// The .text section is mapped read-only + executable (r-xp) and is NEVER
/// modified by the dynamic linker on modern PIE/PIC binaries. All relocations
/// (R_X86_64_RELATIVE, GOT/PLT patching) only affect data segments. If the
/// .text section in memory differs from disk, code has been tampered with.
///
/// This replaces the old naive ELF header comparison which produced massive
/// false positives because ASLR/PIE relocation legitimately modifies header
/// fields like e_entry, e_phoff, e_shoff.
///
/// # False positive prevention
/// - Skips binaries with DT_TEXTREL (rare; text relocations modify .text legitimately)
/// - Skips known JIT/Electron processes (Chrome, VS Code, Python, Java, etc.)
/// - Skips processes being actively debugged (breakpoints modify .text)
/// - Compares only the .text section, not headers or data segments
///
/// Requires root.
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

        // Skip kernel threads and our own process
        if comm.starts_with('[') && comm.ends_with(']') {
            continue;
        }
        if pid <= 1 || pid == std::process::id() as i32 {
            continue;
        }

        // Resolve /proc/PID/exe
        let exe_link = format!("/proc/{}/exe", pid);
        let exe_path = match fs::read_link(&exe_link) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip deleted binaries (handled by fileless malware detector)
        if exe_path.to_string_lossy().contains("(deleted)") {
            continue;
        }

        let exe_str = exe_path.to_string_lossy();

        // Skip processes known to legitimately modify executable memory (JIT, Electron/V8)
        if is_known_self_modifying_process(&comm, &exe_str) {
            debug!(
                "Skipping known JIT/self-modifying process {} (PID: {})",
                comm, pid
            );
            continue;
        }

        // Skip processes being debugged (breakpoints modify .text)
        if is_being_traced(pid) {
            debug!("Skipping traced process {} (PID: {})", comm, pid);
            continue;
        }

        // Determine the path to use when opening the binary on disk.
        //
        // For processes running in a different mount namespace (e.g. Docker containers),
        // `fs::read_link("/proc/PID/exe")` resolves through the HOST filesystem. The
        // resulting path (e.g. `/usr/bin/bash`) points to the HOST's bash binary, but the
        // container loaded a DIFFERENT binary from its own overlay filesystem layer. Reading
        // the host binary and comparing it against the container process's in-memory .text
        // section will always produce a mismatch starting at byte 0 — a systematic false
        // positive.
        //
        // The fix: when a process is in a different mount namespace, open the binary via
        // `/proc/PID/root/<exe_path>`. The kernel resolves that path through the process's
        // own filesystem namespace, giving us the exact binary the container loaded.
        //
        // `/proc/PID/maps` always shows the path as seen inside the process's namespace
        // (e.g. `/usr/bin/bash`), so we keep using `exe_str` for the maps lookup — only
        // the on-disk binary read uses the namespace-aware path.
        let disk_binary_path = if is_in_different_mount_namespace(pid) {
            debug!(
                "Process {} (PID: {}) is in a container; reading binary via /proc/{}/root{}",
                comm, pid, pid, exe_str
            );
            std::path::PathBuf::from(format!("/proc/{}/root{}", pid, exe_str))
        } else {
            exe_path.clone()
        };

        // Parse the on-disk ELF to find .text section.
        // We parse from `disk_binary_path` which is namespace-correct.
        let text_info = match parse_elf_text_section(&disk_binary_path) {
            Some(info) => info,
            None => continue,
        };

        // Skip binaries with text relocations (TEXTREL) — .text is legitimately modified
        if text_info.has_textrel {
            debug!(
                "Skipping {} (PID: {}) — has DT_TEXTREL",
                comm, pid
            );
            continue;
        }

        // Find the r-xp file-backed mapping for this binary in /proc/PID/maps
        let maps_path = format!("/proc/{}/maps", pid);
        let maps = match fs::read_to_string(&maps_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let text_mapping = match find_text_mapping(&maps, &exe_str, text_info.file_offset) {
            Some(m) => m,
            None => continue,
        };

        // Calculate the in-memory address of the .text section.
        //
        // Layout: each r-xp mapping covers a contiguous range of the file starting at
        // `text_mapping.file_offset`. The virtual address of any byte at file offset F
        // within that mapping is:
        //
        //   vaddr(F) = mapping_start + (F - mapping_file_offset)
        //
        // find_text_mapping already guarantees that text_info.file_offset falls within
        // [mapping.file_offset, mapping.file_offset + mapping_size), so the subtraction
        // cannot underflow.
        let mem_text_addr =
            text_mapping.start + (text_info.file_offset - text_mapping.file_offset);

        // Read the .text section from memory (limit to 1MB for performance)
        let read_size = text_info.size.min(1024 * 1024) as usize;
        let mem_text = match read_process_memory(pid, mem_text_addr, read_size) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Read the .text section from the namespace-correct on-disk binary
        let disk_text = match read_file_range(
            &disk_binary_path,
            text_info.file_offset,
            read_size,
        ) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Compare hashes
        if mem_text.len() != disk_text.len() || mem_text.len() < 64 {
            continue;
        }

        let mem_hash = sha256_hash(&mem_text);
        let disk_hash = sha256_hash(&disk_text);

        if mem_hash != disk_hash {
            // Find the first differing offset for diagnostics
            let diff_offset = mem_text
                .iter()
                .zip(disk_text.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(0);

            findings.push(
                Finding::critical(
                    "process_hollowing",
                    "Process Code Tampered — .text Section Modified",
                    &format!(
                        "Process '{}' (PID: {}) has a modified .text section compared to \
                         on-disk binary '{}'. The .text section is read-only and should \
                         NEVER differ from disk (ASLR/PIE/dynamic linking do not modify it). \
                         First difference at offset 0x{:x}. This indicates code injection \
                         or process hollowing.",
                        comm, pid, exe_str, diff_offset
                    ),
                )
                .with_remediation(&format!(
                    "Investigate: cat /proc/{}/maps | grep r-xp && \
                     sha256sum '{}' && sudo kill -9 {} if confirmed malicious",
                    pid, exe_str, pid
                ))
                .with_details(serde_json::json!({
                    "pid": pid,
                    "comm": comm,
                    "exe": exe_str.to_string(),
                    "text_size": text_info.size,
                    "mem_hash": mem_hash,
                    "disk_hash": disk_hash,
                    "first_diff_offset": format!("0x{:x}", diff_offset),
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
