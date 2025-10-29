use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::fs;
use tracing::{debug, info};

/// Detect processes with writable + executable memory (code injection indicator)
pub async fn detect_memory_injection() -> Result<Vec<Finding>> {
    info!("🔍 Checking for memory injection indicators...");
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

        // Read /proc/pid/maps to check memory regions
        let maps_path = format!("/proc/{}/maps", pid);
        if let Ok(maps_content) = fs::read_to_string(&maps_path) {
            check_memory_maps(&process, &maps_content, &mut findings);
        }

        // Check ASLR per-process
        check_process_aslr(pid, &mut findings);
    }

    if findings.is_empty() {
        debug!("Memory injection check passed");
    }

    Ok(findings)
}

/// Detect if a process is likely a JIT compiler based on memory map characteristics
fn is_jit_compiler(maps_content: &str, process_name: &str, anonymous_rwx_count: usize) -> bool {
    let maps_lower = maps_content.to_lowercase();
    let process_lower = process_name.to_lowercase();

    // Generic heuristic 1: Check for JIT-specific file patterns
    // JIT engines typically have these artifacts
    let jit_indicators = [
        "v8_context_snapshot", // V8 snapshot files
        "snapshot_blob",       // V8/Chromium
        "icudtl.dat",          // Internationalization data (Chrome/Node.js/Electron)
        ".node",               // Node.js native modules
        "jvm",                 // Java Virtual Machine
        "jre",                 // Java Runtime Environment
        "hotspot",             // JVM JIT compiler
        "mozjs",               // Mozilla JavaScript
        "javascriptcore",      // WebKit JS engine
        "luajit",              // Lua JIT
        "pypy",                // Python JIT
        "mono",                // .NET runtime
        "dotnet",              // .NET
        "coreclr",             // .NET Core
        "qemu",                // QEMU emulator
        "wasm",                // WebAssembly
        "ruby",                // Ruby (potential JIT)
    ];

    for indicator in &jit_indicators {
        if maps_lower.contains(indicator) {
            return true;
        }
    }

    // Generic heuristic 2: Look for process names that commonly use JIT
    // Browsers, IDEs, language runtimes
    let jit_process_patterns = [
        "chrome", "chromium", "firefox", "safari", "edge", "code", "electron", "discord", "slack",
        "teams", "spotify", "node", "java", "python", "ruby", "mono",
    ];

    for pattern in &jit_process_patterns {
        if process_lower.contains(pattern) {
            return true;
        }
    }

    // 2. Check if process has many anonymous RWX regions (JIT pattern)
    // If it has 5+ RWX regions, it's almost certainly a JIT compiler
    if anonymous_rwx_count >= 5 {
        return true;
    }

    // 3. Count total anonymous regions to detect JIT behavior
    let total_anonymous = maps_content
        .lines()
        .filter(|line| {
            !line.contains('/')
                && !line.contains("[vdso]")
                && !line.contains("[vvar]")
                && !line.contains("[vsyscall]")
                && !line.contains("[stack")
                && !line.contains("[heap]")
        })
        .count();

    // If process has MANY anonymous regions (50+), even with 1-2 RWX = likely JIT
    // JIT compilers allocate many code pages
    if total_anonymous >= 50 && anonymous_rwx_count > 0 {
        return true;
    }

    // 4. Medium number of anonymous regions + some RWX = possible JIT
    if total_anonymous >= 20 && anonymous_rwx_count >= 3 {
        return true;
    }

    false
}

fn check_memory_maps(
    process: &procfs::process::Process,
    maps_content: &str,
    findings: &mut Vec<Finding>,
) {
    let pid = process.pid;
    let comm = process.stat().ok().map(|s| s.comm).unwrap_or_default();

    let mut has_rwx_memory = false;
    let mut has_heap_executable = false;
    let mut has_stack_executable = false;
    let mut rwx_regions = Vec::new();
    let mut anonymous_rwx_count = 0;

    for line in maps_content.lines() {
        // Format: address perms offset dev inode pathname
        // Example: 00400000-00401000 r-xp 00000000 08:01 12345 /bin/bash
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let perms = parts[1];

        // Check for rwx (read, write, execute) memory regions
        if perms.starts_with("rwx") {
            has_rwx_memory = true;
            let region_desc = if parts.len() > 5 {
                parts[5..].join(" ")
            } else {
                parts[0].to_string()
            };
            rwx_regions.push(region_desc);
        }

        // Check for executable heap (very suspicious!)
        if perms.contains('x') && line.contains("[heap]") {
            has_heap_executable = true;
        }

        // Check for executable stack (also suspicious)
        if perms.contains('x') && line.contains("[stack]") {
            has_stack_executable = true;
        }

        // Count anonymous executable memory (shellcode injection)
        if perms.contains('x') && perms.contains('w') && !line.contains('/') {
            // Anonymous memory that's writable and executable
            if !line.contains("[vdso]") && !line.contains("[vvar]") {
                anonymous_rwx_count += 1;
            }
        }
    }

    // Report anonymous RWX memory once per process with count
    if anonymous_rwx_count > 0 {
        // Detect if this is likely a JIT compiler
        let is_likely_jit = is_jit_compiler(maps_content, &comm, anonymous_rwx_count);

        // Single RWX region is often from legitimate native libraries (Python extensions, etc.)
        // Multiple RWX regions are much more suspicious
        let is_suspicious = anonymous_rwx_count >= 2;

        if !is_likely_jit && is_suspicious {
            findings.push(
                Finding::critical(
                    "memory_injection",
                    "Writable + Executable Anonymous Memory",
                    &format!(
                        "Process '{}' (PID: {}) has {} anonymous RWX memory regions. Likely code injection!",
                        comm, pid, anonymous_rwx_count
                    ),
                )
                .with_remediation(&format!(
                    "Investigate: cat /proc/{}/maps && sudo kill -9 {}",
                    pid, pid
                )),
            );
        } else {
            debug!(
                "Process {} (PID: {}) has {} anonymous RWX regions but appears to be JIT compiler",
                comm, pid, anonymous_rwx_count
            );
        }
    }

    // Writable + executable memory in legitimate programs is rare
    if has_rwx_memory && rwx_regions.len() > 2 {
        // Detect if this is likely a JIT compiler
        let is_likely_jit = is_jit_compiler(maps_content, &comm, anonymous_rwx_count);

        if !is_likely_jit {
            findings.push(
                Finding::high(
                    "rwx_memory",
                    "Process with Writable + Executable Memory",
                    &format!(
                        "Process '{}' (PID: {}) has {} RWX memory regions. Possible code injection!",
                        comm,
                        pid,
                        rwx_regions.len()
                    ),
                )
                .with_remediation(&format!("Investigate: cat /proc/{}/maps", pid)),
            );
        } else {
            debug!(
                "Process {} (PID: {}) has RWX memory but appears to be JIT compiler",
                comm, pid
            );
        }
    }

    // Executable heap is almost always malicious
    // Exception: JIT compilers legitimately use executable heap for code generation
    if has_heap_executable {
        let is_likely_jit = is_jit_compiler(maps_content, &comm, anonymous_rwx_count);

        if !is_likely_jit {
            findings.push(
                Finding::critical(
                    "executable_heap",
                    "Process with Executable Heap",
                    &format!(
                        "Process '{}' (PID: {}) has executable heap. Clear sign of exploitation/injection!",
                        comm, pid
                    ),
                )
                .with_remediation(&format!("Kill immediately: sudo kill -9 {}", pid)),
            );
        } else {
            debug!(
                "Process {} (PID: {}) has executable heap but appears to be JIT compiler",
                comm, pid
            );
        }
    }

    // Executable stack (common in exploits)
    if has_stack_executable {
        // Some old binaries have executable stack (legacy)
        findings.push(
            Finding::high(
                "executable_stack",
                "Process with Executable Stack",
                &format!(
                    "Process '{}' (PID: {}) has executable stack. Vulnerable to stack-based exploits!",
                    comm, pid
                ),
            )
            .with_remediation(&format!("Investigate: file /proc/{}/exe", pid)),
        );
    }
}

fn check_process_aslr(pid: i32, findings: &mut Vec<Finding>) {
    // Check if ASLR is disabled for this process
    let personality_path = format!("/proc/{}/personality", pid);
    if let Ok(personality_content) = fs::read_to_string(&personality_path) {
        if let Ok(personality) = personality_content.trim().parse::<u32>() {
            // ADDR_NO_RANDOMIZE = 0x0040000
            const ADDR_NO_RANDOMIZE: u32 = 0x0040000;

            if personality & ADDR_NO_RANDOMIZE != 0 {
                if let Ok(process) = procfs::process::Process::new(pid) {
                    let comm = process.stat().ok().map(|s| s.comm).unwrap_or_default();

                    findings.push(
                        Finding::medium(
                            "aslr_disabled",
                            "ASLR Disabled for Process",
                            &format!(
                                "Process '{}' (PID: {}) has ASLR disabled. Easier to exploit!",
                                comm, pid
                            ),
                        )
                        .with_remediation("This is unusual. Investigate if legitimate."),
                    );
                }
            }
        }
    }
}

/// Check for core dumps in suspicious locations
pub async fn check_core_dumps() -> Result<Vec<Finding>> {
    info!("🔍 Checking for suspicious core dumps...");
    let mut findings = Vec::new();

    // Common locations for core dumps
    let core_locations = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/var/crash",
        "/var/lib/systemd/coredump",
    ];

    for location in &core_locations {
        if let Ok(entries) = fs::read_dir(location) {
            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name().unwrap_or_default().to_string_lossy();

                // Check for core dump files
                if filename.starts_with("core")
                    || filename.contains("core.")
                    || filename.ends_with(".core")
                {
                    if let Ok(metadata) = entry.metadata() {
                        let size = metadata.len();
                        let modified = metadata.modified().ok();

                        let age = if let Some(mod_time) = modified {
                            std::time::SystemTime::now()
                                .duration_since(mod_time)
                                .unwrap_or_default()
                                .as_secs()
                        } else {
                            0
                        };

                        // Recent core dumps (< 24 hours) are more interesting
                        if age < 24 * 3600 {
                            findings.push(
                                Finding::medium(
                                    "recent_core_dump",
                                    "Recent Core Dump Found",
                                    &format!(
                                        "Core dump '{}' found in {} ({:.1} MB, {:.1} hours old). Could indicate exploitation attempt.",
                                        filename,
                                        location,
                                        size as f64 / 1_048_576.0,
                                        age as f64 / 3600.0
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate: file '{}' && strings '{}' | head -20",
                                    path.display(),
                                    path.display()
                                )),
                            );
                        }

                        // Core dumps in /tmp or /dev/shm are especially suspicious
                        if *location == "/tmp" || *location == "/dev/shm" {
                            findings.push(
                                Finding::high(
                                    "core_in_temp",
                                    "Core Dump in Temporary Directory",
                                    &format!(
                                        "Core dump in temporary location: {}. Possible exploitation!",
                                        path.display()
                                    ),
                                )
                                .with_remediation(&format!(
                                    "Investigate immediately: file '{}' && strings '{}' | grep -E '(http|tcp|shell|password)'",
                                    path.display(),
                                    path.display()
                                )),
                            );
                        }
                    }
                }
            }
        }
    }

    // Check core dump settings
    if let Ok(core_pattern) = fs::read_to_string("/proc/sys/kernel/core_pattern") {
        let core_pattern = core_pattern.trim();

        // Core dumps piped to a program can be dangerous
        if core_pattern.starts_with('|') {
            findings.push(
                Finding::medium(
                    "core_pattern_piped",
                    "Core Dumps Piped to Program",
                    &format!(
                        "Core pattern is set to pipe: '{}'. Could be exfiltrating crashes.",
                        core_pattern
                    ),
                )
                .with_remediation("Review: cat /proc/sys/kernel/core_pattern"),
            );
        }
    }

    if findings.is_empty() {
        debug!("Core dump check passed");
    }

    Ok(findings)
}
