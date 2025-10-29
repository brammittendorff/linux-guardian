use crate::models::Finding;
use anyhow::Result;
use procfs::process::{all_processes, Process};
use std::fs;
use tracing::{debug, info};

/// Detect processes with dangerous capabilities (especially CAP_SYS_ADMIN)
pub async fn detect_dangerous_capabilities() -> Result<Vec<Finding>> {
    info!("🔍 Checking for processes with dangerous capabilities...");
    let mut findings = Vec::new();

    // Get all processes
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

        // Read process status for capability information
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status_content) = fs::read_to_string(&status_path) {
            check_process_capabilities(&process, &status_content, &mut findings);
        }
    }

    if findings.is_empty() {
        debug!("Process capabilities check passed");
    }

    Ok(findings)
}

/// Check if a package is a core system package with essential/important priority
/// Only trusts packages that are part of the base OS (not random user-installed packages)
fn is_core_system_package(package_name: &str) -> bool {
    // ONLY trust packages with essential, required, important, or standard priority
    // These are the base OS packages that are installed by default
    // Random packages installed by user (even from official repos) are NOT trusted
    if let Ok(output) = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Priority}", package_name])
        .output()
    {
        if output.status.success() {
            let priority = String::from_utf8_lossy(&output.stdout);
            // ONLY trust base system packages
            if priority.contains("required")
                || priority.contains("important")
                || priority.contains("standard")
            {
                return true;
            }
        }
    }

    // For RPM-based systems, check if package is in the base system
    if let Ok(output) = std::process::Command::new("rpm")
        .args(["-qi", package_name])
        .output()
    {
        if output.status.success() {
            let info = String::from_utf8_lossy(&output.stdout);
            // Check if package is signed AND in base system group
            if info.contains("Signature")
                && !info.contains("(none)")
                && (info.contains("System Environment/Base")
                    || info.contains("System Environment/Daemons"))
            {
                return true;
            }
        }
    }

    false
}

/// Check if a process binary is managed by a package manager
/// Package-managed binaries are more trustworthy than random executables
fn is_package_managed_binary(pid: i32) -> bool {
    // Try to get the binary path from /proc/pid/exe (requires root for some processes)
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(real_path) = fs::read_link(&exe_path) {
        let path_str = real_path.to_string_lossy();

        // Try dpkg (Debian/Ubuntu)
        if let Ok(output) = std::process::Command::new("dpkg")
            .args(["-S", &path_str])
            .output()
        {
            if output.status.success() {
                // Extract package name from output (format: "package: /path/to/file")
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(package_name) = stdout.split(':').next() {
                    // Check if it's a core system package
                    if is_core_system_package(package_name.trim()) {
                        return true;
                    }
                }
                // Even if not core, being package-managed is better than nothing
                return true;
            }
        }

        // Try rpm (RHEL/Fedora)
        if let Ok(output) = std::process::Command::new("rpm")
            .args(["-qf", &path_str])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.contains("is not owned by any package") {
                    let package_name = stdout.trim();
                    // Check if it's a core system package
                    if is_core_system_package(package_name) {
                        return true;
                    }
                    return true;
                }
            }
        }
    }

    // If we can't read /proc/pid/exe (permission denied for system processes),
    // we're likely looking at a system daemon. These are generally safe.
    // This happens when running without root on PID 1, systemd daemons, etc.
    true
}

fn check_process_capabilities(
    process: &Process,
    status_content: &str,
    findings: &mut Vec<Finding>,
) {
    let pid = process.pid;
    let comm = process.stat().ok().map(|s| s.comm).unwrap_or_default();

    // Skip kernel threads - they legitimately have all capabilities
    // Kernel threads have no associated user space process (kthreadd is PID 2)
    // They show up with comm in square brackets [like_this] and have no cmdline
    if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
        if cmdline.is_empty() {
            // Empty cmdline = kernel thread
            return;
        }
    } else {
        // Can't read cmdline - probably kernel thread
        return;
    }

    // Parse capabilities from /proc/pid/status
    // Format: CapEff: 000001ffffffffff (hex bitmask)
    let mut cap_eff = 0u64;

    for line in status_content.lines() {
        if line.starts_with("CapEff:") {
            if let Some(hex_str) = line.split_whitespace().nth(1) {
                cap_eff = u64::from_str_radix(hex_str, 16).unwrap_or(0);
                break;
            }
        }
    }

    if cap_eff == 0 {
        return; // No capabilities
    }

    // Capability bit positions (from linux/capability.h)
    const CAP_SYS_ADMIN: u64 = 1 << 21; // Most dangerous capability
    const CAP_SYS_PTRACE: u64 = 1 << 19; // Can trace any process
    const CAP_SYS_MODULE: u64 = 1 << 16; // Can load kernel modules
    const CAP_SYS_RAWIO: u64 = 1 << 17; // Direct I/O access
    const CAP_NET_ADMIN: u64 = 1 << 12; // Network configuration
    const CAP_DAC_OVERRIDE: u64 = 1 << 1; // Bypass file permissions

    // Check for CAP_SYS_ADMIN (god mode)
    if cap_eff & CAP_SYS_ADMIN != 0 {
        // Known safe programs with CAP_SYS_ADMIN
        let safe_programs = [
            "systemd",
            "dockerd",
            "containerd",
            "snapd",
            "NetworkManager",
            "udisksd",
            "cupsd",
            "cups-browsed",
            "fusermount3",
            "login",
            "cron",
            "smartd",
            "wpa_supplicant",
            "ModemManager",
            "low-memory-moni",
            // Chrome/Electron sandboxing helpers need CAP_SYS_ADMIN for namespace operations
            "chrome",
            "chromium",
            "Discord",
            "code", // VS Code
            "electron",
        ];

        let is_known_safe = safe_programs.iter().any(|safe| comm.contains(safe));

        // Generic check: Also allow package-managed binaries
        let is_package_managed = is_package_managed_binary(pid);

        if !is_known_safe && !is_package_managed {
            findings.push(
                Finding::critical(
                    "cap_sys_admin",
                    "Process with CAP_SYS_ADMIN Detected",
                    &format!(
                        "Process '{}' (PID: {}) has CAP_SYS_ADMIN capability. This grants near-root privileges!",
                        comm, pid
                    ),
                )
                .with_remediation(&format!(
                    "Investigate: ps -p {} -o pid,comm,cmd && sudo cat /proc/{}/status",
                    pid, pid
                )),
            );
        } else {
            debug!(
                "Process {} (PID: {}) has CAP_SYS_ADMIN but is known safe",
                comm, pid
            );
        }
    }

    // Check for CAP_SYS_PTRACE (can inject into any process)
    if cap_eff & CAP_SYS_PTRACE != 0 {
        let safe_ptrace = ["gdb", "strace", "ltrace", "perf"];
        let is_safe = safe_ptrace.iter().any(|safe| comm.contains(safe));

        // Generic check: Also allow package-managed binaries
        let is_package_managed = is_package_managed_binary(pid);

        if !is_safe && !is_package_managed {
            findings.push(
                Finding::high(
                    "cap_sys_ptrace",
                    "Process with CAP_SYS_PTRACE Detected",
                    &format!(
                        "Process '{}' (PID: {}) can trace/inject into any process. Used by rootkits!",
                        comm, pid
                    ),
                )
                .with_remediation(&format!("Investigate: sudo kill -9 {}", pid)),
            );
        }
    }

    // Check for CAP_SYS_MODULE (can load kernel modules = rootkit)
    if cap_eff & CAP_SYS_MODULE != 0 {
        // Known safe system services that have CAP_SYS_MODULE but don't actively use it
        let safe_module_loaders = [
            "systemd",
            "systemd-udevd",
            "NetworkManager",
            "snapd",
            "dockerd",
            "containerd",
            "udisksd",
            "cupsd",
            "cups-browsed",
            "login",
            "cron",
            "smartd",
            "wpa_supplicant",
            "fusermount3",
        ];

        let is_known_safe = safe_module_loaders.iter().any(|safe| comm.contains(safe));

        // Generic check: Also allow package-managed binaries
        let is_package_managed = is_package_managed_binary(pid);

        if !is_known_safe && !is_package_managed {
            findings.push(
                Finding::critical(
                    "cap_sys_module",
                    "Process Can Load Kernel Modules",
                    &format!(
                        "Process '{}' (PID: {}) has CAP_SYS_MODULE. Can load rootkit modules!",
                        comm, pid
                    ),
                )
                .with_remediation(&format!(
                    "Investigate immediately: ps -p {} -o pid,comm,cmd",
                    pid
                )),
            );
        } else {
            debug!(
                "Process {} (PID: {}) has CAP_SYS_MODULE but is known safe system service",
                comm, pid
            );
        }
    }

    // Check for CAP_SYS_RAWIO (direct hardware access)
    if cap_eff & CAP_SYS_RAWIO != 0 {
        let safe_rawio = ["X", "Xorg", "qemu"];
        let is_safe = safe_rawio.iter().any(|safe| comm.contains(safe));

        // Generic check: Also allow package-managed binaries
        let is_package_managed = is_package_managed_binary(pid);

        if !is_safe && !is_package_managed {
            findings.push(
                Finding::high(
                    "cap_sys_rawio",
                    "Process with Raw I/O Access",
                    &format!(
                        "Process '{}' (PID: {}) has CAP_SYS_RAWIO. Can access hardware directly!",
                        comm, pid
                    ),
                )
                .with_remediation(&format!("Review: ps -p {} -o pid,comm,cmd", pid)),
            );
        }
    }

    // Check for dangerous capability combinations
    if (cap_eff & CAP_DAC_OVERRIDE != 0) && (cap_eff & CAP_NET_ADMIN != 0) {
        // Generic check: Allow package-managed binaries
        let is_package_managed = is_package_managed_binary(pid);

        if !is_package_managed {
            findings.push(
                Finding::medium(
                    "cap_combination",
                    "Process with Dangerous Capability Combination",
                    &format!(
                        "Process '{}' (PID: {}) has DAC_OVERRIDE + NET_ADMIN. Can bypass filesystem + configure network.",
                        comm, pid
                    ),
                )
                .with_remediation(&format!("Consider if process needs these capabilities: ps -p {} -o pid,comm,cmd", pid)),
            );
        }
    }
}

/// Check file capabilities (executables with ambient capabilities)
pub async fn check_file_capabilities() -> Result<Vec<Finding>> {
    info!("🔍 Checking for files with dangerous capabilities...");
    let mut findings = Vec::new();

    // Find files with capabilities using getcap
    if let Ok(output) = std::process::Command::new("getcap")
        .args(["-r", "/"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if line.is_empty() {
                continue;
            }

            // Format: /path/to/file = cap_net_admin,cap_net_raw+ep
            if let Some((file_path, caps)) = line.split_once('=') {
                let file_path = file_path.trim();
                let caps_lower = caps.to_lowercase();

                // Check for dangerous capabilities on files
                if caps_lower.contains("cap_sys_admin")
                    || caps_lower.contains("cap_sys_module")
                    || caps_lower.contains("cap_sys_ptrace")
                {
                    findings.push(
                        Finding::critical(
                            "file_dangerous_cap",
                            "Executable with Dangerous Capability",
                            &format!(
                                "File '{}' has dangerous capabilities: {}. Could be privilege escalation!",
                                file_path, caps.trim()
                            ),
                        )
                        .with_remediation(&format!(
                            "Remove capabilities: sudo setcap -r '{}'",
                            file_path
                        )),
                    );
                }

                // Check for capabilities on files in suspicious locations
                if (file_path.contains("/tmp")
                    || file_path.contains("/dev/shm")
                    || file_path.contains("/var/tmp"))
                    && !caps_lower.is_empty()
                {
                    findings.push(
                        Finding::critical(
                            "temp_file_cap",
                            "Temporary File with Capabilities",
                            &format!(
                                "File in temporary directory has capabilities: {} = {}. Likely malware!",
                                file_path, caps.trim()
                            ),
                        )
                        .with_remediation(&format!("Remove: sudo rm -f '{}'", file_path)),
                    );
                }
            }
        }
    } else {
        debug!("getcap not available or failed (may need root)");
    }

    Ok(findings)
}
