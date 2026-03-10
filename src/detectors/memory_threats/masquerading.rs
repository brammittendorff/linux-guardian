use super::utils::truncate_str;
use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::fs;
use tracing::{debug, info};

/// Detect process masquerading (comm/exe/cmdline mismatch)
/// Works without root
pub async fn detect_process_masquerading() -> Result<Vec<Finding>> {
    info!("🔍 Checking for process masquerading...");
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

        let comm = match process.stat() {
            Ok(s) => s.comm.clone(),
            Err(_) => continue,
        };

        let exe_link = format!("/proc/{}/exe", pid);
        let exe_path = match fs::read_link(&exe_link) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline = match fs::read_to_string(&cmdline_path) {
            Ok(c) => c.replace('\0', " ").trim().to_string(),
            Err(_) => continue,
        };

        // Skip kernel threads (empty cmdline, bracketed comm)
        if cmdline.is_empty() || (comm.starts_with('[') && comm.ends_with(']')) {
            continue;
        }

        // Check 1: Userspace process pretending to be a kernel thread
        if comm.starts_with('[') && comm.ends_with(']') && !cmdline.is_empty() {
            findings.push(
                Finding::critical(
                    "process_masquerading",
                    "Process Masquerading as Kernel Thread",
                    &format!(
                        "Process (PID: {}) has kernel thread name '{}' but has cmdline: '{}'. \
                         Binary: {}. Userspace processes should not have kernel thread names.",
                        pid,
                        comm,
                        truncate_str(&cmdline, 100),
                        exe_path
                    ),
                )
                .with_remediation(&format!(
                    "Investigate immediately: ls -la /proc/{}/exe && cat /proc/{}/cmdline",
                    pid, pid
                ))
                .with_details(serde_json::json!({
                    "pid": pid,
                    "comm": comm,
                    "exe": exe_path,
                    "cmdline": cmdline,
                    "technique": "process_masquerading",
                    "mitre_attack": "T1036.004"
                })),
            );
            continue;
        }

        // Check 2: exe basename doesn't match comm (process renamed itself)
        let exe_basename = exe_path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .replace(" (deleted)", "");

        // comm is truncated to 15 chars by the kernel
        let comm_matches_exe = if exe_basename.len() > 15 {
            exe_basename.starts_with(&comm)
        } else {
            comm == exe_basename
        };

        if !comm_matches_exe && !exe_path.contains("(deleted)") {
            let is_interpreter = is_interpreter_binary(&exe_basename);
            let is_multicall = exe_basename == "busybox" || exe_path.contains("applets");

            if !is_interpreter && !is_multicall {
                let impersonating_system = is_system_process_name(&comm)
                    && !exe_path.starts_with("/usr/")
                    && !exe_path.starts_with("/lib/")
                    && !exe_path.starts_with("/sbin/")
                    && !exe_path.starts_with("/bin/");

                if impersonating_system {
                    findings.push(
                        Finding::critical(
                            "process_masquerading",
                            "Process Impersonating System Binary",
                            &format!(
                                "Process (PID: {}) claims to be '{}' but runs from '{}'. \
                                 Legitimate '{}' should run from system paths.",
                                pid, comm, exe_path, comm
                            ),
                        )
                        .with_remediation(&format!(
                            "Kill and investigate: sudo kill -9 {} && file '{}'",
                            pid, exe_path
                        )),
                    );
                }
            }
        }

        // Check 3: cmdline[0] doesn't match exe (process rewrote argv[0])
        let cmdline_binary = cmdline.split_whitespace().next().unwrap_or("");
        let cmdline_basename = cmdline_binary.rsplit('/').next().unwrap_or("");

        if !cmdline_basename.is_empty()
            && cmdline_basename != exe_basename
            && !exe_path.contains("(deleted)")
        {
            let exe_is_interpreter = is_interpreter_binary(&exe_basename);
            let is_known_rewriter = comm == "postgres"
                || comm == "nginx"
                || comm == "apache2"
                || comm == "httpd"
                || comm.starts_with("php-fpm");

            if !exe_is_interpreter
                && !is_known_rewriter
                && is_system_process_name(cmdline_basename)
                && !exe_path.starts_with("/usr/")
                && !exe_path.starts_with("/lib/")
                && !exe_path.starts_with("/sbin/")
                && !exe_path.starts_with("/bin/")
            {
                findings.push(
                    Finding::high(
                        "process_masquerading",
                        "Process Rewrote argv[0] to System Binary Name",
                        &format!(
                            "Process (PID: {}) cmdline shows '{}' but actual binary is '{}'. \
                             May be hiding its true identity.",
                            pid, cmdline_basename, exe_path
                        ),
                    )
                    .with_remediation(&format!(
                        "Investigate: readlink /proc/{}/exe && cat /proc/{}/cmdline",
                        pid, pid
                    )),
                );
            }
        }
    }

    if findings.is_empty() {
        debug!("No process masquerading detected");
    }

    Ok(findings)
}

fn is_interpreter_binary(name: &str) -> bool {
    matches!(
        name,
        "bash" | "sh" | "python3" | "python" | "perl" | "ruby" | "node" | "java" | "dotnet"
    )
}

fn is_system_process_name(name: &str) -> bool {
    const SYSTEM_NAMES: &[&str] = &[
        "sshd",
        "cron",
        "systemd",
        "init",
        "bash",
        "sh",
        "login",
        "getty",
        "udevd",
        "dbus-daemon",
        "rsyslogd",
        "journald",
        "networkd",
        "resolved",
        "timesyncd",
        "polkitd",
        "cupsd",
        "atd",
        "kworker",
        "ksoftirqd",
        "migration",
        "watchdog",
    ];
    SYSTEM_NAMES.iter().any(|&s| name == s || name.contains(s))
}
