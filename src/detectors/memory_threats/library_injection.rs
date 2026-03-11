use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use std::collections::HashSet;
use std::fs;
use tracing::{debug, info};

/// Detect LD_PRELOAD injection attacks
/// Works without root for own-user processes, needs root for others
pub async fn detect_ld_preload_injection() -> Result<Vec<Finding>> {
    info!("🔍 Checking for LD_PRELOAD injection...");
    let mut findings = Vec::new();

    // Check system-wide LD_PRELOAD files
    check_system_preload(&mut findings);

    // Check per-process LD_PRELOAD
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

        // Read environment variables
        let environ_path = format!("/proc/{}/environ", pid);
        let environ = match fs::read_to_string(&environ_path) {
            Ok(e) => e,
            Err(_) => continue, // Can't read (different user or permission denied)
        };

        // environ is null-byte separated
        for var in environ.split('\0') {
            if let Some(value) = var.strip_prefix("LD_PRELOAD=") {
                if value.is_empty() {
                    continue;
                }

                let is_suspicious = is_suspicious_preload(value);

                if is_suspicious {
                    findings.push(
                        Finding::critical(
                            "library_injection",
                            "Suspicious LD_PRELOAD Injection Detected",
                            &format!(
                                "Process '{}' (PID: {}) has suspicious LD_PRELOAD: {}. \
                                 This is commonly used for credential theft, rootkits, and code injection.",
                                comm, pid, value
                            ),
                        )
                        .with_remediation(&format!(
                            "Investigate: cat /proc/{}/environ | tr '\\0' '\\n' | grep LD_PRELOAD && \
                             sudo kill -9 {}",
                            pid, pid
                        ))
                        .with_details(serde_json::json!({
                            "pid": pid,
                            "comm": comm,
                            "ld_preload": value,
                            "technique": "LD_PRELOAD",
                            "mitre_attack": "T1574.006"
                        })),
                    );
                } else {
                    debug!(
                        "Process {} (PID: {}) has LD_PRELOAD: {} (appears legitimate)",
                        comm, pid, value
                    );
                }
            }

            // Also check LD_LIBRARY_PATH for hijacking
            if let Some(value) = var.strip_prefix("LD_LIBRARY_PATH=") {
                if value.contains("/tmp")
                    || value.contains("/dev/shm")
                    || value.contains("/var/tmp")
                {
                    findings.push(
                        Finding::high(
                            "library_injection",
                            "Suspicious LD_LIBRARY_PATH",
                            &format!(
                                "Process '{}' (PID: {}) has suspicious LD_LIBRARY_PATH: {}. \
                                 May be loading malicious libraries from temporary directories.",
                                comm, pid, value
                            ),
                        )
                        .with_remediation("Investigate why library path includes temp directories"),
                    );
                }
            }
        }

        // Check /proc/PID/maps for injected shared libraries
        check_injected_libraries(pid, &comm, &mut findings);
    }

    if findings.is_empty() {
        debug!("No LD_PRELOAD injection detected");
    }

    Ok(findings)
}

/// Check system-wide preload configuration files
fn check_system_preload(findings: &mut Vec<Finding>) {
    if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if is_suspicious_preload(line) {
                findings.push(
                    Finding::critical(
                        "library_injection",
                        "Suspicious System-Wide LD_PRELOAD",
                        &format!(
                            "/etc/ld.so.preload contains suspicious library: {}. \
                             This affects ALL processes on the system.",
                            line
                        ),
                    )
                    .with_remediation(
                        "Review: cat /etc/ld.so.preload - remove unknown entries immediately",
                    ),
                );
            }
        }
    }
}

/// Check if a preloaded library path is suspicious
fn is_suspicious_preload(path: &str) -> bool {
    let suspicious_locations = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/root/"];
    let legitimate_preloads = [
        "libfakeroot",
        "libjemalloc",
        "libtcmalloc",
        "libasan",
        "libSegFault",
        "libgtk3-nocsd",
        "libsandbox",
        "libtsocks",
        "libproxychains",
        "libnss_",
        "libeatmydata",
    ];

    for loc in &suspicious_locations {
        if path.contains(loc) {
            return true;
        }
    }

    for legit in &legitimate_preloads {
        if path.contains(legit) {
            return false;
        }
    }

    !path.starts_with("/usr/lib") && !path.starts_with("/lib")
}

/// Check /proc/PID/maps for injected shared libraries from suspicious locations
fn check_injected_libraries(pid: i32, comm: &str, findings: &mut Vec<Finding>) {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = match fs::read_to_string(&maps_path) {
        Ok(m) => m,
        Err(_) => return,
    };

    let suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    // Deduplicate: only report each unique library path once per process
    let mut seen_libraries = HashSet::new();

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let path = parts[5..].join(" ");

        // Skip if we already reported this library for this process
        if !seen_libraries.insert(path.clone()) {
            continue;
        }

        // Check for shared libraries loaded from suspicious locations
        if path.ends_with(".so") || path.contains(".so.") {
            for sus in &suspicious_paths {
                if path.starts_with(sus) {
                    findings.push(
                        Finding::critical(
                            "library_injection",
                            "Injected Shared Library from Suspicious Location",
                            &format!(
                                "Process '{}' (PID: {}) has loaded library from suspicious path: {}",
                                comm, pid, path
                            ),
                        )
                        .with_remediation(&format!(
                            "Investigate: ls -la '{}' && cat /proc/{}/maps | grep '{}'",
                            path, pid, sus
                        )),
                    );
                    break;
                }
            }
        }

        // Check for deleted shared libraries (injected then removed)
        if !is_deleted_shared_library(&path) {
            continue;
        }

        // Strip " (deleted)" suffix to get the original path
        let original_path = path.strip_suffix(" (deleted)").unwrap_or(&path);

        // Determine WHY the library was deleted — this distinguishes
        // "app updated and old .so was replaced" from "injected .so was
        // deleted to cover tracks"
        let deletion_reason = classify_deleted_library(original_path, pid);

        match deletion_reason {
            DeletedLibraryReason::ReplacedByUpdate => {
                // A newer version of the file exists at the same path.
                // This is normal after package/app updates — the running
                // process still maps the old (now unlinked) inode while
                // the new version sits on disk.
                debug!(
                    "Deleted library '{}' in process '{}' (PID {}) was replaced by update — benign",
                    original_path, comm, pid
                );
            }
            DeletedLibraryReason::PackageManaged => {
                // The file is gone but the package manager owns that path.
                // Likely mid-update or the process just needs a restart.
                findings.push(
                    Finding::low(
                        "library_stale",
                        "Process Using Outdated Library",
                        &format!(
                            "Process '{}' (PID {}) still maps deleted library '{}' which is \
                             package-managed. The package was likely updated — restart the \
                             process to load the new version.",
                            comm, pid, original_path
                        ),
                    )
                    .with_remediation(&format!(
                        "Restart the process to pick up the updated library. Check: dpkg -S '{}'",
                        original_path
                    )),
                );
            }
            DeletedLibraryReason::ProcessExeDirectory => {
                // The deleted lib lived in the same directory as the
                // process executable.  This strongly suggests the
                // application itself was updated (e.g. Chrome, VS Code,
                // Electron apps).
                findings.push(
                    Finding::low(
                        "library_stale",
                        "Process Using Outdated Library (App Update)",
                        &format!(
                            "Process '{}' (PID {}) still maps deleted library '{}'. \
                             The library was in the application's own directory, suggesting \
                             the application was updated while running.",
                            comm, pid, original_path
                        ),
                    )
                    .with_remediation("Restart the application to load updated libraries"),
                );
            }
            DeletedLibraryReason::SuspiciousLocation => {
                // Library was loaded from /tmp, /dev/shm, etc. and then
                // deleted — classic injection-then-cleanup pattern.
                findings.push(
                    Finding::critical(
                        "library_injection",
                        "Deleted Injected Library (Suspicious Location)",
                        &format!(
                            "Process '{}' (PID {}) has a deleted library mapped from a \
                             suspicious location: '{}'. Loading a library from a temporary \
                             directory and then deleting it is a common code injection technique.",
                            comm, pid, original_path
                        ),
                    )
                    .with_remediation(&format!(
                        "URGENT: Investigate process: sudo ls -la /proc/{}/exe && \
                         sudo cat /proc/{}/maps | grep deleted && \
                         sudo kill -9 {} if confirmed malicious",
                        pid, pid, pid
                    )),
                );
            }
            DeletedLibraryReason::TrulyDeleted => {
                // File is gone, no replacement, not package-managed, not
                // from the app's own dir — genuinely suspicious.
                findings.push(
                    Finding::high(
                        "library_injection",
                        "Deleted Shared Library Still Loaded",
                        &format!(
                            "Process '{}' (PID {}) has a deleted library still mapped: '{}'. \
                             The file no longer exists on disk and is not package-managed. \
                             This may indicate code injection with post-cleanup.",
                            comm, pid, original_path
                        ),
                    )
                    .with_remediation(&format!(
                        "Investigate: sudo cat /proc/{}/maps | grep deleted && \
                         sudo kill -9 {} if suspicious",
                        pid, pid
                    )),
                );
            }
        }
    }
}

/// Why a deleted library was deleted
enum DeletedLibraryReason {
    /// A newer file exists at the same path (app/package was updated)
    ReplacedByUpdate,
    /// File is gone but the package manager owns that path
    PackageManaged,
    /// File lived in the same directory as the process executable
    ProcessExeDirectory,
    /// File was in /tmp, /dev/shm, or similar — classic injection cleanup
    SuspiciousLocation,
    /// File is truly gone with no obvious benign explanation
    TrulyDeleted,
}

/// Check if a map entry is a deleted shared library
fn is_deleted_shared_library(path: &str) -> bool {
    if !path.contains("(deleted)") {
        return false;
    }
    // Must be a .so file
    if !path.contains(".so") {
        return false;
    }
    // Skip system library paths — handled by package manager, low risk
    if path.starts_with("/usr/lib") || path.starts_with("/lib/") || path.starts_with("/lib64/") {
        return false;
    }
    true
}

/// Classify why a deleted library was deleted to distinguish updates from injection
fn classify_deleted_library(original_path: &str, pid: i32) -> DeletedLibraryReason {
    use std::path::Path;

    let suspicious_dirs = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];

    // 1. If loaded from a suspicious temp directory, flag immediately
    for dir in &suspicious_dirs {
        if original_path.starts_with(dir) {
            return DeletedLibraryReason::SuspiciousLocation;
        }
    }

    // 2. If a file still exists at the same path, it was replaced (update)
    if Path::new(original_path).exists() {
        return DeletedLibraryReason::ReplacedByUpdate;
    }

    // 3. Check if the deleted lib was in the same directory as the process
    //    executable — strong signal of an application self-update
    let exe_link = format!("/proc/{}/exe", pid);
    if let Ok(exe_path) = fs::read_link(&exe_link) {
        if let (Some(exe_dir), Some(lib_dir)) = (
            exe_path.parent().and_then(|p| p.to_str()),
            Path::new(original_path).parent().and_then(|p| p.to_str()),
        ) {
            // Check if the library is under the same base application directory
            // e.g. exe=/opt/google/chrome/chrome, lib=/opt/google/chrome/WidevineCdm/...
            // Both share /opt/google/chrome/
            let exe_base = get_app_base_dir(exe_dir);
            let lib_base = get_app_base_dir(lib_dir);
            if exe_base == lib_base && !exe_base.is_empty() {
                return DeletedLibraryReason::ProcessExeDirectory;
            }
        }
    }

    // 4. Check if the package manager knows about this file path
    if is_package_managed(original_path) {
        return DeletedLibraryReason::PackageManaged;
    }

    // 5. None of the above — genuinely suspicious
    DeletedLibraryReason::TrulyDeleted
}

/// Get the base application directory (first 3-4 path components for /opt, /snap, etc.)
fn get_app_base_dir(dir: &str) -> &str {
    // For paths like /opt/google/chrome/subdir, return /opt/google/chrome
    // For paths like /snap/foo/123/usr/lib, return /snap/foo/123
    let parts: Vec<usize> = dir.match_indices('/').map(|(i, _)| i).collect();

    // /opt/vendor/app -> 3 components
    // /snap/name/rev -> 3 components
    let depth = if dir.starts_with("/opt/") || dir.starts_with("/snap/") {
        3
    } else {
        2
    };

    if parts.len() > depth {
        &dir[..parts[depth]]
    } else {
        dir
    }
}

/// Check if a file path is managed by dpkg (Debian/Ubuntu)
fn is_package_managed(path: &str) -> bool {
    // Use dpkg -S to check if the package manager knows this file
    // This is fast for single lookups (searches dpkg's database file)
    match std::process::Command::new("dpkg")
        .args(["-S", path])
        .output()
    {
        Ok(output) => output.status.success(),
        Err(_) => false, // dpkg not available (not Debian-based)
    }
}
