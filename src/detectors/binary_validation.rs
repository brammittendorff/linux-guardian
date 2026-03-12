/// Binary Legitimacy Scanner - Detect trojaned/backdoored binaries
/// NO API KEYS REQUIRED - Uses local verification methods
use crate::models::Finding;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tracing::{debug, info};

/// Critical system binaries that MUST be validated.
///
/// Binaries that dpkg tracks under /bin/ keep their /bin/ paths for accurate
/// package-manager verification (usrmerge compatibility). Newly added binaries
/// use the canonical /usr/bin/ or /usr/sbin/ locations found on modern systems.
/// `check_binary_from_package` automatically probes alternate paths, so both
/// schemes are handled transparently.
///
/// Coverage is informed by real-world rootkit behaviour documented in perfctl,
/// Pygmy Goat, XorDdos, and the chkrootkit/rkhunter reference lists.
const CRITICAL_BINARIES: &[&str] = &[
    // --- Authentication & privilege escalation ---
    "/usr/bin/sudo", // sudo is actually in /usr/bin
    "/bin/su",       // Tracked in /bin by dpkg
    "/usr/bin/passwd",
    "/bin/login",    // Tracked in /bin by dpkg
    "/usr/bin/chfn", // SUID binary, classic rootkit target
    "/usr/bin/chsh", // SUID binary, classic rootkit target
    // --- Shells ---
    "/bin/bash",
    "/bin/sh",
    // --- Remote access & file transfer ---
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/scp",  // Exfiltrate files
    "/usr/bin/curl", // Download payloads (perfctl, XorDdos)
    "/usr/bin/wget", // Download payloads
    // --- Process & system monitoring ---
    "/bin/ps",         // Tracked in /bin by dpkg
    "/bin/ls",         // Tracked in /bin by dpkg
    "/bin/systemctl",  // Tracked in /bin by dpkg
    "/usr/bin/top",    // Hide cryptominer CPU usage
    "/usr/bin/pstree", // Hide process trees
    "/usr/bin/lsof",   // Hide open files/connections
    "/usr/bin/find",   // Prevent discovery of malware files
    "/usr/bin/w",      // Hide logged-in attackers
    // --- File & disk inspection ---
    "/usr/bin/du", // Hide disk usage of malicious files
    "/usr/bin/df", // Hide filesystem usage
    // --- Text & binary analysis ---
    "/usr/bin/grep", // Filter out evidence from command output
    "/usr/bin/ldd",  // Hide malicious library injections (perfctl)
    // --- Scheduling & persistence ---
    "/usr/bin/crontab", // Hide persistence mechanisms (perfctl)
    "/usr/sbin/cron",   // Hide cron-based backdoors
    // --- Network utilities ---
    "/bin/netstat",
    "/usr/bin/ss",        // iproute2 package
    "/usr/sbin/ifconfig", // Hide promiscuous mode (Pygmy Goat)
    "/usr/sbin/ip",       // Modern ifconfig replacement
    "/usr/bin/tcpdump",   // Modified to capture/exfiltrate traffic
    // --- Filesystem & mounting ---
    "/usr/bin/mount", // Mount attacker-controlled filesystems
    // --- Firewall & network filtering ---
    "/usr/sbin/iptables", // Open firewall holes
    "/usr/sbin/nft",      // Modern nftables firewall
    // --- Kernel module loading ---
    "/usr/sbin/modprobe", // Load kernel rootkit modules
    "/usr/sbin/insmod",   // Load kernel rootkit modules directly
    // --- Dynamic linker & library management ---
    "/usr/sbin/ldconfig", // Inject malicious library search paths
    // --- Environment manipulation ---
    "/usr/bin/env", // Inject environment variables into processes
    // --- Package management ---
    "/usr/bin/dpkg", // Hide tampered packages (Debian/Ubuntu)
    "/usr/bin/rpm",  // Hide tampered packages (RPM-based systems)
    // --- User account management ---
    "/usr/sbin/adduser", // Create backdoor accounts
    "/usr/sbin/useradd", // Create backdoor accounts (low-level)
    // --- Interpreters & runtimes (common execution targets) ---
    // NOTE: JIT processes are excluded from .text section comparison in the
    // process hollowing detector (deep_scan.rs) to avoid false positives, but
    // they MUST still be validated here: package ownership, permissions,
    // suspicious strings, and modification time are equally applicable and
    // these binaries are high-value attack targets.

    // Browsers (handle credentials, sessions, cookies)
    "/usr/bin/firefox",
    "/usr/bin/firefox-esr",
    "/usr/bin/brave-browser",
    // JavaScript runtimes (common malware execution vectors)
    "/usr/bin/node",
    "/usr/bin/nodejs",
    "/usr/bin/deno",
    "/usr/bin/bun",
    // Language runtimes (arbitrary code execution targets)
    "/usr/bin/python3",
    "/usr/bin/python3.11", // Common on Debian/Ubuntu 22.04+
    "/usr/bin/java",
    "/usr/bin/ruby",
    "/usr/bin/php",
    "/usr/bin/perl",
    "/usr/bin/lua",
    "/usr/bin/luajit",
    // .NET runtime
    "/usr/bin/dotnet",
    // --- Databases (data theft targets) ---
    "/usr/bin/psql",         // PostgreSQL client
    "/usr/sbin/postgres",    // PostgreSQL server daemon
    "/usr/bin/redis-server", // Redis server
    "/usr/sbin/mysqld",      // MySQL/MariaDB server daemon
];

/// Suspicious strings in binaries (backdoor indicators)
/// NOTE: /dev/tcp/ is LEGITIMATE bash feature when used alone
/// We check for specific reverse shell patterns
const SUSPICIOUS_STRINGS: &[&str] = &[
    "eval(base64_decode",
    "nc -e /bin/sh",              // Netcat executing shell
    "nc -e /bin/bash",            // Netcat executing bash
    "nc -c /bin/sh",              // Netcat with command
    "nc -c /bin/bash",            // Netcat with command
    "ncat -e /bin/",              // Ncat variant
    "netcat -e /bin/",            // Netcat variant
    "bash -i >& /dev/tcp",        // Bash reverse shell (specific pattern)
    "sh -i >& /dev/tcp",          // Shell reverse shell
    "exec 5<>/dev/tcp/",          // File descriptor redirection to TCP
    "0<&196;exec 196<>/dev/tcp/", // Advanced reverse shell
    "0.0.0.0:4444",               // Common reverse shell port
    ":4444/shell",                // Shell endpoint
    "PAYLOAD_START",              // Metasploit marker
    "msfvenom",                   // Metasploit payload generator
    "chmod 777 /tmp",             // Suspicious permission change
    "iptables -F && ",            // Flush firewall in script
    "setenforce 0 &&",            // Disable SELinux in script
    "rm -rf /var/log",            // Log deletion
    "history -c",                 // Clear command history
    "ROOTKIT_",                   // Rootkit marker
    "BACKDOOR_",                  // Backdoor marker
    "xmrig",                      // Cryptominer
    "stratum+tcp://",             // Mining pool connection
];

/// Build the set of candidate paths to query for a given binary path.
///
/// Returns the original path, its usrmerge alternate, and the resolved
/// symlink target (plus that target's usrmerge alternate).  Duplicates are
/// deduplicated before returning.
fn candidate_paths_for(binary_path: &str) -> Vec<String> {
    let mut paths = vec![
        binary_path.to_string(),
        binary_path.replace("/usr/bin/", "/bin/"),
        binary_path.replace("/usr/sbin/", "/sbin/"),
    ];

    if let Ok(resolved) = std::fs::canonicalize(binary_path) {
        let resolved_str = resolved.to_string_lossy().to_string();
        if resolved_str != binary_path {
            paths.push(resolved_str.replace("/usr/bin/", "/bin/"));
            paths.push(resolved_str.replace("/usr/sbin/", "/sbin/"));
            paths.push(resolved_str);
        }
    }

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));
    paths
}

/// Run a single `dpkg -S` call with all provided paths as arguments and return
/// a map of `path -> package_name` for every path that dpkg recognises.
///
/// dpkg -S exits with code 1 if *any* path is unknown, but still prints the
/// results for all paths it does know.  We therefore parse stdout line-by-line
/// and ignore the exit code entirely.
fn dpkg_s_batch(paths: &[String]) -> HashMap<String, String> {
    let mut result = HashMap::new();

    if paths.is_empty() {
        return result;
    }

    let output = match Command::new("dpkg").arg("-S").args(paths).output() {
        Ok(o) => o,
        Err(_) => return result, // dpkg not available (RPM system)
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Format: "package-name:arch: /path/to/file"  (e.g. "coreutils:amd64: /usr/bin/ls")
        // or:     "package-name: /path/to/file"       (arch-independent packages)
        // Diversions: "diversion by foo from: /path"  — skip those.
        //
        // Split on ": " (colon-space) to correctly handle the ":arch" suffix
        // in package names. Using split_once(':') would split at the arch
        // separator and misparse the path.
        if let Some((pkg_part, path_part)) = line.split_once(": ") {
            // Strip architecture suffix (e.g. "coreutils:amd64" -> "coreutils")
            let pkg = pkg_part.split(':').next().unwrap_or(pkg_part).trim();
            let path = path_part.trim();
            // A plain package name contains no spaces; diversion lines do.
            if !pkg.contains(' ') && !path.is_empty() {
                result.insert(path.to_string(), pkg.to_string());
            }
        }
    }

    result
}

/// Run `dpkg -V <package>` for each unique package and return a map of
/// `package -> stdout`.  One subprocess per unique package instead of one
/// per binary.
fn dpkg_v_by_package(packages: &[&str]) -> HashMap<String, String> {
    let mut result = HashMap::new();

    for &pkg in packages {
        if let Ok(output) = Command::new("dpkg").args(["-V", pkg]).output() {
            // dpkg -V exits 0 when all files are clean, non-zero when something
            // differs.  We want the output either way.
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            result.insert(pkg.to_string(), stdout);
        }
    }

    result
}

/// Scan critical binaries for legitimacy
pub async fn validate_critical_binaries() -> Result<Vec<Finding>> {
    info!("Validating critical system binaries...");

    // --- Phase 1: collect binaries that actually exist on this system. -------
    let existing_binaries: Vec<&str> = CRITICAL_BINARIES
        .iter()
        .copied()
        .filter(|p| std::path::Path::new(p).exists())
        .collect();

    debug!(
        "{} of {} critical binaries present on this system",
        existing_binaries.len(),
        CRITICAL_BINARIES.len()
    );

    // --- Phase 2: single batched dpkg -S for all candidate paths. -----------
    //
    // For every binary we may need to query /bin/foo, /usr/bin/foo, the
    // resolved symlink target, etc.  Build the full candidate list once and
    // feed it to dpkg in a single subprocess call.

    // candidate_paths_for is cheap (just fs::canonicalize), run sequentially.
    let candidates_per_binary: Vec<Vec<String>> = existing_binaries
        .iter()
        .map(|p| candidate_paths_for(p))
        .collect();

    let all_candidate_paths: Vec<String> = candidates_per_binary
        .iter()
        .flat_map(|v| v.iter().cloned())
        .collect();

    // One dpkg -S call for every candidate path across all binaries.
    let dpkg_ownership: HashMap<String, String> = dpkg_s_batch(&all_candidate_paths);

    // For each binary, determine whether *any* of its candidates was found.
    // If found, record the owning package name.
    let binary_packages: Vec<Option<String>> = candidates_per_binary
        .iter()
        .map(|candidates| {
            candidates
                .iter()
                .find_map(|p| dpkg_ownership.get(p).cloned())
        })
        .collect();

    // --- Phase 3: batch dpkg -V by unique package. --------------------------
    let unique_packages: Vec<&str> = {
        let mut pkgs: Vec<&str> = binary_packages
            .iter()
            .filter_map(|opt| opt.as_deref())
            .collect();
        pkgs.sort_unstable();
        pkgs.dedup();
        pkgs
    };

    let dpkg_verify: HashMap<String, String> = dpkg_v_by_package(&unique_packages);

    // --- Phase 4: parallel per-binary checks (local I/O only). -------------
    //
    // Everything from here is pure local I/O – no more subprocesses.
    // Spawn one tokio task per binary and collect all findings.

    let mut task_handles = Vec::with_capacity(existing_binaries.len());

    for (idx, &binary_path) in existing_binaries.iter().enumerate() {
        let owned_by: Option<String> = binary_packages[idx].clone();
        let pkg_verify_output: Option<String> = owned_by
            .as_deref()
            .and_then(|pkg| dpkg_verify.get(pkg).cloned());
        let binary_path = binary_path.to_string();

        task_handles.push(tokio::spawn(async move {
            validate_single_binary(binary_path, owned_by, pkg_verify_output).await
        }));
    }

    // --- Phase 5: gather results, then RPM fallback for unowned binaries. ---
    let mut findings = Vec::new();

    for handle in task_handles {
        if let Ok(binary_findings) = handle.await {
            findings.extend(binary_findings);
        }
    }

    info!("  Validated {} critical binaries", existing_binaries.len());
    Ok(findings)
}

/// All checks for a single binary given pre-fetched package ownership data.
async fn validate_single_binary(
    binary_path: String,
    owned_by: Option<String>,       // package owning this binary (from batch dpkg -S)
    dpkg_v_output: Option<String>,  // stdout of `dpkg -V <package>` for that package
) -> Vec<Finding> {
    let mut findings = Vec::new();

    match &owned_by {
        None => {
            // dpkg doesn't know it.  Try rpm before flagging.
            let rpm_owned = rpm_owns_binary(&binary_path);
            if !rpm_owned {
                findings.push(
                    Finding::critical(
                        "binary_validation",
                        "Critical Binary Not From Package",
                        &format!(
                            "{} is a critical system binary but doesn't belong to any package. \
                             This could indicate a trojaned/replaced binary.",
                            binary_path
                        ),
                    )
                    .with_remediation(&format!(
                        "URGENT: Investigate {} - may be backdoor. Reinstall package or restore from backup",
                        binary_path
                    )),
                );
            }
            // Even for unpackaged binaries, still run the local checks below.
        }
        Some(package) => {
            // Binary is package-managed; verify its checksum from the
            // already-fetched dpkg -V output.
            if let Some(finding) =
                check_checksum_from_dpkg_v(&binary_path, package, dpkg_v_output.as_deref())
            {
                findings.push(finding);
            }
        }
    }

    // These checks are purely local — they don't care about package ownership.
    if let Some(finding) = check_binary_permissions(&binary_path) {
        findings.push(finding);
    }

    if let Some(finding) = check_binary_strings(&binary_path).await {
        findings.push(finding);
    }

    if let Some(finding) = check_binary_modification_time(&binary_path) {
        findings.push(finding);
    }

    findings
}

/// Return true if `rpm -qf <path>` (or any usrmerge alternate) succeeds.
/// Only called for binaries that dpkg doesn't know about, so the total
/// number of rpm invocations remains small.
fn rpm_owns_binary(binary_path: &str) -> bool {
    let candidates = candidate_paths_for(binary_path);
    for path in &candidates {
        if let Ok(output) = Command::new("rpm").args(["-qf", path]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() && !stdout.contains("not owned") {
                    debug!(
                        "{} belongs to rpm package (verified via {})",
                        binary_path, path
                    );
                    return true;
                }
            }
        }
    }
    false
}

/// Inspect the pre-fetched `dpkg -V <package>` output for a checksum mismatch
/// on this specific binary.
///
/// dpkg -V output format per tampered file:
///   "??5?????? c /path/to/file"  (the '5' at index 2 means md5sum differs)
fn check_checksum_from_dpkg_v(
    binary_path: &str,
    package: &str,
    dpkg_v_output: Option<&str>,
) -> Option<Finding> {
    let stdout = dpkg_v_output?;

    // Resolve symlinks so we can match against the canonical path too.
    let canonical = fs::canonicalize(binary_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| binary_path.to_string());

    for line in stdout.lines() {
        let line = line.trim();
        if (line.contains(binary_path) || line.contains(canonical.as_str()))
            && line.len() >= 9
            && line.as_bytes()[2] == b'5'
        {
            return Some(
                Finding::critical(
                    "binary_validation",
                    "Critical Binary Checksum Mismatch",
                    &format!(
                        "{} (package: {}) has a different checksum than what was \
                         installed. The binary has been MODIFIED on disk. This is \
                         a strong indicator of tampering.",
                        binary_path, package
                    ),
                )
                .with_remediation(&format!(
                    "URGENT: Reinstall package: sudo apt-get install --reinstall {} && \
                     Investigate who modified it: stat '{}' && sudo ausearch -f '{}'",
                    package, binary_path, binary_path
                )),
            );
        }
    }

    None
}

/// Check binary file permissions
fn check_binary_permissions(binary_path: &str) -> Option<Finding> {
    if let Ok(metadata) = fs::metadata(binary_path) {
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;

        // Critical binaries should not be world-writable
        if (mode & 0o002) != 0 {
            return Some(
                Finding::critical(
                    "binary_validation",
                    "Critical Binary is World-Writable",
                    &format!(
                        "{} is writable by everyone (mode: {:o}). Attacker could replace it with backdoor!",
                        binary_path, mode
                    ),
                )
                .with_remediation(&format!("Fix immediately: sudo chmod 755 {}", binary_path)),
            );
        }

        // Critical binaries should be owned by root
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = metadata.uid();
            if uid != 0 {
                return Some(
                    Finding::high(
                        "binary_validation",
                        "Critical Binary Not Owned by Root",
                        &format!("{} is owned by UID {} (should be root/0)", binary_path, uid),
                    )
                    .with_remediation(&format!("Fix: sudo chown root:root {}", binary_path)),
                );
            }
        }
    }

    None
}

/// Scan binary for suspicious strings
async fn check_binary_strings(binary_path: &str) -> Option<Finding> {
    // Read binary (limit to first 1MB for performance)
    let mut file = match fs::File::open(binary_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB
    let bytes_read = file.read(&mut buffer).unwrap_or(0);

    if bytes_read == 0 {
        return None;
    }

    // Convert to string (lossy)
    let content = String::from_utf8_lossy(&buffer[..bytes_read]);

    // Check for suspicious patterns
    for pattern in SUSPICIOUS_STRINGS {
        if content.contains(pattern) {
            return Some(
                Finding::critical(
                    "binary_validation",
                    "Suspicious String in Critical Binary",
                    &format!(
                        "{} contains suspicious pattern: '{}'. This could indicate a backdoor or trojan.",
                        binary_path, pattern
                    ),
                )
                .with_remediation(&format!(
                    "CRITICAL: Investigate {} with: strings {} | grep -i backdoor && sudo apt-get install --reinstall $(dpkg -S {} | cut -d: -f1)",
                    binary_path, binary_path, binary_path
                )),
            );
        }
    }

    None
}

/// Check if binary was recently modified (suspicious)
fn check_binary_modification_time(binary_path: &str) -> Option<Finding> {
    if let Ok(metadata) = fs::metadata(binary_path) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();

            // Critical binaries modified in last 7 days = SUSPICIOUS
            // (Unless system was recently updated)
            if age.as_secs() < 7 * 24 * 3600 {
                return Some(
                    Finding::high(
                        "binary_validation",
                        "Critical Binary Recently Modified",
                        &format!(
                            "{} was modified {} days ago. If you didn't update recently, this could indicate tampering.",
                            binary_path,
                            age.as_secs() / 86400
                        ),
                    )
                    .with_remediation("Verify with package manager: dpkg -V or rpm -V. Reinstall if tampered."),
                );
            }
        }
    }

    None
}

/// Scan for web shells in web directories
pub async fn scan_web_shells() -> Result<Vec<Finding>> {
    info!("Scanning for web shells...");
    let mut findings = Vec::new();

    // Common web roots
    let web_roots = [
        "/var/www",
        "/srv/http",
        "/usr/share/nginx/html",
        "/var/www/html",
    ];

    for web_root in &web_roots {
        if !std::path::Path::new(web_root).exists() {
            continue;
        }

        // Scan for suspicious files
        for entry in walkdir::WalkDir::new(web_root)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check file extension
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy();

                // Suspicious extensions
                if ext_str == "suspected" || ext_str == "bak" || ext_str == "old" {
                    continue; // Skip backup files
                }

                // PHP/ASP files - check for web shell patterns
                if ext_str == "php" || ext_str == "asp" || ext_str == "aspx" {
                    if let Ok(content) = fs::read_to_string(path) {
                        // Check for web shell patterns
                        for pattern in &[
                            "eval(base64_decode",
                            "system($_GET",
                            "system($_POST",
                            "system($_REQUEST",
                            "shell_exec(",
                            "passthru(",
                            "exec($_",
                            "base64_decode(",
                        ] {
                            if content.contains(pattern) {
                                findings.push(
                                    Finding::critical(
                                        "web_shell",
                                        "Web Shell Detected",
                                        &format!(
                                            "Possible web shell found: {} contains suspicious pattern: '{}'",
                                            path.display(),
                                            pattern
                                        ),
                                    )
                                    .with_remediation(&format!("Delete immediately: sudo rm '{}'", path.display())),
                                );
                                break; // One detection per file is enough
                            }
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        debug!("No web shells detected");
    }

    Ok(findings)
}

/// Calculate SHA256 hash of a file
pub fn hash_file(path: &str) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_world_writable_detection() {
        let mode = 0o100666; // rw-rw-rw-
        assert_eq!(mode & 0o002, 0o002); // World-writable
    }

    #[test]
    fn test_suspicious_string_patterns() {
        let content = "some code eval(base64_decode($_POST['cmd'])) more code";
        assert!(content.contains("eval(base64_decode"));
    }

    #[test]
    fn test_recent_modification() {
        let seven_days_ago = 7 * 24 * 3600;
        let one_day_ago = 24 * 3600;

        assert!(one_day_ago < seven_days_ago);
    }

    // --- Tests for the new batched dpkg-S parsing logic --------------------

    /// Simulate the line-by-line parser used by dpkg_s_batch.
    fn parse_dpkg_s_output(stdout: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for line in stdout.lines() {
            if let Some((pkg_part, path_part)) = line.split_once(':') {
                let pkg = pkg_part.trim();
                let path = path_part.trim();
                if !pkg.contains(' ') && !path.is_empty() {
                    result.insert(path.to_string(), pkg.to_string());
                }
            }
        }
        result
    }

    #[test]
    fn test_dpkg_s_batch_parses_normal_output() {
        let stdout = "coreutils: /bin/ls\ncoreutils: /bin/cp\nbash: /bin/bash\n";
        let map = parse_dpkg_s_output(stdout);
        assert_eq!(map.get("/bin/ls").map(String::as_str), Some("coreutils"));
        assert_eq!(map.get("/bin/cp").map(String::as_str), Some("coreutils"));
        assert_eq!(map.get("/bin/bash").map(String::as_str), Some("bash"));
    }

    #[test]
    fn test_dpkg_s_batch_skips_diversion_lines() {
        // Diversions have spaces in the "package" portion.
        let stdout = "diversion by dash from: /bin/sh\nbash: /bin/bash\n";
        let map = parse_dpkg_s_output(stdout);
        assert!(!map.contains_key("/bin/sh"), "diversion line must be skipped");
        assert_eq!(map.get("/bin/bash").map(String::as_str), Some("bash"));
    }

    #[test]
    fn test_dpkg_s_batch_handles_partial_results() {
        // When one path is unknown dpkg exits 1 but still prints the known ones.
        // Simulating that: only two of three paths are in the output.
        let stdout = "coreutils: /bin/ls\nbash: /bin/bash\n";
        let map = parse_dpkg_s_output(stdout);
        assert_eq!(map.len(), 2);
        assert!(!map.contains_key("/usr/bin/nonexistent"));
    }

    #[test]
    fn test_check_checksum_from_dpkg_v_detects_md5_mismatch() {
        // Position 2 (0-indexed) is '5' when md5sum differs.
        let dpkg_v_output = "??5?????? c /bin/bash\n";
        let finding =
            check_checksum_from_dpkg_v("/bin/bash", "bash", Some(dpkg_v_output));
        assert!(
            finding.is_some(),
            "should detect checksum mismatch when position 2 is '5'"
        );
        let f = finding.unwrap();
        assert!(f.description.contains("/bin/bash"));
        assert!(f.description.contains("bash"));
    }

    #[test]
    fn test_check_checksum_from_dpkg_v_clean_binary() {
        // All dots means everything matches.
        let dpkg_v_output = ".......... c /bin/bash\n";
        let finding =
            check_checksum_from_dpkg_v("/bin/bash", "bash", Some(dpkg_v_output));
        assert!(
            finding.is_none(),
            "should not flag a binary with a clean dpkg -V line"
        );
    }

    #[test]
    fn test_check_checksum_from_dpkg_v_no_output() {
        // dpkg -V produces no output when the package is fully clean.
        let finding = check_checksum_from_dpkg_v("/bin/bash", "bash", Some(""));
        assert!(finding.is_none());
    }

    #[test]
    fn test_candidate_paths_deduplication() {
        // A path that has no usrmerge alternate (/bin/bash -> /bin/bash) should
        // not produce duplicate entries.
        let candidates = candidate_paths_for("/bin/bash");
        let unique: std::collections::HashSet<_> = candidates.iter().collect();
        assert_eq!(
            candidates.len(),
            unique.len(),
            "candidate_paths_for must not return duplicates"
        );
    }

    #[test]
    fn test_candidate_paths_includes_usrmerge_alternate() {
        // /usr/bin/sudo must also probe /bin/sudo.
        let candidates = candidate_paths_for("/usr/bin/sudo");
        assert!(
            candidates.contains(&"/bin/sudo".to_string()),
            "usrmerge alternate /bin/sudo must be included"
        );
    }
}
