use super::utils::{parse_address_range, read_process_memory};
use crate::models::Finding;
use anyhow::Result;
use procfs::process::all_processes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
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

/// Info about the .text section parsed from an ELF binary
struct TextSectionInfo {
    /// File offset of .text section
    file_offset: u64,
    /// Size of .text section in bytes
    size: u64,
    /// Whether the binary has DT_TEXTREL (text relocations)
    has_textrel: bool,
}

/// Parse an ELF binary to find the .text section offset and size.
/// Returns None if the file isn't a valid ELF or has no .text section.
fn parse_elf_text_section(path: &std::path::Path) -> Option<TextSectionInfo> {
    let data = fs::read(path).ok()?;

    // Verify ELF magic
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return None;
    }

    // We only handle 64-bit ELF (class 2)
    if data[4] != 2 {
        return None;
    }

    // Little-endian (data encoding 1) — x86_64
    let le = data[5] == 1;
    if !le {
        return None;
    }

    let read_u16 = |off: usize| -> u16 { u16::from_le_bytes([data[off], data[off + 1]]) };
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    };
    let read_u64 = |off: usize| -> u64 {
        u64::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ])
    };

    // ELF64 header fields
    let e_shoff = read_u64(40) as usize; // Section header table offset
    let e_shentsize = read_u16(58) as usize; // Section header entry size
    let e_shnum = read_u16(60) as usize; // Number of section headers
    let e_shstrndx = read_u16(62) as usize; // Section name string table index

    if e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return None;
    }

    // Bounds check for section header table
    let sh_table_end = e_shoff + e_shnum * e_shentsize;
    if sh_table_end > data.len() {
        return None;
    }

    // Read section name string table
    let shstrtab_off = e_shoff + e_shstrndx * e_shentsize;
    if shstrtab_off + e_shentsize > data.len() {
        return None;
    }
    let strtab_offset = read_u64(shstrtab_off + 24) as usize;
    let strtab_size = read_u64(shstrtab_off + 32) as usize;

    if strtab_offset + strtab_size > data.len() {
        return None;
    }

    // Check for DT_TEXTREL in .dynamic section and find .text
    let mut has_textrel = false;
    let mut text_offset: Option<u64> = None;
    let mut text_size: Option<u64> = None;

    for i in 0..e_shnum {
        let sh_off = e_shoff + i * e_shentsize;
        if sh_off + e_shentsize > data.len() {
            break;
        }

        let sh_name_idx = read_u32(sh_off) as usize;
        let sh_type = read_u32(sh_off + 4);

        // Get section name
        if sh_name_idx < strtab_size {
            let name_start = strtab_offset + sh_name_idx;
            let name_end = data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| name_start + p)
                .unwrap_or(name_start);
            let name = std::str::from_utf8(&data[name_start..name_end]).unwrap_or("");

            if name == ".text" {
                text_offset = Some(read_u64(sh_off + 24)); // sh_offset
                text_size = Some(read_u64(sh_off + 32)); // sh_size
            }
        }

        // SHT_DYNAMIC = 6 — check for DT_TEXTREL entries
        if sh_type == 6 {
            let dyn_off = read_u64(sh_off + 24) as usize;
            let dyn_size = read_u64(sh_off + 32) as usize;
            if dyn_off + dyn_size <= data.len() {
                // Each dynamic entry is 16 bytes (d_tag u64, d_val u64)
                let mut pos = dyn_off;
                while pos + 16 <= dyn_off + dyn_size {
                    let d_tag = read_u64(pos);
                    if d_tag == 22 {
                        // DT_TEXTREL = 22
                        has_textrel = true;
                        break;
                    }
                    if d_tag == 0x6ffffffb {
                        // DT_FLAGS_1: check for DF_1_TEXTREL (bit 0)
                        // DT_FLAGS = 30: check for DF_TEXTREL (bit 2)
                    }
                    if d_tag == 30 {
                        // DT_FLAGS
                        let d_val = read_u64(pos + 8);
                        if d_val & 4 != 0 {
                            // DF_TEXTREL = 0x4
                            has_textrel = true;
                            break;
                        }
                    }
                    if d_tag == 0 {
                        break; // DT_NULL
                    }
                    pos += 16;
                }
            }
        }
    }

    let offset = text_offset?;
    let size = text_size?;

    // Sanity check: .text should be reasonable
    if size == 0 || offset + size > data.len() as u64 {
        return None;
    }

    Some(TextSectionInfo {
        file_offset: offset,
        size,
        has_textrel,
    })
}

/// Info about a memory mapping from /proc/PID/maps
struct MappingInfo {
    /// Start address
    start: u64,
    /// File offset this mapping corresponds to
    file_offset: u64,
}

/// Find the r-xp file-backed mapping that contains the .text section.
///
/// Each `r-xp` entry in `/proc/PID/maps` covers a contiguous range of the
/// binary file starting at `file_offset` and spanning exactly `end - start`
/// bytes. The .text section's file offset must fall within that range.
///
/// The `?` operator is intentionally NOT used on per-line parsing so that a
/// malformed line does not abort the entire search.
fn find_text_mapping(maps: &str, exe_path: &str, text_file_offset: u64) -> Option<MappingInfo> {
    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        // Must be r-xp (read + execute, private)
        if !parts[1].starts_with("r-x") {
            continue;
        }

        // Must be mapped from the same executable.
        // /proc/PID/maps always shows the path as seen inside the process's
        // namespace, which matches the value returned by readlink(/proc/PID/exe).
        let mapped_path = parts[5..].join(" ");
        if !mapped_path.contains(exe_path) {
            continue;
        }

        // Parse start/end addresses and file offset; skip malformed lines
        // without aborting the search for subsequent valid lines.
        let (start, end) = match parse_address_range(parts[0]) {
            Some(r) => r,
            None => continue,
        };
        let file_offset = match u64::from_str_radix(parts[2], 16) {
            Ok(o) => o,
            Err(_) => continue,
        };

        // The mapping covers file bytes [file_offset, file_offset + mapping_size).
        // The virtual size of an r-xp segment equals its file coverage (no BSS
        // zero-fill in executable segments), so mapping_size is the correct span.
        let mapping_size = end - start;
        if text_file_offset >= file_offset
            && text_file_offset < file_offset + mapping_size
        {
            return Some(MappingInfo {
                start,
                file_offset,
            });
        }
    }

    None
}

/// Read a range of bytes from a file
fn read_file_range(
    path: &std::path::Path,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size];
    let bytes_read = file.read(&mut buf)?;
    buf.truncate(bytes_read);
    Ok(buf)
}

/// Calculate SHA256 hash of data
fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Check if a process is being traced (debugged) — breakpoints modify .text
fn is_being_traced(pid: i32) -> bool {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(&status_path) {
        for line in content.lines() {
            if let Some(tracer) = line.strip_prefix("TracerPid:\t") {
                if let Ok(tracer_pid) = tracer.trim().parse::<i32>() {
                    return tracer_pid != 0;
                }
            }
        }
    }
    false
}

/// Check whether a process is running in a different mount namespace from us.
///
/// Docker containers and other Linux namespaces have their own mount namespace.
/// When we open `/proc/PID/exe` on the host, the symlink resolves to the HOST
/// filesystem path (e.g. `/usr/bin/bash`). But the container loaded a DIFFERENT
/// binary from its own overlay filesystem — the host's `/usr/bin/bash` may be a
/// completely different build/version. Comparing the container's in-memory .text
/// against the host binary will always differ from byte 0.
///
/// We detect this by comparing the mount namespace inode of the target process
/// against our own. If they differ, the process is in a container and we must
/// access its binary through `/proc/PID/root/<path>` instead of the raw host path.
fn is_in_different_mount_namespace(pid: i32) -> bool {
    let our_ns = fs::read_link("/proc/self/ns/mnt");
    let their_ns = fs::read_link(format!("/proc/{}/ns/mnt", pid));
    match (our_ns, their_ns) {
        (Ok(ours), Ok(theirs)) => ours != theirs,
        // If we can't read the namespace links, err on the side of caution and
        // assume same namespace (avoid spurious skips if permissions are limited).
        _ => false,
    }
}

/// Processes that legitimately modify their own executable memory.
/// JIT compilers, Electron/V8 apps, interpreters, emulators, and programs
/// using libraries like libffi create writable+executable pages or remap .text.
/// Flagging these would be false positives.
fn is_known_self_modifying_process(comm: &str, exe_path: &str) -> bool {
    let comm_lc = comm.to_lowercase();
    let exe_lc = exe_path.to_lowercase();

    // -- Web browsers (all have JS JIT engines) --
    let browsers = [
        "chrome", "chromium", "firefox", "firefox-esr",
        "brave", "vivaldi", "opera", "msedge", "microsoft-edge",
        "epiphany", "gnome-web", "falkon", "midori", "qutebrowser",
        "thunderbird",
    ];

    // -- Electron/CEF apps (embed Chromium V8 JIT) --
    let electron = [
        "electron", "code", "code-oss", "cursor",
        "discord", "slack", "teams", "ms-teams",
        "spotify", "signal", "obsidian", "notion",
        "figma", "atom", "1password", "bitwarden",
        "skype", "skypeforlinux", "whatsapp", "whatsdesk",
        "postman", "insomnia", "gitkraken", "github-desktop",
        "element", "mattermost", "rocketchat", "wire", "keybase", "zulip",
        "hyper", "tabby", "logseq", "typora", "mailspring",
        "mongodb-compass", "etcher", "balena-etcher",
        "simplenote", "standard-notes", "todoist", "trello",
        "loom", "tidal-hifi", "cider", "nuclear", "youtube-music",
    ];

    // -- JavaScript runtimes --
    let js_runtimes = ["node", "nodejs", "deno", "bun", "graaljs"];

    // -- Language runtimes with JIT --
    let interpreters = [
        "python", "python3", "pypy", "pypy3",
        "ruby", "irb", "jruby", "truffle-ruby",
        "java", "javac", "javaw",
        "lua", "luajit",
        "php", "php-fpm", "php-cgi", "hhvm",
        "dotnet", "mono", "mono-sgen",
        "julia", "dart", "flutter",
        "erlang", "beam.smp", "elixir", "iex",
        "guile", "racket", "sbcl", "ghci",
        "gjs", "cjs", "numba",
        "perl", "r",
    ];

    // -- JVM-based IDEs and build tools --
    let jvm_tools = [
        "idea", "clion", "pycharm", "goland", "webstorm",
        "rider", "rustrover", "phpstorm", "datagrip",
        "eclipse", "netbeans", "android-studio",
        "gradle", "mvn", "sbt", "lein", "bazel",
    ];

    // -- Databases with JIT --
    let databases = [
        "postgres", "postgresql",
        "clickhouse", "clickhouse-server",
        "mongod", "mongos",
    ];

    // -- Emulators and dynamic binary translators --
    let emulators = [
        "qemu", "dolphin-emu", "pcsx2", "rpcs3", "ppsspp",
        "citra", "yuzu", "suyu", "sudachi", "ryujinx",
        "retroarch", "mupen64plus", "desmume", "melonds",
        "cemu", "flycast", "xemu", "mednafen",
        "dosbox", "dosbox-x", "dosbox-staging",
        "wine", "wine64", "wine-preloader", "proton",
        "box86", "box64", "fex",
    ];

    // -- Virtualization --
    let virt = [
        "virtualboxvm", "vboxheadless", "vboxsvc", "vmware-vmx",
    ];

    // -- Desktop environments with JS engines --
    let desktop = [
        "gnome-shell", "cinnamon",
        "libreoffice", "soffice",
        "blender", "obs",
    ];

    // -- Debuggers and instrumentation --
    let debuggers = ["gdb", "lldb", "valgrind", "rr"];

    // -- WebAssembly runtimes --
    let wasm = ["wasmtime", "wasmer"];

    let all_lists: &[&[&str]] = &[
        &browsers, &electron, &js_runtimes, &interpreters, &jvm_tools,
        &databases, &emulators, &virt, &desktop, &debuggers, &wasm,
    ];

    for list in all_lists {
        for name in list.iter() {
            if comm_lc == *name
                || comm_lc.starts_with(&format!("{}-", name))
                || comm_lc.starts_with(&format!("{}.", name))
                || exe_lc.contains(&format!("/{}", name))
                || exe_lc.contains(&format!("/{}-", name))
            {
                return true;
            }
        }
    }

    // Crashpad handlers (Chrome, Electron apps)
    if comm_lc.contains("crashpad") || comm_lc.contains("chrome_crash") {
        return true;
    }

    // QEMU variants (qemu-system-x86_64, qemu-aarch64, etc.)
    if comm_lc.starts_with("qemu-") {
        return true;
    }

    // JetBrains IDEs often have versioned process names
    if exe_lc.contains("/jetbrains/") || exe_lc.contains("/idea") || exe_lc.contains("/pycharm") {
        return true;
    }

    false
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
