use anyhow::Result;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use std::fs;
use std::io::{IoSliceMut, Read, Seek, SeekFrom};

/// Read process memory, preferring process_vm_readv(2) for performance.
///
/// process_vm_readv transfers data directly between address spaces without
/// routing through kernel buffers, avoiding the open/seek/read round-trip
/// that /proc/PID/mem requires. Falls back to /proc/PID/mem when the syscall
/// fails (e.g. insufficient privileges or the target is a kernel thread).
pub fn read_process_memory(pid: i32, addr: u64, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];

    // process_vm_readv requires &mut [IoSliceMut] for the local side.
    let mut local_iov = [IoSliceMut::new(&mut buf)];
    let remote_iov = [RemoteIoVec {
        base: addr as usize,
        len: size,
    }];

    match process_vm_readv(Pid::from_raw(pid), &mut local_iov, &remote_iov) {
        Ok(bytes_read) => {
            buf.truncate(bytes_read);
            Ok(buf)
        }
        Err(_) => {
            // Fall back to /proc/PID/mem (e.g. ptrace_scope restrictions).
            read_process_memory_proc(pid, addr, size)
        }
    }
}

/// Read process memory via /proc/PID/mem (fallback path).
fn read_process_memory_proc(pid: i32, addr: u64, size: usize) -> Result<Vec<u8>> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = fs::File::open(&mem_path)?;
    file.seek(SeekFrom::Start(addr))?;

    let mut buf = vec![0u8; size];
    let bytes_read = file.read(&mut buf)?;
    buf.truncate(bytes_read);

    Ok(buf)
}

/// Parse address range from maps format "start-end"
pub fn parse_address_range(range: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = u64::from_str_radix(parts[0], 16).ok()?;
    let end = u64::from_str_radix(parts[1], 16).ok()?;
    Some((start, end))
}

/// Truncate a string to max length with ellipsis
pub fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

/// Calculate Shannon entropy of a byte buffer.
///
/// Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly random).
///
/// Interpretation for executable memory:
///   0.0 – 5.0  Normal data, text, uninitialized memory
///   5.0 – 6.5  Normal compiled code (.text sections, JIT output)
///   6.5 – 7.0  Compressed data (embedded resources, zlib streams)
///   7.0 – 7.7  Heavily compressed or lightly encrypted
///   7.7 – 8.0  Almost certainly packed/encrypted (shellcode, crypted malware)
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Entropy thresholds for classifying executable memory content
pub const ENTROPY_PACKED_THRESHOLD: f64 = 7.7; // Encrypted/packed shellcode

/// Walk the process tree from `pid` up to init (PID 1).
///
/// Returns a list of `(pid, comm)` pairs starting from the given process
/// and walking up through parent processes. Useful for context in findings:
/// "webserver → bash → curl" is suspicious regardless of allowlists.
///
/// Stops at PID 1, after 32 levels (infinite loop guard), or on error.
pub fn get_process_lineage(pid: i32) -> Vec<(i32, String)> {
    let mut chain = Vec::new();
    let mut current_pid = pid;

    for _ in 0..32 {
        if current_pid <= 0 {
            break;
        }

        let status_path = format!("/proc/{}/status", current_pid);
        let content = match fs::read_to_string(&status_path) {
            Ok(c) => c,
            Err(_) => break,
        };

        let mut name = String::new();
        let mut ppid = 0i32;

        for line in content.lines() {
            if let Some(n) = line.strip_prefix("Name:\t") {
                name = n.to_string();
            } else if let Some(p) = line.strip_prefix("PPid:\t") {
                ppid = p.trim().parse().unwrap_or(0);
            }
        }

        chain.push((current_pid, name));

        if current_pid == 1 || ppid == current_pid {
            break;
        }
        current_pid = ppid;
    }

    chain
}

/// Format process lineage as a readable string: "bash(1234) → python3(5678) → curl(9012)"
pub fn format_lineage(lineage: &[(i32, String)]) -> String {
    lineage
        .iter()
        .map(|(pid, name)| format!("{}({})", name, pid))
        .collect::<Vec<_>>()
        .join(" → ")
}
