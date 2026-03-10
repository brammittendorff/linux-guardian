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
