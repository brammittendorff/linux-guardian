use anyhow::Result;
use std::fs;
use std::io::{Read, Seek, SeekFrom};

/// Read process memory using /proc/PID/mem
pub fn read_process_memory(pid: i32, addr: u64, size: usize) -> Result<Vec<u8>> {
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
