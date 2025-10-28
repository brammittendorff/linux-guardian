use nix::unistd::{getuid, Uid};

/// Check if the current process is running with root privileges
pub fn check_privileges() -> bool {
    getuid() == Uid::from_raw(0)
}

/// Check if we have read access to a file
pub fn has_read_access(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}
