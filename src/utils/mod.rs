pub mod privilege;
pub mod version;

use std::process::Command;

/// Execute a command and return output as string
pub fn execute_command(cmd: &str, args: &[&str]) -> Result<String, std::io::Error> {
    let output = Command::new(cmd).args(args).output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(std::io::Error::other(String::from_utf8_lossy(
            &output.stderr,
        )))
    }
}

/// Check if a binary path is managed by the system package manager (dpkg or rpm).
/// Package-managed binaries are legitimate — e.g. browsers whose binary shows
/// "(deleted)" during an in-place update.
pub fn is_binary_package_managed(path: &str) -> bool {
    // Try dpkg -S (Debian/Ubuntu)
    if let Ok(output) = Command::new("dpkg").args(["-S", path]).output() {
        if output.status.success() {
            return true;
        }
    }
    // Try rpm -qf (RedHat/Fedora/CentOS)
    if let Ok(output) = Command::new("rpm").args(["-qf", path]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() && !stdout.contains("not owned") {
                return true;
            }
        }
    }
    false
}

/// Check if a file exists
pub fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Read file contents safely
pub fn read_file_safe(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
