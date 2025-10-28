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

/// Check if a file exists
pub fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Read file contents safely
pub fn read_file_safe(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
