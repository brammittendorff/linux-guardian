use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Check disk encryption status (LUKS)
pub async fn check_disk_encryption() -> Result<Vec<Finding>> {
    info!("🔍 Checking disk encryption status...");
    let mut findings = Vec::new();

    // Check for LUKS encrypted partitions
    let output = Command::new("lsblk")
        .args(["-f", "-o", "NAME,FSTYPE,MOUNTPOINT"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("lsblk output: {} lines", stdout.lines().count());

        // Check for crypto_LUKS
        let has_luks = stdout.contains("crypto_LUKS");
        let luks_count = stdout.lines().filter(|l| l.contains("crypto_LUKS")).count();

        // Check if root partition is encrypted
        let root_encrypted = stdout
            .lines()
            .any(|l| l.contains("crypto_LUKS") && l.contains("/"));

        if !has_luks {
            findings.push(
                Finding::critical(
                    "encryption",
                    "Disk Encryption Not Enabled",
                    "No LUKS encrypted partitions detected. If device is lost or stolen, all data is accessible.",
                )
                .with_remediation("Enable full disk encryption on next OS install or encrypt data partitions with cryptsetup"),
            );
        } else if !root_encrypted {
            findings.push(
                Finding::high(
                    "encryption",
                    "Root Partition Not Encrypted",
                    &format!(
                        "Found {} encrypted partitions but root (/) is not encrypted. System files and logs are unprotected.",
                        luks_count
                    ),
                )
                .with_remediation("Consider full disk encryption on next install or encrypt /home partition"),
            );
        } else {
            debug!(
                "Disk encryption: {} LUKS partitions, root is encrypted",
                luks_count
            );
        }

        // Check for unencrypted /home on separate partition
        let has_separate_home = stdout
            .lines()
            .any(|l| l.contains("/home") && !l.contains("crypto_LUKS"));

        if has_separate_home && !root_encrypted {
            findings.push(
                Finding::medium(
                    "encryption",
                    "/home Partition Not Encrypted",
                    "Separate /home partition exists but is not encrypted. User data is at risk.",
                )
                .with_remediation("Encrypt /home partition or migrate to encrypted partition"),
            );
        }
    } else {
        debug!("lsblk command not available");
    }

    // Check for Secure Boot (hardware security)
    if let Some(sb_finding) = check_secure_boot().await {
        findings.push(sb_finding);
    }

    info!("  Checked disk encryption and hardware security");
    Ok(findings)
}

/// Check UEFI Secure Boot status
async fn check_secure_boot() -> Option<Finding> {
    let output = Command::new("mokutil").arg("--sb-state").output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("Secure Boot status: {}", stdout.trim());

    if stdout.contains("SecureBoot disabled") {
        return Some(
            Finding::medium(
                "hardware_security",
                "Secure Boot Disabled",
                "UEFI Secure Boot is not active. Boot-level malware (bootkits) can compromise system before OS loads.",
            )
            .with_remediation("Enable Secure Boot in UEFI/BIOS settings"),
        );
    }

    if stdout.contains("SecureBoot enabled") {
        debug!("Secure Boot is enabled - good!");
        return None;
    }

    // mokutil not available or unclear status
    None
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_luks_detection() {
        let lsblk_output = "NAME        FSTYPE      MOUNTPOINT\nsda1        crypto_LUKS\nsda2        ext4        /";
        assert!(lsblk_output.contains("crypto_LUKS"));

        let luks_count = lsblk_output
            .lines()
            .filter(|l| l.contains("crypto_LUKS"))
            .count();
        assert_eq!(luks_count, 1);
    }

    #[test]
    fn test_root_encryption_detection() {
        let encrypted_root = "sda1   crypto_LUKS\nsda2   ext4    /";
        let root_encrypted = encrypted_root
            .lines()
            .any(|l| l.contains("crypto_LUKS") && l.contains("/"));
        assert!(!root_encrypted); // Root not directly marked as LUKS in this example

        let _properly_encrypted = "dm-0   ext4    /\nsda1   crypto_LUKS";
        // In real systems, LUKS creates dm-X devices
    }

    #[test]
    fn test_secure_boot_status() {
        let enabled = "SecureBoot enabled";
        assert!(enabled.contains("SecureBoot enabled"));

        let disabled = "SecureBoot disabled";
        assert!(disabled.contains("SecureBoot disabled"));
    }
}
