use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tracing::{debug, info};

/// Check bootloader security (GRUB)
pub async fn check_bootloader_security() -> Result<Vec<Finding>> {
    info!("🔍 Checking bootloader security...");
    let mut findings = Vec::new();

    // Check GRUB configuration
    let grub_configs = [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/*/grub.cfg",
    ];

    let mut grub_cfg = None;
    for config in &grub_configs {
        if std::path::Path::new(config).exists() {
            grub_cfg = Some(*config);
            break;
        }
    }

    if let Some(cfg_path) = grub_cfg {
        debug!("Found GRUB config: {}", cfg_path);

        // Check permissions (should be 600 or 400)
        if let Ok(metadata) = fs::metadata(cfg_path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode();
            let other_perms = mode & 0o007;

            if other_perms != 0 {
                findings.push(
                    Finding::medium(
                        "bootloader",
                        "GRUB Config Too Permissive",
                        &format!(
                            "{} has permissions {:o}. Should be 600 (rw-------) to prevent unauthorized reading.",
                            cfg_path,
                            mode & 0o777
                        ),
                    )
                    .with_remediation(&format!("Fix permissions: sudo chmod 600 {}", cfg_path)),
                );
            }
        }

        // Check for password protection
        if let Ok(content) = fs::read_to_string(cfg_path) {
            let has_password = content.contains("password_pbkdf2") || content.contains("password");

            if !has_password {
                findings.push(
                    Finding::high(
                        "bootloader",
                        "GRUB Not Password Protected",
                        "GRUB bootloader is not password protected. Attacker with physical access can bypass security via single-user mode or modify boot parameters.",
                    )
                    .with_remediation("Set GRUB password: sudo grub-mkpasswd-pbkdf2 && Edit /etc/grub.d/40_custom to add password"),
                );
            } else {
                debug!("GRUB has password protection configured");
            }

            // Check for dangerous boot parameters
            if content.contains("init=/bin/bash") || content.contains("single") {
                findings.push(
                    Finding::medium(
                        "bootloader",
                        "Dangerous Boot Parameters in GRUB Config",
                        "GRUB configuration contains potentially dangerous boot parameters",
                    )
                    .with_remediation("Review GRUB configuration: sudo vi /etc/default/grub"),
                );
            }
        }
    } else {
        debug!("GRUB configuration not found (might be using different bootloader)");
    }

    info!("  Checked bootloader security");
    Ok(findings)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_permission_checking() {
        let mode_600 = 0o100600; // rw-------
        let mode_644 = 0o100644; // rw-r--r--

        assert_eq!(mode_600 & 0o007, 0); // No other permissions
        assert_eq!(mode_644 & 0o007, 4); // Other can read
    }

    #[test]
    fn test_password_detection() {
        let with_password = "set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512...";
        assert!(with_password.contains("password_pbkdf2"));

        let without_password = "menuentry 'Ubuntu' {\n  linux /boot/vmlinuz\n}";
        assert!(!without_password.contains("password_pbkdf2"));
    }
}
