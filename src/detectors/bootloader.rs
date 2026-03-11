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

            // Check for dangerous boot parameters, categorized by severity.
            // "critical" = authentication bypass or kernel code integrity defeat
            // "high"     = disables major security features (MAC, hardware protections)
            // "medium"   = disables individual CPU mitigations or hardening

            check_boot_params(&content, &mut findings);
        }
    } else {
        debug!("GRUB configuration not found (might be using different bootloader)");
    }

    info!("  Checked bootloader security");
    Ok(findings)
}

/// Severity level for a dangerous boot parameter
enum ParamSeverity {
    Critical,
    High,
    Medium,
}

/// Check GRUB config content for dangerous boot parameters
fn check_boot_params(content: &str, findings: &mut Vec<Finding>) {
    // (parameter, severity, explanation)
    let dangerous_params: &[(&str, ParamSeverity, &str)] = &[
        // --- CRITICAL: Authentication bypass / kernel code integrity ---
        (
            "init=/bin/bash",
            ParamSeverity::Critical,
            "Replaces init with root shell — complete authentication bypass",
        ),
        (
            "init=/bin/sh",
            ParamSeverity::Critical,
            "Replaces init with root shell — complete authentication bypass",
        ),
        (
            "init=/sysroot/bin/bash",
            ParamSeverity::Critical,
            "Replaces init with root shell (ostree variant) — complete authentication bypass",
        ),
        (
            "rd.break",
            ParamSeverity::Critical,
            "Drops to initramfs root shell — used to reset root passwords",
        ),
        (
            "rodata=off",
            ParamSeverity::Critical,
            "Makes kernel code/data writable at runtime — defeats W^X for the kernel",
        ),
        (
            "rodata=0",
            ParamSeverity::Critical,
            "Makes kernel code/data writable at runtime — defeats W^X for the kernel",
        ),
        // --- HIGH: Disables major security features ---
        (
            "systemd.unit=rescue.target",
            ParamSeverity::High,
            "Boots into rescue mode — may provide root shell without password",
        ),
        (
            "systemd.unit=emergency.target",
            ParamSeverity::High,
            "Boots into emergency mode — root shell before most services start",
        ),
        (
            "selinux=0",
            ParamSeverity::High,
            "Disables SELinux mandatory access control entirely",
        ),
        (
            "enforcing=0",
            ParamSeverity::High,
            "Sets SELinux to permissive — violations logged but not enforced",
        ),
        (
            "apparmor=0",
            ParamSeverity::High,
            "Disables AppArmor application confinement",
        ),
        (
            "security=none",
            ParamSeverity::High,
            "Disables all Linux Security Modules (SELinux, AppArmor, etc.)",
        ),
        (
            "lockdown=none",
            ParamSeverity::High,
            "Disables kernel lockdown — allows userspace to modify running kernel",
        ),
        (
            "module.sig_enforce=0",
            ParamSeverity::High,
            "Disables kernel module signature enforcement — allows unsigned/tampered module loading",
        ),
        (
            "nosmep",
            ParamSeverity::High,
            "Disables Supervisor Mode Execution Prevention — kernel can execute userspace code",
        ),
        (
            "nosmap",
            ParamSeverity::High,
            "Disables Supervisor Mode Access Prevention — kernel can freely read/write userspace memory",
        ),
        (
            "noexec=off",
            ParamSeverity::High,
            "Disables NX bit enforcement — allows code execution from data pages",
        ),
        (
            "noexec32=off",
            ParamSeverity::High,
            "Disables NX for 32-bit executables — allows code execution from data segments",
        ),
        (
            "iommu=off",
            ParamSeverity::High,
            "Disables IOMMU — allows unrestricted DMA attacks via Thunderbolt/PCIe",
        ),
        (
            "intel_iommu=off",
            ParamSeverity::High,
            "Disables Intel VT-d IOMMU — allows DMA attacks",
        ),
        (
            "amd_iommu=off",
            ParamSeverity::High,
            "Disables AMD IOMMU — allows DMA attacks",
        ),
        (
            "nokaslr",
            ParamSeverity::High,
            "Disables kernel ASLR — makes kernel addresses predictable for exploit development",
        ),
        (
            "mitigations=off",
            ParamSeverity::High,
            "Disables ALL CPU vulnerability mitigations (Spectre, Meltdown, MDS, L1TF, etc.)",
        ),
        (
            "debugfs=on",
            ParamSeverity::High,
            "Mounts debugfs — exposes internal kernel debugging interfaces to userspace",
        ),
        (
            "kgdbwait",
            ParamSeverity::High,
            "Waits for kernel debugger at boot — allows full kernel control via debug connection",
        ),
        (
            "audit=0",
            ParamSeverity::High,
            "Disables kernel audit subsystem — prevents security event logging and forensics",
        ),
        // --- MEDIUM: Individual CPU mitigations / hardening weakened ---
        (
            "nopti",
            ParamSeverity::Medium,
            "Disables Page Table Isolation — removes Meltdown mitigation",
        ),
        (
            "kpti=0",
            ParamSeverity::Medium,
            "Disables kernel page table isolation (ARM64 Meltdown mitigation)",
        ),
        (
            "nospectre_v1",
            ParamSeverity::Medium,
            "Disables Spectre v1 (bounds check bypass) mitigation",
        ),
        (
            "nospectre_v2",
            ParamSeverity::Medium,
            "Disables Spectre v2 (branch target injection) mitigation",
        ),
        (
            "spectre_v2=off",
            ParamSeverity::Medium,
            "Disables all Spectre v2 mitigations",
        ),
        (
            "spec_store_bypass_disable=off",
            ParamSeverity::Medium,
            "Disables Spectre v4 (Speculative Store Bypass) mitigation",
        ),
        (
            "l1tf=off",
            ParamSeverity::Medium,
            "Disables L1 Terminal Fault (Foreshadow) mitigation",
        ),
        (
            "mds=off",
            ParamSeverity::Medium,
            "Disables Microarchitectural Data Sampling mitigation",
        ),
        (
            "tsx_async_abort=off",
            ParamSeverity::Medium,
            "Disables TSX Async Abort (TAA) mitigation",
        ),
        (
            "srbds=off",
            ParamSeverity::Medium,
            "Disables Special Register Buffer Data Sampling mitigation",
        ),
        (
            "mmio_stale_data=off",
            ParamSeverity::Medium,
            "Disables MMIO Stale Data mitigation",
        ),
        (
            "retbleed=off",
            ParamSeverity::Medium,
            "Disables Retbleed (return speculation) mitigation",
        ),
        (
            "gather_data_sampling=off",
            ParamSeverity::Medium,
            "Disables Gather Data Sampling (Downfall) mitigation",
        ),
        (
            "spec_rstack_overflow=off",
            ParamSeverity::Medium,
            "Disables Speculative Return Stack Overflow (AMD Inception) mitigation",
        ),
        (
            "tsx=on",
            ParamSeverity::Medium,
            "Enables Intel TSX — basis of multiple side-channel attacks (TAA, ZombieLoad)",
        ),
        (
            "norandmaps",
            ParamSeverity::Medium,
            "Disables userspace ASLR — makes all process memory layouts predictable",
        ),
        (
            "vsyscall=native",
            ParamSeverity::Medium,
            "Enables legacy vsyscall page at fixed address — reliable ROP gadget source",
        ),
        (
            "hardened_usercopy=0",
            ParamSeverity::Medium,
            "Disables hardened usercopy checks — removes slab boundary validation",
        ),
        (
            "init_on_alloc=0",
            ParamSeverity::Medium,
            "Disables zeroing of memory allocations — stale data may leak",
        ),
        (
            "init_on_free=0",
            ParamSeverity::Medium,
            "Disables zeroing of freed memory — sensitive data (keys, passwords) may persist",
        ),
        (
            "iommu.passthrough=1",
            ParamSeverity::Medium,
            "Sets IOMMU to passthrough mode — devices bypass DMA protection",
        ),
        (
            "randomize_kstack_offset=off",
            ParamSeverity::Medium,
            "Disables kernel stack randomization on syscall entry",
        ),
        (
            "nopku",
            ParamSeverity::Medium,
            "Disables Memory Protection Keys — removes hardware memory domain isolation",
        ),
    ];

    for (param, severity, reason) in dangerous_params {
        if content.contains(param) {
            let finding = match severity {
                ParamSeverity::Critical => Finding::critical(
                    "bootloader",
                    "Critical Boot Parameter in GRUB Config",
                    &format!("'{}': {}", param, reason),
                ),
                ParamSeverity::High => Finding::high(
                    "bootloader",
                    "Dangerous Boot Parameter in GRUB Config",
                    &format!("'{}': {}", param, reason),
                ),
                ParamSeverity::Medium => Finding::medium(
                    "bootloader",
                    "Security-Weakening Boot Parameter in GRUB Config",
                    &format!("'{}': {}", param, reason),
                ),
            };
            findings.push(finding.with_remediation(&format!(
                "Review and remove '{}' from /etc/default/grub, then run: sudo update-grub",
                param
            )));
        }
    }
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
