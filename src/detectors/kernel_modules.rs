use crate::models::Finding;
use anyhow::Result;
use std::fs;
use std::process::Command;
use tracing::{debug, info};

/// Detect suspicious kernel modules (common rootkit vector)
pub async fn detect_kernel_modules() -> Result<Vec<Finding>> {
    info!("🔍 Checking for suspicious kernel modules...");
    let mut findings = Vec::new();

    // Get list of loaded kernel modules
    let modules = match fs::read_to_string("/proc/modules") {
        Ok(content) => content,
        Err(e) => {
            debug!("Could not read /proc/modules: {}", e);
            return Ok(findings);
        }
    };

    let mut module_names = Vec::new();
    for line in modules.lines() {
        if let Some(name) = line.split_whitespace().next() {
            module_names.push(name);
        }
    }

    debug!("Found {} loaded kernel modules", module_names.len());

    // Suspicious module name patterns (known rootkits)
    let suspicious_patterns = [
        "diamorphine",
        "reptile",
        "suterusu",
        "rootkit",
        "backdoor",
        "hide",
        "stealth",
        "keylog",
        "sniffer",
        "kovid",
        "maK_it",
        "vlany",
    ];

    for module in &module_names {
        let module_lower = module.to_lowercase();

        // Check for known rootkit names
        for pattern in &suspicious_patterns {
            if module_lower.contains(pattern) {
                findings.push(
                    Finding::critical(
                        "kernel_rootkit",
                        "Known Rootkit Kernel Module Detected",
                        &format!(
                            "Kernel module '{}' matches known rootkit pattern '{}'. System is likely compromised!",
                            module, pattern
                        ),
                    )
                    .with_remediation(&format!("Remove immediately: sudo rmmod {} && investigate /lib/modules/$(uname -r)/", module)),
                );
            }
        }
    }

    // Check for unsigned modules (if signature checking is enabled)
    if let Ok(output) = Command::new("modinfo")
        .arg("--field=sig_key")
        .args(&module_names)
        .output()
    {
        let sig_info = String::from_utf8_lossy(&output.stdout);

        for (i, sig) in sig_info.lines().enumerate() {
            if sig.is_empty() && i < module_names.len() {
                // Check if module signature checking is enforced
                if let Ok(secure_boot_data) = fs::read(
                    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                ) {
                    if secure_boot_data.contains(&1u8) {
                        findings.push(
                            Finding::high(
                                "unsigned_module",
                                "Unsigned Kernel Module Loaded",
                                &format!(
                                    "Module '{}' is not signed but Secure Boot is enabled. Could be malicious!",
                                    module_names[i]
                                ),
                            )
                            .with_remediation(&format!("Investigate: modinfo {} && sudo rmmod {}", module_names[i], module_names[i])),
                        );
                    }
                }
            }
        }
    }

    // Check for modules loaded from suspicious locations
    for module in &module_names {
        if let Ok(output) = Command::new("modinfo")
            .arg("--field=filename")
            .arg(module)
            .output()
        {
            let path = String::from_utf8_lossy(&output.stdout);
            let path_lower = path.to_lowercase();

            // Modules should be in /lib/modules or /usr/lib/modules
            if !path_lower.contains("/lib/modules") && !path_lower.is_empty() {
                findings.push(
                    Finding::critical(
                        "suspicious_module_location",
                        "Kernel Module Loaded from Unusual Location",
                        &format!(
                            "Module '{}' loaded from suspicious path: {}. Likely rootkit!",
                            module,
                            path.trim()
                        ),
                    )
                    .with_remediation(&format!(
                        "Remove: sudo rmmod {} && rm -f {}",
                        module,
                        path.trim()
                    )),
                );
            }

            // Check for modules in /tmp or /dev/shm (red flag!)
            if path_lower.contains("/tmp")
                || path_lower.contains("/dev/shm")
                || path_lower.contains("/var/tmp")
            {
                findings.push(
                    Finding::critical(
                        "module_in_temp",
                        "Kernel Module in Temporary Directory",
                        &format!(
                            "Module '{}' in temp directory {}. DEFINITE ROOTKIT!",
                            module,
                            path.trim()
                        ),
                    )
                    .with_remediation(&format!(
                        "Emergency: sudo rmmod {} && sudo rm -f {} && reboot into recovery",
                        module,
                        path.trim()
                    )),
                );
            }
        }
    }

    // Check for recently loaded modules (last 10 minutes)
    if let Ok(dmesg) = Command::new("dmesg").args(["-T", "--level=info"]).output() {
        let log = String::from_utf8_lossy(&dmesg.stdout);

        // Look for recent module loads in dmesg
        for line in log.lines().rev().take(100) {
            if line.contains("module loaded") || line.contains("loading module") {
                // Check timestamp (dmesg -T gives human timestamps)
                debug!("Recent module load: {}", line);
            }
        }
    }

    // Check for hidden modules (not in /proc/modules but in lsmod)
    if let Ok(lsmod_output) = Command::new("lsmod").output() {
        let lsmod = String::from_utf8_lossy(&lsmod_output.stdout);
        let lsmod_modules: Vec<&str> = lsmod
            .lines()
            .skip(1) // Skip header
            .filter_map(|l| l.split_whitespace().next())
            .collect();

        for lsmod_mod in lsmod_modules {
            if !module_names.contains(&lsmod_mod) {
                findings.push(
                    Finding::critical(
                        "hidden_module",
                        "Hidden Kernel Module Detected",
                        &format!(
                            "Module '{}' appears in lsmod but NOT in /proc/modules. Rootkit hiding technique!",
                            lsmod_mod
                        ),
                    )
                    .with_remediation("System likely compromised. Consider clean reinstall."),
                );
            }
        }
    }

    if findings.is_empty() {
        debug!(
            "Kernel module check passed: {} modules, none suspicious",
            module_names.len()
        );
    }

    Ok(findings)
}

/// Check for suspicious module parameters (can enable rootkit features)
pub async fn check_module_parameters() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check /sys/module/ for suspicious parameters
    if let Ok(entries) = fs::read_dir("/sys/module") {
        for entry in entries.flatten() {
            let module_name = entry.file_name();
            let params_path = entry.path().join("parameters");

            if params_path.exists() {
                if let Ok(param_entries) = fs::read_dir(&params_path) {
                    for param_entry in param_entries.flatten() {
                        let param_name = param_entry.file_name();
                        let param_name_str = param_name.to_string_lossy();

                        // Check for truly suspicious parameters
                        // Only flag if the parameter is actually ENABLED (not just exists)
                        if let Ok(value) = fs::read_to_string(param_entry.path()) {
                            let value_trimmed = value.trim();

                            // Rootkit-style parameters - but only if ENABLED
                            let always_suspicious = (param_name_str.contains("hide")
                                || param_name_str.contains("stealth"))
                                && (value_trimmed != "0"
                                    && value_trimmed != "N"
                                    && !value_trimmed.is_empty());

                            // Backdoor parameters - flag if enabled
                            let backdoor_enabled = param_name_str.contains("backdoor")
                                && (value_trimmed != "0"
                                    && value_trimmed != "N"
                                    && value_trimmed != "n"
                                    && !value_trimmed.is_empty());

                            // Debug parameters are only suspicious if ENABLED
                            let debug_enabled = (param_name_str.contains("debug")
                                || param_name_str.contains("verbose"))
                                && (value_trimmed != "0"
                                    && value_trimmed != "N"
                                    && !value_trimmed.is_empty());

                            // Root-related parameters enabled
                            let root_enabled = param_name_str.contains("root")
                                && value_trimmed != "0"
                                && value_trimmed != "N";

                            if always_suspicious
                                || backdoor_enabled
                                || (debug_enabled && !param_name_str.contains("nodebug"))
                                || root_enabled
                            {
                                findings.push(
                                    Finding::medium(
                                        "suspicious_module_param",
                                        "Suspicious Kernel Module Parameter",
                                        &format!(
                                            "Module '{}' has suspicious parameter '{}' = '{}'",
                                            module_name.to_string_lossy(),
                                            param_name_str,
                                            value_trimmed
                                        ),
                                    )
                                    .with_remediation("Investigate module behavior"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}
