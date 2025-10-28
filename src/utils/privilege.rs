use nix::unistd::{getuid, Uid};

/// Check if the current process is running with root privileges
pub fn check_privileges() -> bool {
    getuid() == Uid::from_raw(0)
}

/// Check if we have read access to a file
pub fn has_read_access(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// Privilege level required for a detector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// Detector works fully without root privileges
    None,
    /// Detector works partially without root (some features unavailable)
    Partial,
    /// Detector requires root privileges for all features
    Required,
}

/// Metadata about what requires privileges in a partial-privilege detector
#[derive(Debug, Clone)]
pub struct PrivilegeInfo {
    pub level: PrivilegeLevel,
    pub requires_root_for: Vec<&'static str>,
    pub works_without_root: Vec<&'static str>,
}

impl PrivilegeInfo {
    pub fn none() -> Self {
        Self {
            level: PrivilegeLevel::None,
            requires_root_for: vec![],
            works_without_root: vec![],
        }
    }

    pub fn required(reasons: Vec<&'static str>) -> Self {
        Self {
            level: PrivilegeLevel::Required,
            requires_root_for: reasons,
            works_without_root: vec![],
        }
    }

    pub fn partial(requires: Vec<&'static str>, works: Vec<&'static str>) -> Self {
        Self {
            level: PrivilegeLevel::Partial,
            requires_root_for: requires,
            works_without_root: works,
        }
    }
}

/// Get privilege requirements for a detector by name
pub fn get_detector_privilege_info(detector: &str) -> PrivilegeInfo {
    match detector {
        // NO ROOT REQUIRED
        "network" => PrivilegeInfo::none(),
        "cve_database" => PrivilegeInfo::none(),
        "cve_database_sqlite" => PrivilegeInfo::none(),
        "cve_knowledge_base" => PrivilegeInfo::none(),
        "application_versions" => PrivilegeInfo::none(),
        "nvd_database" => PrivilegeInfo::none(),
        "mandatory_access_control" => PrivilegeInfo::none(),
        "kernel_hardening" => PrivilegeInfo::none(),
        "disk_encryption" => PrivilegeInfo::none(),
        "updates" => PrivilegeInfo::none(),

        // PARTIAL ROOT
        "firewall" => PrivilegeInfo::partial(
            vec!["Full iptables/nftables ruleset inspection"],
            vec!["UFW status", "Firewalld status", "Basic rule counting"],
        ),
        "file_permissions" => PrivilegeInfo::partial(
            vec!["System-wide world-writable file scan"],
            vec!["Critical system file permission checks"],
        ),
        "container_security" => PrivilegeInfo::partial(
            vec!["Docker socket inspection", "Container process analysis"],
            vec!["Docker configuration checks", "Basic security scanning"],
        ),
        "package_integrity" => PrivilegeInfo::partial(
            vec!["Full dpkg --verify", "Full rpm -Va"],
            vec!["Package listing", "Basic integrity checks"],
        ),
        "ssh" => PrivilegeInfo::partial(
            vec![
                "Auth log analysis (/var/log/auth.log)",
                "Root SSH key checks",
            ],
            vec!["SSH config analysis", "User SSH key checks"],
        ),
        "bootloader" => PrivilegeInfo::partial(
            vec!["GRUB config reading (/boot/grub/grub.cfg)"],
            vec!["Basic bootloader detection"],
        ),
        "credential_theft" => PrivilegeInfo::partial(
            vec![
                "Other users' process fd inspection",
                "System-wide credential scan",
            ],
            vec!["Own process inspection", "User credential file checks"],
        ),
        "binary_validation" => PrivilegeInfo::partial(
            vec!["System binary hash verification", "Complete /usr/bin scan"],
            vec!["Package verification", "User binary checks"],
        ),
        "cryptominer" => PrivilegeInfo::partial(
            vec!["All users' process inspection", "System cron job checks"],
            vec!["CPU usage analysis", "Own process checks"],
        ),
        "malware_hashes" => PrivilegeInfo::partial(
            vec!["System-wide /home scan", "All users' temp directories"],
            vec!["/tmp scan", "/dev/shm scan", "Own directories"],
        ),
        "process" => PrivilegeInfo::partial(
            vec!["All users' /proc/*/fd inspection", "Complete process tree"],
            vec!["Hidden process detection", "Own process analysis"],
        ),

        // REQUIRES ROOT
        "privilege_escalation" => PrivilegeInfo::required(vec![
            "SUID binary scan requires read access to all filesystems",
            "Capability scan (getcap -r /) requires elevated privileges",
        ]),

        _ => PrivilegeInfo::none(), // Default to no requirements
    }
}

/// Get list of all detectors grouped by privilege level
pub fn group_detectors_by_privilege() -> (Vec<&'static str>, Vec<&'static str>, Vec<&'static str>) {
    let no_root = vec![
        "network",
        "cve_database",
        "cve_database_sqlite",
        "cve_knowledge_base",
        "application_versions",
        "nvd_database",
        "mandatory_access_control",
        "kernel_hardening",
        "disk_encryption",
        "updates",
    ];

    let partial_root = vec![
        "firewall",
        "file_permissions",
        "container_security",
        "package_integrity",
        "ssh",
        "bootloader",
        "credential_theft",
        "binary_validation",
        "cryptominer",
        "malware_hashes",
        "process",
    ];

    let requires_root = vec!["privilege_escalation"];

    (no_root, partial_root, requires_root)
}
