# Development Guide

## Build

```bash
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
cargo build --release
```

Requires Rust 1.75+.

## Project Structure

```
src/
  main.rs                          # CLI, argument parsing, scan orchestration
  lib.rs                           # Library exports
  models.rs                        # Finding, Severity types
  server_context.rs                # Server type detection, suppression config
  cve_db/
    mod.rs                         # CVE database init, schema, queries
    downloader.rs                  # CISA KEV + NVD feed downloading
    matcher.rs                     # Version matching against CPE ranges
  detectors/
    mod.rs                         # Detector module registry
    application_versions.rs        # Version detection for installed software
    binary_validation.rs           # System binary integrity checks
    bootloader.rs                  # GRUB/bootloader security
    container_security.rs          # Docker/container checks
    credential_theft.rs            # Exposed credentials, API keys
    cron_backdoor.rs               # Cron job persistence detection
    cryptominer.rs                 # Cryptominer process detection
    cve_database.rs                # CVE database scanning
    cve_knowledge_base.rs          # Hardcoded critical CVE checks
    disk_encryption.rs             # LUKS/encryption detection
    file_permissions.rs            # World-writable files, critical perms
    firewall.rs                    # UFW/iptables/nftables checks
    kernel_hardening.rs            # Sysctl security parameters
    malware_hashes.rs              # MalwareBazaar hash matching
    malware_hash_db.rs             # Malware hash database management
    mandatory_access_control.rs    # SELinux/AppArmor status
    memory_security.rs             # RWX memory, ASLR checks
    network/
      mod.rs                       # Network analysis orchestration
      connections.rs               # TCP/UDP parsing, hidden connection detection
      services.rs                  # Port reachability, service fingerprinting
      traffic.rs                   # DNS tunneling, reverse shells, C2 beaconing
    nvd_database.rs                # NVD CVE feed integration
    privilege_escalation.rs        # SUID binaries, capabilities
    process.rs                     # Hidden processes, suspicious activity
    process_capabilities.rs        # Linux capabilities analysis
    ssh.rs                         # SSH config, brute force detection
    updates.rs                     # Pending security updates
  utils/
    mod.rs
    privilege.rs                   # Root detection, privilege levels
    version.rs                     # Version parsing and comparison
```

## Adding a Detector

1. Create `src/detectors/your_detector.rs`:

```rust
use crate::models::Finding;
use anyhow::Result;

pub async fn detect() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Detection logic here

    if suspicious {
        findings.push(
            Finding::high(
                "category",
                "Title",
                "Description of what was found",
            )
            .with_remediation("How to fix it"),
        );
    }

    Ok(findings)
}
```

2. Register in `src/detectors/mod.rs`
3. Call from `src/main.rs` in `run_scan()`
4. Add privilege info in `src/utils/privilege.rs`

### Severity levels

- `Finding::critical()` - Active threats, exploited CVEs, malware
- `Finding::high()` - Exposed services, suspicious processes
- `Finding::medium()` - Misconfigurations, missing hardening
- `Finding::low()` - Informational, best practices

## CVE Database

### Schema

Two data sources merged into SQLite (`~/.cache/linux-guardian/cve.db`):

- **CISA KEV** - ~1,450 actively exploited CVEs (JSON feed, no API key)
- **NVD** - Critical CVEs with CVSS >= 7.0 (REST API, rate limited)

Tables: `cves`, `cpe_matches`, `cve_references`, `metadata`

### Adding hardcoded CVE checks

For critical CVEs that need immediate detection (before database update), add to `src/detectors/cve_knowledge_base.rs`:

```rust
CveDefinition {
    cve_id: "CVE-2025-XXXXX".to_string(),
    product: "package-name".to_string(),
    vulnerability_name: "Vulnerability Name".to_string(),
    description: "What it does".to_string(),
    min_version: Some("1.0.0".to_string()),
    max_version: Some("1.5.0".to_string()),
    fixed_version: Some("1.5.1".to_string()),
    cvss_score: 9.8,
    actively_exploited: true,
},
```

## Testing

```bash
cargo test                          # All tests
cargo test --lib                    # Unit tests only
cargo test --lib detectors::ssh     # Specific module
cargo clippy -- -D warnings         # Linter
cargo fmt                           # Format
```

## CI/CD

### `ci.yml` - Runs on every push/PR
- `cargo fmt --check`
- `cargo clippy`
- `cargo test`
- `cargo audit` (dependency vulnerabilities)

### `release.yml` - Runs on release/tag
- Builds packages for Debian, Ubuntu, Fedora, Rocky, Arch, Alpine
- Signs with GPG (requires `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` secrets)
- Uploads to GitHub release
- Publishes APT/RPM repository to GitHub Pages

### Package repository

After release, packages are available at `https://brammittendorff.github.io/linux-guardian/`.

To set up GPG signing:
```bash
gpg --full-generate-key             # RSA 4096, no expiry
gpg --armor --export-secret-keys KEY_ID  # Add as GPG_PRIVATE_KEY secret
```

## Architecture Notes

- All detectors are async (`tokio`) and run in parallel
- Findings use a unified `Finding` type with severity, category, remediation
- Server context auto-detects installed services to reduce false positives
- Suppression config (`/etc/linux-guardian.toml`) lets users whitelist known-good items
- No data leaves the machine - all scanning is local
