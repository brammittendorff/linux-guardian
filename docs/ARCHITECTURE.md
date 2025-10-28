# Architecture Overview

## Project Structure

```
linux-guardian/
├── src/
│   ├── main.rs                    # Entry point, CLI, orchestration
│   ├── models/
│   │   └── mod.rs                 # Data structures (Finding, ScanMode, Severity)
│   ├── utils/
│   │   ├── mod.rs                 # Utility functions
│   │   └── privilege.rs           # Privilege checking
│   └── detectors/
│       ├── mod.rs                 # Detector module exports
│       ├── privilege_escalation.rs  # CVE checks, SUID scanning
│       ├── cryptominer.rs         # Miner detection, CPU analysis
│       ├── ssh.rs                 # SSH security, brute force
│       ├── process.rs             # Process analysis, hidden processes
│       └── network.rs             # Network connections, suspicious ports
├── Cargo.toml                     # Dependencies and build config
├── README.md                      # Full documentation
├── QUICK_START.md                 # Quick reference guide
├── ARCHITECTURE.md                # This file
└── install.sh                     # Installation script
```

## Core Components

### 1. Main Orchestrator (`main.rs`)

**Responsibilities:**
- CLI argument parsing (using `clap`)
- Privilege checking
- Scan mode selection (fast/comprehensive/deep)
- Parallel detector execution (using `tokio`)
- Result aggregation
- Output formatting (terminal/JSON)

**Flow:**
```
Parse CLI args → Check privileges → Run detectors in parallel → Aggregate results → Format output
```

### 2. Data Models (`models/mod.rs`)

**Key Structures:**

```rust
pub struct Finding {
    severity: String,      // critical, high, medium, low
    category: String,      // privilege_escalation, cryptominer, etc.
    title: String,
    description: String,
    remediation: Option<String>,
    cve: Option<String>,
    details: Option<serde_json::Value>,
}

pub enum ScanMode {
    Fast,           // 10-30s
    Comprehensive,  // 1-3min
    Deep,           // 5-15min
}
```

### 3. Detector Modules

Each detector is independent and returns `Vec<Finding>`:

#### **Privilege Escalation Detector**
- **File**: `detectors/privilege_escalation.rs`
- **Checks**:
  - Sudo version (CVE-2025-32462/32463, CVE-2021-3156)
  - SUID/SGID binaries with location-based risk assessment
  - Kernel version CVEs
  - File capabilities abuse
- **Data Sources**: `/usr/bin/sudo --version`, filesystem walk, `/proc/version`

#### **Cryptominer Detector**
- **File**: `detectors/cryptominer.rs`
- **Checks**:
  - Known miner process names
  - Suspicious process locations
  - Mining pool connections
  - Deleted binaries still running
  - CPU usage patterns
  - Cron job persistence
- **Data Sources**: `/proc/[pid]/*`, crontab files, process cmdline

#### **SSH Security Detector**
- **File**: `detectors/ssh.rs`
- **Checks**:
  - Unauthorized SSH keys
  - Recent key modifications
  - Brute force detection via log analysis
  - Dangerous SSH configurations
  - Root login detection
  - SSH binary tampering
- **Data Sources**: `~/.ssh/authorized_keys`, `/var/log/auth.log`, `/etc/ssh/sshd_config`

#### **Process Analyzer**
- **File**: `detectors/process.rs`
- **Checks**:
  - Known malware names
  - Processes in suspicious locations
  - Hidden processes (rootkit detection)
  - Deleted binaries
  - Orphaned processes
  - Network-listening processes
- **Data Sources**: `/proc`, process syscalls, `/proc/net/*`

#### **Network Analyzer**
- **File**: `detectors/network.rs`
- **Checks**:
  - Suspicious listening ports
  - Malicious connections
  - Mining pool connections
  - Hidden connections (discrepancies)
  - Excessive open ports
  - Unusual DNS servers
- **Data Sources**: `/proc/net/tcp`, `/proc/net/udp`, `ss` command, `/etc/resolv.conf`

## Execution Model

### Parallel Execution (Tokio)

```rust
let handles = vec![
    tokio::spawn(privilege_escalation::check_sudo_vulnerabilities()),
    tokio::spawn(privilege_escalation::scan_suid_binaries(is_root)),
    tokio::spawn(cryptominer::detect_cpu_anomalies()),
    tokio::spawn(ssh::check_unauthorized_keys()),
    tokio::spawn(ssh::detect_brute_force_attempts()),
    tokio::spawn(process::detect_suspicious_processes()),
    tokio::spawn(network::analyze_connections()),
];

for handle in handles {
    if let Ok(result) = handle.await {
        findings.extend(result?);
    }
}
```

### Benefits:
- **Speed**: All checks run concurrently
- **Efficiency**: I/O-bound operations don't block CPU
- **Scalability**: Easy to add more detectors

## Performance Optimizations

### 1. Early Termination
- Critical findings can trigger immediate alerts
- User can set thresholds for scan abortion

### 2. Caching
- System information cached (kernel version, etc.)
- Process list fetched once and shared
- Regex patterns compiled once

### 3. Selective Scanning
- Root-only checks skipped without privileges
- File walks limited by depth
- Log analysis limited to recent entries (last 10,000 lines)

### 4. Efficient Data Structures
- HashSet for O(1) lookups (whitelists, etc.)
- Vec for sequential findings
- Regex pre-compilation

## Security Considerations

### Read-Only Operations
- No modifications to system (except during remediation by user)
- No network requests (future: threat intel integration optional)
- All operations are local

### Privilege Handling
- Runs without root for basic checks
- Root required for:
  - Full SUID scan
  - Reading auth logs
  - Network socket enumeration
  - Process memory inspection

### False Positive Mitigation
- Whitelists for known-good binaries
- Context-aware severity (location matters)
- Multiple verification methods
- User-reviewable findings

## Extension Points

### Adding New Detectors

1. Create new module in `src/detectors/`
2. Implement detection functions returning `Result<Vec<Finding>>`
3. Export from `detectors/mod.rs`
4. Add to execution flow in `main.rs`

Example:
```rust
// src/detectors/container.rs
pub async fn check_container_escape() -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    // Detection logic here
    Ok(findings)
}

// src/main.rs
tokio::spawn(container::check_container_escape()),
```

### Adding New CVEs

Update the version checking logic in detector modules:

```rust
if major == 1 && minor == 9 && patch == 15 {
    findings.push(
        Finding::critical(...)
        .with_cve("CVE-2025-XXXXX")
    );
}
```

### Custom Output Formats

Extend the `output_*` functions in `main.rs`:

```rust
match args.output.as_str() {
    "json" => output_json(&findings, duration)?,
    "xml" => output_xml(&findings, duration)?,    // New
    "csv" => output_csv(&findings, duration)?,    // New
    _ => output_terminal(&findings, duration)?,
}
```

## Dependencies

### Core Runtime
- `tokio` - Async runtime for parallel execution
- `anyhow` - Error handling
- `tracing` - Structured logging

### System Interaction
- `nix` - Unix system calls
- `libc` - Low-level system interfaces
- `procfs` - /proc filesystem parsing

### CLI & Output
- `clap` - Command-line argument parsing
- `colored` - Terminal colors
- `serde` / `serde_json` - Serialization

### Utilities
- `regex` - Pattern matching
- `chrono` - Time handling
- `walkdir` - Filesystem walking
- `sha2` / `hex` - Hashing (future use)

## Future Enhancements

### Planned Features
1. **eBPF Integration**: Real-time syscall monitoring using `aya`
2. **Kernel Module**: Deeper rootkit detection
3. **Machine Learning**: Anomaly detection with trained models
4. **Container Support**: Docker/Kubernetes scanning
5. **Daemon Mode**: Continuous monitoring
6. **File Integrity Monitoring**: inotify-based watching
7. **Threat Intelligence**: Optional CVE feed integration
8. **Reporting**: HTML/PDF report generation

### Performance Targets
- Fast mode: < 10 seconds
- Comprehensive mode: < 60 seconds
- Memory usage: < 50MB
- CPU usage: < 3% average

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_sudo_version_parsing() {
        // Test version detection logic
    }
}
```

### Integration Tests
- Test full scan execution
- Verify finding generation
- Check output formats

### Benchmark Tests
```bash
cargo bench
```

## Build & Release

### Debug Build
```bash
cargo build
```

### Release Build (Optimized)
```bash
cargo build --release
```

### Release Optimizations (Cargo.toml)
```toml
[profile.release]
opt-level = 3        # Maximum optimization
lto = true           # Link-time optimization
codegen-units = 1    # Single codegen unit for better optimization
strip = true         # Strip symbols for smaller binary
```

### Binary Size
- Debug: ~15-20 MB
- Release (optimized): ~3-5 MB

## Contributing Guidelines

1. **Code Style**: Follow Rust style guide (`cargo fmt`)
2. **Documentation**: Document all public functions
3. **Testing**: Add tests for new detectors
4. **Performance**: Profile before/after changes
5. **Security**: No external dependencies without review

## License

MIT OR Apache-2.0 (dual-licensed for maximum compatibility)
