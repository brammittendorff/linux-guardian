# Changelog

All notable changes to Linux Guardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-10-20

### Added - Initial Release

#### Core Features
- **Comprehensive Linux Security Scanner** with 8 detection modules
- **Parallel Execution** using Tokio async runtime
- **Multiple Scan Modes**: Fast (10-30s), Comprehensive (1-3min), Deep (5-15min)
- **Flexible Output**: Terminal (colored) and JSON formats
- **CLI Interface** with clap: mode selection, verbosity, output format

#### Detection Modules

1. **🆕 CVE Database Integration** ⭐ Major Feature
   - **CISA KEV Catalog**: 1,400+ actively exploited CVEs
   - **NVD Database**: 314,000+ total CVEs (optional)
   - Automatic package version detection (dpkg, rpm, binaries)
   - Daily database updates with 24-hour caching
   - Offline mode support
   - Fuzzy product name matching
   - **Performance**: 1-3 seconds per scan

2. **Privilege Escalation Detector**
   - CVE-2025-32462 & CVE-2025-32463 (sudo vulnerabilities)
   - CVE-2021-3156 (Baron Samedit)
   - CVE-2023-0386 (OverlayFS)
   - CVE-2021-22555 (Netfilter)
   - SUID/SGID binary scanning with location analysis
   - File capabilities abuse detection
   - Whitelisted known-good binaries

3. **Cryptominer & Backdoor Detector**
   - Known miner detection (xmrig, kinsing, perfctl, kdevtmpfsi)
   - Mining pool connection detection
   - CPU anomaly detection (>80% usage)
   - Deleted binary detection
   - Cron job persistence analysis
   - Suspicious process locations (/tmp, /dev/shm, /var/tmp)

4. **SSH Security Analyzer**
   - Brute force attack detection (threshold-based)
   - Unauthorized SSH key detection
   - Recent key modification alerts
   - SSH configuration auditing (PermitRootLogin, PasswordAuthentication)
   - Successful login after brute force detection
   - Root login detection
   - SSH binary tampering detection

5. **Process Analyzer**
   - Known malware detection (kinsing, perfctl, etc.)
   - Hidden process detection (rootkit indicator)
   - Orphaned process detection
   - Deleted binary execution
   - Suspicious location detection
   - Network-listening process analysis

6. **Network Analyzer**
   - Suspicious port detection (4444, 31337, etc.)
   - High-numbered port monitoring
   - Mining pool connection detection
   - Hidden connection detection (rootkit indicator)
   - DNS configuration auditing
   - Connection count anomaly detection

7. **Rootkit Detection**
   - Hidden process detection (/proc vs syscall mismatch)
   - Hidden network connections
   - Deleted binary execution
   - Process/proc filesystem discrepancies

8. **Kernel Vulnerability Checker**
   - Kernel version CVE mapping
   - Known vulnerable kernel detection

#### Testing & Quality
- **Comprehensive Test Suite**: 100+ unit tests
- **7 Test Modules**: models, privilege_escalation, cve_database, cryptominer, ssh, process, network
- **Integration Tests**: 20+ end-to-end tests
- **Test Coverage**: ~90%+ estimated
- **CI-Ready**: All tests automated

#### Documentation
- **README.md**: Quick start and features overview
- **docs/README.md**: Complete documentation (375+ lines)
- **docs/QUICK_START.md**: 5-minute getting started guide
- **docs/ARCHITECTURE.md**: Technical implementation details
- **docs/CVE_DATABASE.md**: Comprehensive CVE integration guide (300+ lines)
- **docs/IMPLEMENTATION_PLAN.md**: Development roadmap and progress
- **BUILD_AND_TEST.md**: Complete build and test instructions (400+ lines)

#### Performance
- **Fast Mode**: 10-30 seconds typical
- **CPU Usage**: < 5% during scan
- **Memory**: < 100MB RAM
- **Binary Size**: ~3-5 MB (release, stripped)
- **Parallel Execution**: All detectors run concurrently

#### Infrastructure
- **Rust 2021 Edition**
- **14 Dependencies**: tokio, clap, serde, reqwest, nix, procfs, etc.
- **Cross-Platform Build**: Linux kernel 4.0+
- **Release Optimizations**: LTO, strip, single codegen unit

### Changed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Security
- Read-only operations (no system modifications)
- Memory-safe Rust implementation
- No data collection or external transmission
- Local CVE database caching

---

## Upcoming Features (v0.2.0)

### Planned
- [ ] Full version range matching for CVEs
- [ ] eBPF-based real-time monitoring
- [ ] Container security scanning (Docker, Kubernetes)
- [ ] Daemon mode with continuous monitoring
- [ ] File integrity monitoring (inotify)
- [ ] Inline hook detection
- [ ] Temporal anomaly detection
- [ ] Machine learning-based anomaly detection
- [ ] Additional package managers (pacman for Arch)
- [ ] GUI interface
- [ ] Email/webhook alerting
- [ ] SIEM integration plugins

### Under Consideration
- [ ] Windows/macOS support
- [ ] Browser extension for web-based monitoring
- [ ] Mobile app for remote monitoring
- [ ] Distributed scanning for multiple hosts
- [ ] Compliance reporting (CIS, NIST, etc.)
- [ ] Automatic remediation suggestions
- [ ] Integration with patch management systems

---

## Version History

- **v0.1.0** (2025-10-20): Initial release with 8 detection modules, CVE database integration, comprehensive testing
- **v0.0.1** (2025-10-20): Project initiated

---

## Migration Guide

### From 0.0.x to 0.1.0

This is the first release. No migration needed.

---

## Contributors

- Linux Guardian Development Team
- Based on 2025 security research from CISA, NVD, Trend Micro, and Thalium

---

**For detailed changes, see the [git log](https://github.com/your-repo/linux-guardian/commits/main)**
