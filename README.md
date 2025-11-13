# Linux Guardian

**A lightning-fast Linux security scanner that finds REAL threats with minimal false positives**

Detects active threats on your Linux system in 10-30 seconds. Built in Rust with 30+ specialized detectors for malware, CVEs, rootkits, and network attacks.

> **Works without root!** Most security checks run perfectly fine without root privileges.

## What It Finds

- **Active Threats**: Cryptominers, known malware (4M+ hashes), rootkits, reverse shells, C2 beaconing
- **Exploitable CVEs**: 1,400+ actively exploited vulnerabilities from CISA catalog
- **Network Attacks**: SSH brute force, suspicious connections, data exfiltration, exposed services
- **Privilege Escalation**: Suspicious SUID binaries, dangerous capabilities, backdoors
- **System Weaknesses**: Firewall disabled, weak configs, missing updates

## Quick Start

```bash
# Clone and install (handles Rust installation, builds, installs to /usr/local/bin)
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
./install.sh

# Run a scan (works without root!)
linux-guardian                   # Fast scan (10-30s)
sudo linux-guardian --mode deep  # Complete scan with all checks
```

## Why Use This?

| Linux Guardian | Traditional Scanners |
|----------------|---------------------|
| 10-30 seconds | 5-60 minutes |
| ~10 real findings | 500-1000+ false alarms |
| Single binary | Complex agents/servers |
| 100% local | Often cloud-based |
| 1,400+ actively exploited CVEs | Generic CVE lists |

## Usage Examples

```bash
# Quick scan (no root needed)
linux-guardian

# Full scan with root
sudo linux-guardian

# Only show problems
linux-guardian --quiet

# Only show active threats
linux-guardian --threats-only

# Check specific category
linux-guardian --category malware

# Different scan depths
linux-guardian                        # Fast (10-30s, default)
linux-guardian --mode comprehensive   # Thorough (1-3min)
sudo linux-guardian --mode deep       # Complete (5-15min)

# Output formats
linux-guardian --output json
linux-guardian --output summary
```

## Detection Capabilities

**30+ specialized detectors** across:
- Malware & Threats (cryptominers, known hashes, rootkits, reverse shells)
- Vulnerabilities (CISA KEV + NVD CVE databases)
- Network Security (service fingerprinting, C2 beaconing, data exfiltration)
- Privilege Escalation (SUID binaries, file capabilities)
- System Hardening (kernel params, firewall, disk encryption)
- Persistence Mechanisms (systemd, cron, eBPF, kernel modules)
- Credential Theft (SSH keys, cookies, API keys)

## CVE & Malware Databases

### CVE Database (1,400+ actively exploited)
```bash
linux-guardian --update-cve-db     # Update CVE database
linux-guardian --cve-db-stats      # Show database info
```

### Malware Hash Database (4M+ hashes)
```bash
linux-guardian --update-malware-db    # Update malware hashes
linux-guardian --malware-db-stats     # Show database info
```

## Advanced Options

```bash
# Filter by severity
linux-guardian --min-severity high

# Automation & CI/CD
linux-guardian --output json --quiet > scan.json

# Privilege information
linux-guardian --show-privilege-info
```

## Privilege Separation

- **10 detectors** work fully without root (CVE checks, network analysis, kernel hardening)
- **11 detectors** work partially without root (SSH config, firewall status, own processes)
- **1 detector** requires root (SUID binary scanning)

## How It Works

**Smart Detection:**
- Generic package verification (dpkg/rpm, no hardcoded allowlists)
- JIT compiler recognition (knows Chrome's V8 is legitimate)
- Context-aware capabilities (CAP_SYS_ADMIN normal for systemd, suspicious in /tmp)
- Version-specific CVE matching (only flags actually vulnerable versions)
- Network service fingerprinting (intelligent banner grabbing)

## Real-World Examples

**Cryptominer detected:**
```
CRITICAL Known Cryptominer Process Detected
  Process "xmrig" (PID 12345) is a known cryptominer
  Remediation: kill -9 12345 && investigate how it got there
```

**Vulnerable sudo:**
```
CRITICAL Vulnerable Sudo Version Detected
  Sudo version 1.9.15 vulnerable to CVE-2025-32462
  Remediation: apt update && apt upgrade sudo
```

**SSH brute force:**
```
HIGH SSH Brute Force Attack Detected
  248 failed login attempts in last 24h
  Remediation: Check /var/log/auth.log, consider fail2ban
```

## Performance

- Scan time: 10-30 seconds (fast mode)
- CPU usage: <5% during scan
- Memory: <100MB
- Read-only operations (no system modifications)

## Security & Privacy

All scanning is local | No data sent to external servers | Open source | No telemetry

## Known Limitations

- Kernel rootkits: Limited detection (needs eBPF/kernel modules)
- Encrypted malware: Can't scan encrypted files
- Memory-only threats: Doesn't scan RAM
- Zero-days: Only detects known threats + suspicious behavior

Use as **part** of your security, not the only tool.

## Contributing

PRs welcome! Especially for: New CVE checks, better cryptominer detection, container security, performance optimizations.

## License

MIT OR Apache-2.0

## Legal

**Defensive use only.** For systems you own or have permission to scan. Do not scan systems you don't own or use for offensive security without authorization.

## Documentation

- [CVE Database Documentation](docs/CVE_DATABASE.md)
- [Verification Guide](docs/VERIFICATION_GUIDE.md)
- [GitHub Issues](https://github.com/brammittendorff/linux-guardian/issues)

---

**Keep your system secure.**
