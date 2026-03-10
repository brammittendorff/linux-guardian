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

## Install

### Debian / Ubuntu

```bash
curl -fsSL https://brammittendorff.github.io/linux-guardian/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/linux-guardian.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/linux-guardian.gpg] https://brammittendorff.github.io/linux-guardian/deb stable main" | sudo tee /etc/apt/sources.list.d/linux-guardian.list
sudo apt update && sudo apt install linux-guardian
```

### Fedora / RHEL / Rocky Linux

```bash
sudo dnf config-manager addrepo --from-repofile=https://brammittendorff.github.io/linux-guardian/rpm/linux-guardian.repo
sudo dnf install linux-guardian
```

### From source

```bash
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
cargo build --release
sudo cp target/release/linux-guardian /usr/local/bin/
```

## Quick Start

```bash
# First-time setup (interactive - choose which databases to download)
linux-guardian setup

# Scan
linux-guardian                # Fast scan (10-30s)
sudo linux-guardian --deep    # Full scan with all checks
```

## Why Use This?

| Linux Guardian | Traditional Scanners |
|----------------|---------------------|
| 10-30 seconds | 5-60 minutes |
| ~10 real findings | 500-1000+ false alarms |
| Single binary | Complex agents/servers |
| 100% local | Often cloud-based |
| 1,400+ actively exploited CVEs | Generic CVE lists |

## Usage

```bash
linux-guardian                    # Fast scan
sudo linux-guardian --deep        # Full scan (all checks)
linux-guardian update             # Update databases
linux-guardian stats              # Show database info

# Filters
linux-guardian -t                 # Threats only
linux-guardian -s high            # Minimum severity
linux-guardian -c malware         # Category filter
linux-guardian -j                 # JSON output
linux-guardian -q                 # Quiet (findings only)
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

```bash
linux-guardian update    # Download/update CVE + malware hash databases
linux-guardian stats     # Show database info
```

Automate with cron:
```bash
0 3 * * 0 /usr/local/bin/linux-guardian update
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

MIT

## Legal

**Defensive use only.** For systems you own or have permission to scan. Do not scan systems you don't own or use for offensive security without authorization.

## Documentation

- [Development Guide](docs/DEVELOPMENT.md)
- [Contributing](docs/CONTRIBUTING.md)
- [GitHub Issues](https://github.com/brammittendorff/linux-guardian/issues)

---

**Keep your system secure.**
