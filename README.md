# 🛡️ Linux Guardian - Security Scanner

**Fast Linux security scanner that detects real threats: rootkits, malware, cryptominers, and known vulnerabilities.**

Built in Rust. Scans your system in 10-30 seconds.

## 🚀 Quick Start

```bash
# Build it
cargo build --release

# Run without root (safe checks only)
./target/release/linux-guardian

# Run with root (complete scan)
sudo ./target/release/linux-guardian
```

That's it. It tells you if something's wrong.

## 📖 Basic Usage

### Just check if I'm hacked

```bash
sudo linux-guardian
```

Shows findings in ~15 seconds. Red = bad, yellow = check it, white = info.

### Without root privileges

```bash
./target/release/linux-guardian
```

Many checks work without root. It shows you exactly what's limited and what's not.

**See what requires root:**
```bash
./target/release/linux-guardian --show-privilege-info
```

### Quiet mode (only show problems)

```bash
sudo linux-guardian --quiet
```

### Show only active threats

```bash
sudo linux-guardian --threats-only
```

### Check specific things

```bash
sudo linux-guardian --category malware      # Only malware/cryptominers
sudo linux-guardian --category hardening    # System security config
sudo linux-guardian --category network      # Network security
```

### Different scan depths

```bash
sudo linux-guardian                        # Fast (10-30s) - default
sudo linux-guardian --mode comprehensive   # Thorough (1-3min)
sudo linux-guardian --mode deep            # Complete (5-15min)
```

## 🎯 What It Detects

### Active Threats
- **Cryptominers**: xmrig, kinsing, perfctl, and CPU-intensive malware
- **Rootkits**: Hidden processes, deleted binaries, process hiding
- **SSH Attacks**: Brute force attempts, unauthorized keys
- **Backdoors**: Suspicious network connections, unusual processes

### Known Vulnerabilities (CVE Database)
- **1,400+ actively exploited CVEs** from CISA's catalog
- Checks: sudo, kernel, openssh, systemd, polkit, dbus, and more
- Example: Detects vulnerable sudo versions (CVE-2025-32462/32463)

### Privilege Escalation
- Suspicious SUID binaries (setuid root files)
- Unusual file capabilities
- Binaries in dangerous locations (/tmp, /dev/shm)

### System Weaknesses
- Firewall disabled or misconfigured
- Unencrypted disks
- Weak SSH configuration
- Missing security updates
- Insecure kernel parameters

## 📊 Understanding Results

**🔴 CRITICAL** = Immediate threat. Fix now.
- Example: "Known cryptominer detected", "Actively exploited CVE found"

**🟠 HIGH** = Serious issue. Investigate today.
- Example: "Suspicious SUID binary", "Unauthorized SSH key"

**🟡 MEDIUM** = Potential problem. Check when you can.
- Example: "Unknown SUID binary", "High CPU usage"

**⚪ LOW** = Recommendation. Nice to fix.
- Example: "Firewall not enabled", "Disk not encrypted"

## 🔧 Advanced Options

### Output formats

```bash
sudo linux-guardian --output json     # For scripts/automation
sudo linux-guardian --output summary  # Just the score
```

### Filter by severity

```bash
sudo linux-guardian --min-severity high      # Only high + critical
sudo linux-guardian --min-severity critical  # Only critical
```

### CVE database

```bash
# Update CVE database (do this weekly)
sudo linux-guardian --update-cve-db

# See database stats
sudo linux-guardian --cve-db-stats

# Skip CVE checks (faster)
sudo linux-guardian --no-cve-db
```

### Automation

```bash
# CI/CD pipeline
sudo linux-guardian --output json --quiet > scan.json

# Daily cron job
0 2 * * * /usr/local/bin/linux-guardian --quiet >> /var/log/security.log 2>&1
```

## 💡 Privilege Separation

**10 detectors work fully without root:**
- CVE database checks
- Network connection analysis
- Kernel hardening checks
- Disk encryption detection
- System update checks

**11 detectors work partially without root:**
- SSH: Config analysis works, log analysis needs root
- Firewall: Basic status works, full rules need root
- Processes: Your processes work, all users need root
- Containers: Basic checks work, Docker socket needs root

**1 detector requires root:**
- SUID binary scanning (needs filesystem access)

Run `--show-privilege-info` to see exactly what needs root and why.

## 📦 Installation

### From source (recommended)

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
cargo build --release

# Install (optional)
sudo cp target/release/linux-guardian /usr/local/bin/
```

### Requirements

- Rust 1.75+
- Linux (tested on Ubuntu, Debian, Fedora, Arch)
- Root access for complete scans (optional for basic checks)

## 🔍 Real-World Examples

**Finding 1: Cryptominer**
```
🔴 CRITICAL Known Cryptominer Process Detected
  Process "xmrig" (PID 12345) is a known cryptominer
  💡 Remediation: kill -9 12345 && investigate how it got there
```

**Finding 2: Vulnerable sudo**
```
🔴 CRITICAL Vulnerable Sudo Version Detected
  Sudo version 1.9.15 vulnerable to CVE-2025-32462
  💡 Remediation: apt update && apt upgrade sudo
```

**Finding 3: SSH attack**
```
🟠 HIGH SSH Brute Force Attack Detected
  248 failed login attempts in last 24h
  💡 Remediation: Check /var/log/auth.log, consider fail2ban
```

**Finding 4: Suspicious SUID**
```
🟠 HIGH Unpackaged SUID Binary Detected
  /tmp/exploit has SUID bit set, not managed by package manager
  💡 Remediation: Remove: sudo rm /tmp/exploit
```

## 🛡️ What Makes This Different

**Fast**: 10-30 seconds for most scans
**Accurate**: Smart filtering, minimal false positives
**Practical**: Clear remediation steps
**Private**: All scanning is local, no data sent anywhere
**Open**: Full source code, no mystery boxes

## ⚡ Performance

- **Scan time**: 10-30 seconds (fast mode)
- **CPU usage**: <5% during scan
- **Memory**: <100MB
- **Disk**: Read-only, no modifications

## 🔒 Security & Privacy

- ✅ All scanning is local
- ✅ No data sent to external servers
- ✅ Read-only operations
- ✅ Open source (audit the code)
- ✅ No telemetry or tracking

## 🐛 Known Limitations

- **Kernel rootkits**: Limited detection (needs eBPF/kernel modules)
- **Encrypted malware**: Can't scan encrypted files
- **Memory-only threats**: Doesn't scan RAM (yet)
- **Zero-days**: Only detects known threats + suspicious behavior

Use as **part** of your security, not the only tool.

## 🤝 Contributing

PRs welcome! Especially for:
- New CVE checks
- Better cryptominer detection
- Container security improvements
- Performance optimizations

## 📜 License

MIT OR Apache-2.0

## ⚠️ Legal

**Defensive use only.** For systems you own or have permission to scan.

Do not:
- Scan systems you don't own
- Use for offensive security without authorization
- Rely on this as your only security tool

Always investigate findings before taking action.

## 📚 References

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST NVD](https://nvd.nist.gov/)
- [CVE Database Documentation](docs/CVE_DATABASE.md)
- [Verification Guide](docs/VERIFICATION_GUIDE.md)

## 💬 Support

Issues and questions: [GitHub Issues](https://github.com/brammittendorff/linux-guardian/issues)

---

**Keep your system secure. 🛡️**
