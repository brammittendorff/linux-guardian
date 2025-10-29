# 🛡️ Linux Guardian

> **A lightning-fast Linux security scanner that finds REAL threats with minimal false positives**

Linux Guardian is a comprehensive security scanner built in Rust that detects active threats on your Linux system in 10-30 seconds. Unlike traditional scanners that overwhelm you with hundreds of warnings, Linux Guardian focuses on **actionable findings** that matter.

> 💡 **Works without root!** Most security checks run perfectly fine without root privileges. You'll get a comprehensive security scan even as a regular user. Root access just enables a few additional checks (like SUID binary scanning).

## 🎯 What We're Really Good At

**1. Finding Active Threats Fast**
- Cryptominers (xmrig, kinsing, perfctl)
- Known malware (4M+ hash database from MalwareBazaar)
- Rootkits and hidden processes
- SSH brute force attacks
- Suspicious privilege escalation attempts

**2. Detecting Exploitable Vulnerabilities**
- 1,400+ actively exploited CVEs (CISA catalog)
- Version-specific vulnerability matching (sudo, kernel, openssh, systemd)
- Real CVEs that are being exploited in the wild RIGHT NOW

**3. Low False Positives**
- Smart detection: knows Chrome's JIT is normal, flags `/tmp/unknown-binary` with capabilities
- Generic package verification: uses dpkg/rpm, no hardcoded allowlists
- Context-aware analysis: understands what's legitimate vs. suspicious
- **Result: ~10 real findings instead of 1000+ false alarms**

**4. Privacy & Speed**
- 100% local scanning (no data leaves your machine)
- 10-30 second scans (Rust performance)
- No agents, no servers, no subscriptions
- Single static binary

## 📊 At a Glance

| Aspect | Linux Guardian | Traditional Scanners |
|--------|----------------|---------------------|
| **Scan Speed** | 10-30 seconds | 5-60 minutes |
| **False Positives** | ~10 findings (all actionable) | 500-1000+ findings (mostly noise) |
| **Setup** | Single binary, zero config | Complex agents, servers, configs |
| **Privacy** | 100% local | Often cloud-based |
| **CVE Database** | 1,400+ actively exploited | Generic vulnerability lists |
| **Malware Detection** | 4M+ hash database | Limited or signature-based |
| **Smart Detection** | Context-aware (knows Chrome JIT is OK) | Hardcoded rules (many false alarms) |
| **Cost** | Free & open source | Often expensive licenses |

## 👥 Who Should Use This?

✅ **Perfect for:**
- System administrators managing production servers
- DevOps teams adding security checks to CI/CD
- Security professionals doing incident response
- Anyone who suspects their Linux system might be compromised
- Developers who want to understand Linux security

✅ **Works great on:**
- Ubuntu, Debian, Fedora, Arch, and most Linux distros
- Servers, desktops, containers, and cloud instances
- Systems with or without root access (with different feature sets)

## 🚀 Quick Start

```bash
# Clone and install (installs Rust if needed, builds, and installs to /usr/local/bin)
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
./install.sh

# Run a scan (works without root too!)
linux-guardian              # Non-root: runs most checks, safe for any user
sudo linux-guardian         # Root: complete scan with all checks
```

**That's it!** The install script handles everything: Rust installation, building, and system installation. Takes ~2-5 minutes on first run.

**Don't have root?** No problem! Many security checks work perfectly without root privileges.

## 📖 Basic Usage

### Quick scan (no root needed!)

```bash
linux-guardian
```

Runs most security checks without root. Safe for any user. Shows findings in ~15 seconds.

**Color guide:** Red = bad, yellow = check it, white = info.

### Full scan (with root)

```bash
sudo linux-guardian
```

Runs ALL security checks including SUID binaries and system-wide process scanning.

**See what requires root:**
```bash
linux-guardian --show-privilege-info
```

### Quiet mode (only show problems)

```bash
linux-guardian --quiet              # Works without root
sudo linux-guardian --quiet         # With root for complete scan
```

### Show only active threats

```bash
linux-guardian --threats-only       # Works without root
```

### Check specific things

```bash
linux-guardian --category malware      # Only malware/cryptominers
linux-guardian --category hardening    # System security config
linux-guardian --category network      # Network security
```

### Different scan depths

```bash
linux-guardian                        # Fast (10-30s) - default, works without root
linux-guardian --mode comprehensive   # Thorough (1-3min), works without root
sudo linux-guardian --mode deep       # Complete (5-15min), root recommended
```

## 🎯 What It Detects

### Active Threats
- **Known Malware (Hash Database)**: ~4M malware hashes from MalwareBazaar
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
linux-guardian --output json     # For scripts/automation (works without root)
linux-guardian --output summary  # Just the score (works without root)
```

### Filter by severity

```bash
linux-guardian --min-severity high      # Only high + critical (works without root)
linux-guardian --min-severity critical  # Only critical (works without root)
```

### CVE database

```bash
# Update CVE database (do this weekly, needs root for system-wide cache)
sudo linux-guardian --update-cve-db

# See database stats (works without root)
linux-guardian --cve-db-stats

# Skip CVE checks (faster, works without root)
linux-guardian --no-cve-db
```

### Malware hash database

```bash
# Update malware hash database (do this weekly, needs root for system-wide cache)
sudo linux-guardian --update-malware-db

# See database stats (works without root)
linux-guardian --malware-db-stats

# Skip malware hash checks (faster, works without root)
linux-guardian --no-malware-db
```

The scanner checks **all executables and shared libraries** against **MalwareBazaar's database** (~1 million known malware SHA256 hashes).

**What gets scanned:**
- All system binaries: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`
- Shared libraries: `/lib`, `/usr/lib` (`.so` files)
- User installations: `/opt`, `/home`, `/root`
- Web applications: `/var/www`, `/srv`
- **High-risk locations**: `/tmp`, `/var/tmp`, `/dev/shm`

**Database details:**
- Source: [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/)
- Free, community-driven, updated daily
- **No API keys required**
- Download size: ~180MB (compressed)
- Scan time: Adds ~10-30 seconds depending on file count

### Automation

```bash
# CI/CD pipeline (works without root for most checks)
linux-guardian --output json --quiet > scan.json

# Daily cron job (non-root user)
0 2 * * * /usr/local/bin/linux-guardian --quiet >> ~/security.log 2>&1

# Daily cron job (as root for complete scan)
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

### Easy Install (Recommended)

```bash
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
./install.sh
```

The install script automatically:
- ✅ Installs Rust if not present
- ✅ Builds the project in release mode
- ✅ Installs to /usr/local/bin/linux-guardian
- ✅ Makes it available system-wide

### Manual Build (Advanced)

```bash
# If you already have Rust installed and want to build manually
cargo build --release
sudo cp target/release/linux-guardian /usr/local/bin/
```

### Requirements

- Linux (tested on Ubuntu, Debian, Fedora, Arch)
- Git (to clone the repository)
- Internet connection (for Rust installation and dependencies)
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

## 🤔 Why Linux Guardian?

### **The Problem with Traditional Security Scanners**

Most Linux security tools either:
1. **Generate too many false positives** (1000+ warnings, most meaningless)
2. **Miss real threats** (focus on outdated signatures or wrong indicators)
3. **Require complex setup** (agents, servers, cloud accounts, licenses)
4. **Sacrifice privacy** (send your data to external servers)

### **Our Solution**

Linux Guardian takes a different approach:
- **Smart heuristics** that understand legitimate behavior
- **Focused on real threats** that are actively being exploited
- **Zero-setup** single binary that works immediately
- **100% private** all scanning happens locally

### **Real-World Impact**

Traditional scanner output:
```
❌ 555 critical findings
   - systemd has capabilities (system process)
   - Chrome uses RWX memory (JavaScript JIT)
   - 1000+ generic "consider hardening X" warnings
   → You ignore all of them because it's noise
```

Linux Guardian output:
```
✅ 6 critical findings
   - Cryptominer "xmrig" detected (PID 12345) ← FIX NOW
   - Sudo vulnerable to CVE-2025-32462 ← PATCH NOW
   - 248 SSH brute force attempts detected ← INVESTIGATE
   → Every finding is actionable and important
```

## 🛡️ How It Works

### **Smart Detection Methods**

**1. Generic Package Verification**
- Uses `dpkg`/`rpm` to verify binaries are package-managed
- Trusts system packages, flags unknown binaries
- No hardcoded lists to maintain

**2. JIT Compiler Recognition**
- Detects V8, JVM, PyPy by artifacts (snapshot files, ICU data)
- Understands memory patterns of legitimate runtimes
- Prevents false alarms on Chrome, VS Code, Node.js

**3. Context-Aware Capabilities**
- Knows CAP_SYS_ADMIN is normal for systemd
- Flags same capability in `/tmp/unknown-binary`
- Understands Linux privilege model

**4. CVE Version Matching**
- Parses package versions from system
- Matches against 1,400+ known exploited vulnerabilities
- Only flags actually vulnerable versions

**5. Malware Hash Matching**
- Checks binaries against 4M+ known malware hashes
- Uses MalwareBazaar database (free, community-driven)
- Prioritizes high-risk locations like /tmp, /dev/shm

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
