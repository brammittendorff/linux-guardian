# 🚀 Quick Start Guide

## Installation

```bash
# Run the installation script
./install.sh
```

This will:
1. Install Rust (if not already installed)
2. Build Linux Guardian in release mode
3. Install the binary to `/usr/local/bin/` (with sudo)

## Basic Usage

### Run a Fast Security Scan (Recommended)

```bash
sudo linux-guardian
```

This performs critical security checks in 10-30 seconds:
- ✅ Vulnerable sudo version (CVE-2025-32462/32463)
- ✅ Suspicious SUID binaries
- ✅ Cryptominers and CPU anomalies
- ✅ Unauthorized SSH keys
- ✅ SSH brute force attacks
- ✅ Suspicious processes
- ✅ Malicious network connections

### Other Scan Modes

```bash
# Comprehensive scan (1-3 minutes)
sudo linux-guardian --mode comprehensive

# Deep scan (5-15 minutes)
sudo linux-guardian --mode deep

# JSON output for automation
sudo linux-guardian --output json

# Quiet mode (only show findings)
sudo linux-guardian --quiet
```

## Interpreting Results

### Severity Levels

- **🔴 CRITICAL**: Take immediate action - system likely compromised
- **🟠 HIGH**: Serious issue requiring prompt investigation
- **🟡 MEDIUM**: Potential concern to review
- **⚪ LOW**: Best practice recommendation

### Exit Codes

- `0`: No critical issues found
- `1`: Critical security issues detected

Use in scripts:
```bash
sudo linux-guardian
if [ $? -eq 0 ]; then
    echo "System is secure"
else
    echo "ALERT: Security issues detected!"
fi
```

## Common Findings & Remediation

### Vulnerable Sudo Version

**Finding**: CVE-2025-32462/32463 detected

**Fix**:
```bash
sudo apt update && sudo apt upgrade sudo
```

### Suspicious SUID Binary

**Finding**: SUID binary in /tmp or /dev/shm

**Fix**:
```bash
# Investigate first
sudo ls -la /tmp/suspicious-file
sudo file /tmp/suspicious-file

# Remove if malicious
sudo rm /tmp/suspicious-file
```

### Cryptominer Detected

**Finding**: Process 'xmrig' or connection to mining pool

**Fix**:
```bash
# Kill the process
sudo kill -9 <PID>

# Find how it persists
sudo crontab -l
cat /etc/crontab
systemctl list-timers

# Remove persistence
sudo crontab -e  # Remove malicious entries
```

### SSH Brute Force

**Finding**: 50+ failed login attempts from IP

**Fix**:
```bash
# Block the IP
sudo iptables -A INPUT -s <IP> -j DROP

# Or use fail2ban
sudo fail2ban-client set sshd banip <IP>

# Harden SSH
sudo vi /etc/ssh/sshd_config
# Set: PermitRootLogin no
# Set: PasswordAuthentication no
sudo systemctl restart sshd
```

### Unauthorized SSH Key

**Finding**: Recent modification to authorized_keys

**Fix**:
```bash
# Review the file
sudo cat /root/.ssh/authorized_keys

# Remove unauthorized keys
sudo vi /root/.ssh/authorized_keys

# Check all users
sudo find /home -name authorized_keys -exec ls -la {} \;
```

## Scheduling Regular Scans

### Daily Scan (Recommended)

```bash
# Add to root's crontab
sudo crontab -e

# Run daily at 2 AM
0 2 * * * /usr/local/bin/linux-guardian --quiet --output json >> /var/log/linux-guardian.log 2>&1
```

### Weekly Deep Scan

```bash
# Run weekly on Sunday at 3 AM
0 3 * * 0 /usr/local/bin/linux-guardian --mode comprehensive --output json >> /var/log/linux-guardian-weekly.log 2>&1
```

## Troubleshooting

### "Permission denied" errors

Run with sudo:
```bash
sudo linux-guardian
```

### Build fails

Ensure you have build tools:
```bash
sudo apt install build-essential pkg-config libssl-dev
```

### Slow performance

Use fast mode:
```bash
sudo linux-guardian --mode fast
```

## Getting Help

```bash
# Show all options
linux-guardian --help

# Enable verbose output for debugging
sudo linux-guardian --verbose
```

## What's Next?

1. **Run your first scan**: `sudo linux-guardian`
2. **Review the findings** and take recommended actions
3. **Schedule regular scans** for continuous monitoring
4. **Harden your system** based on recommendations
5. **Read the full README.md** for advanced usage

---

**Remember**: This tool detects threats but you must act on the findings!
