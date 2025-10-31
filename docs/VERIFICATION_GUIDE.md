# Verification Guide

This guide helps you verify Linux Guardian's findings and understand how to investigate security issues detected by the scanner.

## Table of Contents

1. [Critical Findings](#critical-findings)
2. [High Severity Findings](#high-severity-findings)
3. [Medium Severity Findings](#medium-severity-findings)
4. [False Positive Identification](#false-positive-identification)
5. [Remediation Steps](#remediation-steps)
6. [Verification Tools](#verification-tools)

## Critical Findings

### 🔴 Known Cryptominer Detected

**Finding:**
```
🔴 CRITICAL Known Cryptominer Process Detected
  Process "xmrig" (PID 12345) is a known cryptominer
  💡 Remediation: kill -9 12345 && investigate how it got there
```

**Verification Steps:**

1. **Confirm the process:**
   ```bash
   ps aux | grep 12345
   top -p 12345
   ```

2. **Check CPU usage:**
   ```bash
   top -p 12345
   # Look for high CPU % (often 90-100%)
   ```

3. **Find the binary:**
   ```bash
   ls -la /proc/12345/exe
   readlink -f /proc/12345/exe
   ```

4. **Check connections:**
   ```bash
   sudo lsof -p 12345 | grep -i tcp
   sudo netstat -tanp | grep 12345
   ```

5. **Inspect the binary:**
   ```bash
   strings /path/to/binary | grep -i "pool\|mining\|stratum\|xmr\|crypto"
   file /path/to/binary
   ```

**What to look for:**
- Connections to mining pools (port 3333, 4444, 5555)
- Strings like "stratum+tcp", "xmrig", "pool", "donate-level"
- High CPU usage sustained over time
- Process running from unusual locations (/tmp, /dev/shm, /var/tmp)

**Remediation:**
```bash
# Kill the process
sudo kill -9 12345

# Remove the binary
sudo rm /path/to/binary

# Check for persistence mechanisms
sudo grep -r "xmrig" /etc/systemd/system/
sudo grep -r "xmrig" /etc/cron*
sudo grep -r "xmrig" ~/.config/autostart/

# Check rc.local
cat /etc/rc.local
```

**Prevention:**
- Update all software
- Check for vulnerable web applications
- Review SSH authorized_keys
- Enable fail2ban
- Check firewall rules

---

### 🔴 Actively Exploited CVE Detected

**Finding:**
```
🔴 CRITICAL CVE-2025-32462 - Sudo Vulnerability (Actively Exploited)
  Sudo version 1.9.15 is affected by Sudo Policy-Check Bypass
  This vulnerability is in CISA's Known Exploited Vulnerabilities catalog
  💡 Remediation: URGENT: Apply updates. Due date: 2025-02-10. Update sudo immediately.
```

**Verification Steps:**

1. **Confirm the version:**
   ```bash
   sudo --version
   dpkg -l sudo
   apt-cache policy sudo
   ```

2. **Check vulnerability details:**
   ```bash
   # Search for CVE online
   curl -s "https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2025-32462" | jq

   # Or visit
   # https://nvd.nist.gov/vuln/detail/CVE-2025-32462
   ```

3. **Check if distro has patched it:**
   ```bash
   # Debian/Ubuntu
   apt-cache policy sudo
   apt changelog sudo | grep CVE-2025-32462

   # RHEL/CentOS
   yum info sudo
   rpm -q --changelog sudo | grep CVE-2025-32462
   ```

4. **Check for exploitation attempts:**
   ```bash
   # Check sudo logs
   sudo journalctl -u sudo -since "1 week ago"

   # Check auth logs
   sudo grep sudo /var/log/auth.log | tail -50
   ```

**What to look for:**
- Version matches vulnerable range
- No backported security patches
- Unusual sudo usage patterns in logs
- Failed sudo attempts with unusual options

**Remediation:**
```bash
# Debian/Ubuntu
sudo apt update
sudo apt upgrade sudo

# Verify fixed
sudo --version

# Should show patched version
```

**False Positive Check:**
- Verify your distro hasn't backported the fix
- Check vendor security advisories:
  - Ubuntu: https://ubuntu.com/security/CVEs
  - Debian: https://security-tracker.debian.org/tracker/
  - RHEL: https://access.redhat.com/security/security-updates/

---

### 🔴 Known Malware Hash Match

**Finding:**
```
🔴 CRITICAL Known Malware Detected
  File /tmp/suspicious matches known malware hash (SHA256: abc123...)
  Matched: MalwareBazaar malware database
  💡 Remediation: Quarantine immediately: sudo mv /tmp/suspicious /var/quarantine/
```

**Verification Steps:**

1. **Verify the hash:**
   ```bash
   sha256sum /tmp/suspicious
   ```

2. **Check file details:**
   ```bash
   file /tmp/suspicious
   ls -la /tmp/suspicious
   stat /tmp/suspicious
   ```

3. **Look up hash online:**
   ```bash
   # MalwareBazaar
   curl "https://mb-api.abuse.ch/api/v1/" \
     -d "query=get_info" \
     -d "hash=<SHA256>"

   # VirusTotal (if you have an API key)
   curl "https://www.virustotal.com/api/v3/files/<SHA256>" \
     -H "x-apikey: YOUR_API_KEY"
   ```

4. **Check what's using it:**
   ```bash
   sudo lsof | grep /tmp/suspicious
   ps aux | grep suspicious
   ```

5. **Inspect strings:**
   ```bash
   strings /tmp/suspicious | less
   # Look for: URLs, IPs, domain names, suspicious commands
   ```

**What to look for:**
- File created recently
- Running process associated with it
- Network connections from the process
- Other similar files in /tmp, /dev/shm
- Modified system files or configs

**Remediation:**
```bash
# 1. Stop any running processes
sudo pkill -f suspicious

# 2. Quarantine the file (don't delete yet, for forensics)
sudo mkdir -p /var/quarantine
sudo mv /tmp/suspicious /var/quarantine/

# 3. Check for other instances
sudo find / -name "suspicious" 2>/dev/null

# 4. Check for persistence
sudo grep -r "suspicious" /etc/systemd/system/
sudo grep -r "suspicious" /etc/cron*
sudo find ~/.config -name "*suspicious*"

# 5. Check network connections
sudo netstat -tanp | grep -i "established"

# 6. Review recent file changes
sudo find /etc /root /home -type f -mtime -7
```

**Post-Incident:**
- Change all passwords
- Review SSH keys
- Check for unauthorized users
- Review firewall logs
- Consider full system reinstall

---

## High Severity Findings

### 🟠 Unpackaged SUID Binary

**Finding:**
```
🟠 HIGH Unpackaged SUID Binary Detected
  Found SUID binary not managed by package manager: /tmp/exploit
  💡 Remediation: Investigate origin: ls -la '/tmp/exploit' && file '/tmp/exploit'
```

**Verification Steps:**

1. **Check binary details:**
   ```bash
   ls -la /tmp/exploit
   file /tmp/exploit
   stat /tmp/exploit
   ```

2. **Verify it's not packaged:**
   ```bash
   # Debian/Ubuntu
   dpkg -S /tmp/exploit

   # RHEL/CentOS
   rpm -qf /tmp/exploit

   # Should return: not owned by any package
   ```

3. **Check for symlinks:**
   ```bash
   readlink -f /tmp/exploit
   # If it's a symlink, check the target
   dpkg -S $(readlink -f /tmp/exploit)
   ```

4. **Inspect the binary:**
   ```bash
   strings /tmp/exploit | head -50
   objdump -d /tmp/exploit | head
   ```

5. **Check file history:**
   ```bash
   # When was it created?
   stat /tmp/exploit | grep Birth

   # What process created it?
   sudo ausearch -f /tmp/exploit 2>/dev/null
   ```

**What to look for:**
- SUID bit set: `-rwsr-xr-x` (notice the 's')
- Not managed by package manager
- Located in unusual directory (/tmp, /dev/shm, /var/tmp)
- Created recently
- Suspicious strings (shell commands, /bin/sh, exec)

**Legitimate SUID binaries:**
```bash
# Known good locations
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/bin/ping

# All should be package-managed
dpkg -S /usr/bin/sudo  # Should show: sudo: /usr/bin/sudo
```

**Remediation:**
```bash
# If suspicious, remove SUID bit first
sudo chmod u-s /tmp/exploit

# Then investigate or remove
sudo rm /tmp/exploit
```

---

### 🟠 SSH Brute Force Attack

**Finding:**
```
🟠 HIGH SSH Brute Force Attack Detected
  248 failed login attempts in last 24h
  💡 Remediation: Check /var/log/auth.log, consider fail2ban
```

**Verification Steps:**

1. **Check auth logs:**
   ```bash
   sudo grep "Failed password" /var/log/auth.log | tail -20
   ```

2. **Count failed attempts:**
   ```bash
   sudo grep "Failed password" /var/log/auth.log | wc -l
   ```

3. **Identify source IPs:**
   ```bash
   sudo grep "Failed password" /var/log/auth.log | \
     awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10
   ```

4. **Check for successful logins:**
   ```bash
   sudo grep "Accepted password" /var/log/auth.log | tail -10
   ```

5. **Check current connections:**
   ```bash
   who
   w
   last | head -20
   ```

**What to look for:**
- Many failed attempts from same IP
- Attempts with common usernames (admin, test, user)
- Geographic anomalies (IPs from unexpected countries)
- Successful logins after many failures

**Remediation:**

1. **Block attacking IPs (temporary):**
   ```bash
   sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
   ```

2. **Install fail2ban:**
   ```bash
   sudo apt install fail2ban
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```

3. **Harden SSH config (`/etc/ssh/sshd_config`):**
   ```bash
   # Disable password auth (use keys only)
   PasswordAuthentication no

   # Disable root login
   PermitRootLogin no

   # Change SSH port (security through obscurity, but helps)
   Port 2222

   # Limit users
   AllowUsers your_username

   # Enable key-only auth
   PubkeyAuthentication yes
   ```

4. **Restart SSH:**
   ```bash
   sudo systemctl restart sshd
   ```

---

### 🟠 Reverse Shell Detected

**Finding:**
```
🟠 HIGH Reverse Shell Detected
  Process '/bin/bash' (PID 12345) has ESTABLISHED connection to 192.168.1.100:4444
  Raw shell with network connection and short command line
  💡 Remediation: Investigate immediately: ps aux | grep 12345 && lsof -p 12345
```

**Verification Steps:**

1. **Check the process:**
   ```bash
   ps aux | grep 12345
   ps -fp 12345
   ```

2. **Check command line:**
   ```bash
   cat /proc/12345/cmdline | tr '\0' ' '
   ```

3. **Check connections:**
   ```bash
   sudo lsof -p 12345 | grep TCP
   sudo netstat -tanp | grep 12345
   ```

4. **Check parent process:**
   ```bash
   ps -o ppid= -p 12345
   ps -fp $(ps -o ppid= -p 12345)
   ```

5. **Check file descriptors:**
   ```bash
   ls -la /proc/12345/fd/
   # Reverse shells often have stdin/stdout/stderr redirected to socket
   ```

**What to look for:**
- Shell process (bash, sh, zsh) with network connection
- Connection to uncommon port (4444, 5555, 1337)
- Parent process is unusual (not sshd, not your terminal)
- File descriptors 0, 1, 2 point to socket

**Legitimate shells with connections:**
- SSH sessions (parent: sshd)
- Terminal emulators
- IDE integrated terminals
- Screen/tmux sessions

**False positives:**
```bash
# Check if it's your SSH session
ps -fp $(ps -o ppid= -p 12345)
# Should show sshd

# Check if it's a container
ps -fp 12345 | grep -i docker
```

**Remediation:**
```bash
# 1. Terminate the shell immediately
sudo kill -9 12345

# 2. Block the remote IP
sudo iptables -A OUTPUT -d <REMOTE_IP> -j DROP

# 3. Find how it started
sudo grep -r "bash.*<REMOTE_IP>" /etc/cron*
sudo systemctl list-unit-files | grep -i suspicious

# 4. Check for backdoors
sudo find /tmp /dev/shm /var/tmp -type f -executable
sudo grep -r "<REMOTE_IP>" /home /root

# 5. Check authorized_keys
find /home -name "authorized_keys" -exec grep . {} +
```

**Post-Incident:**
- Rotate all credentials
- Review all SSH keys
- Check for unauthorized users: `cat /etc/passwd`
- Full malware scan
- Consider system reinstall

---

## Medium Severity Findings

### 🟡 Firewall Not Enabled

**Verification:**
```bash
sudo ufw status
sudo iptables -L -n
```

**Remediation:**
```bash
# Enable UFW
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
```

---

### 🟡 Disk Not Encrypted

**Verification:**
```bash
lsblk -f
sudo cryptsetup status /dev/sda1
```

**Note:** This is informational. Encrypting a live system requires reinstallation.

---

## False Positive Identification

### SUID Binaries

**Common false positives:**

1. **Symlinked binaries:**
   ```bash
   # /usr/sbin/mount.ntfs might be a symlink to /bin/ntfs-3g
   ls -la /usr/sbin/mount.ntfs
   readlink -f /usr/sbin/mount.ntfs
   dpkg -S $(readlink -f /usr/sbin/mount.ntfs)
   ```

2. **Alternative installations:**
   ```bash
   # Check if installed via snap, flatpak, or appimage
   snap list
   flatpak list
   ```

3. **Custom compiled software:**
   ```bash
   # If you compiled it yourself, verify the source
   ls -la /usr/local/bin/custom-binary
   ```

### CVE Detections

**False positives due to backports:**

Many distros backport security fixes without changing version numbers.

**Verification:**
```bash
# Ubuntu/Debian
apt-cache policy <package>
apt changelog <package> | grep CVE

# Example for sudo CVE-2025-32462
apt changelog sudo | grep CVE-2025-32462
# If found, it's been patched despite version number
```

**Distro security trackers:**
- Ubuntu: https://ubuntu.com/security/CVEs
- Debian: https://security-tracker.debian.org/tracker/
- RHEL: https://access.redhat.com/security/security-updates/

### Reverse Shell Detections

**Legitimate processes that may trigger:**

1. **Electron apps (Discord, VS Code, Slack):**
   ```bash
   ps aux | grep 12345
   # Check for: --type=utility, --enable-crash-reporter, /usr/share/discord
   ```

2. **Browser processes:**
   ```bash
   ps aux | grep 12345
   # Check for: chrome, firefox, --type=renderer
   ```

3. **Development tools:**
   ```bash
   # node, python, ruby scripts with network connections
   # Check parent process and command line
   ```

---

## Remediation Steps

### General Incident Response

1. **Isolate the system:**
   ```bash
   # Disconnect from network (if severe)
   sudo ip link set eth0 down
   ```

2. **Preserve evidence:**
   ```bash
   # Save logs
   sudo tar czf /tmp/incident-logs.tar.gz /var/log/

   # Save process list
   ps auxf > /tmp/process-list.txt

   # Save network connections
   sudo netstat -tanp > /tmp/network-connections.txt
   ```

3. **Remove threats:**
   ```bash
   # Kill processes
   sudo kill -9 <PID>

   # Remove files
   sudo rm /path/to/malware

   # Block IPs
   sudo iptables -A INPUT -s <IP> -j DROP
   ```

4. **Fix vulnerabilities:**
   ```bash
   # Update all packages
   sudo apt update && sudo apt upgrade -y

   # Remove unnecessary SUID bits
   sudo chmod u-s /path/to/binary
   ```

5. **Secure the system:**
   ```bash
   # Rotate credentials
   passwd

   # Review SSH keys
   cat ~/.ssh/authorized_keys

   # Enable firewall
   sudo ufw enable

   # Install fail2ban
   sudo apt install fail2ban
   ```

6. **Monitor:**
   ```bash
   # Check for reinfection
   linux-guardian --threats-only

   # Monitor logs
   sudo tail -f /var/log/auth.log
   ```

---

## Verification Tools

### System Information

```bash
# OS version
cat /etc/os-release

# Kernel version
uname -a

# Installed packages
dpkg -l
rpm -qa

# Running processes
ps auxf

# Network connections
sudo netstat -tanp
sudo ss -tunap

# Open files
sudo lsof

# System logs
sudo journalctl -xe
```

### Security Tools

```bash
# Install additional tools
sudo apt install \
  rkhunter \        # Rootkit hunter
  chkrootkit \      # Rootkit checker
  lynis \           # Security auditing
  aide \            # File integrity checker
  clamav \          # Antivirus
  auditd            # Audit daemon

# Run scans
sudo rkhunter --check
sudo chkrootkit
sudo lynis audit system
```

### File Integrity

```bash
# Check package integrity
sudo debsums -c      # Debian/Ubuntu
sudo rpm -Va         # RHEL/CentOS

# Install AIDE (Advanced Intrusion Detection Environment)
sudo apt install aide
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo aide --check
```

### Network Monitoring

```bash
# Real-time connection monitoring
sudo nethogs        # Traffic per process
sudo iftop          # Network usage
sudo tcpdump -i any # Packet capture

# Check listening ports
sudo ss -tlnp
sudo netstat -tlnp
```

---

## When to Reinstall

Consider full system reinstallation if:

1. ✅ **Rootkit detected** - Kernel-level compromise
2. ✅ **Multiple malware families** - Severe infection
3. ✅ **Backdoored system binaries** - /bin/bash, /bin/ls modified
4. ✅ **Unknown infection vector** - Don't know how they got in
5. ✅ **Persistent reinfection** - Malware returns after cleaning
6. ✅ **Production system** - Can't trust critical infrastructure

**Reinstallation steps:**
1. Backup important data (scan backups for malware!)
2. Note down configurations
3. Wipe all disks
4. Fresh OS installation
5. Apply all updates before connecting to network
6. Restore data (verify it's clean)
7. Harden the system (firewall, fail2ban, SSH keys)

---

## Additional Resources

- [CISA Cybersecurity Resources](https://www.cisa.gov/cybersecurity)
- [Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Incident Response Best Practices](https://www.sans.org/reading-room/whitepapers/incident)
- [CVE Database Documentation](CVE_DATABASE.md)

---

## Getting Help

If you need help interpreting findings:

1. **Check documentation:** [README.md](../README.md)
2. **Open an issue:** [GitHub Issues](https://github.com/brammittendorff/linux-guardian/issues)
3. **Provide context:**
   - Full scanner output
   - System details (`cat /etc/os-release`)
   - Steps you've taken
   - Specific question

**DO NOT share:**
- Credentials or API keys
- Private network details
- Sensitive file contents

---

**Stay safe and verify everything before taking action!** 🛡️
