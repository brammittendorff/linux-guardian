# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Linux Guardian, please report it responsibly.

### How to Report

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by:

1. **Email**: Send details to the repository owner (check GitHub profile)
2. **GitHub Security Advisory**: Use the "Security" tab on GitHub to create a private security advisory

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What can an attacker do?
- **Reproduction**: Step-by-step instructions to reproduce
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have ideas for a fix

### Example Report

```
Subject: [SECURITY] Privilege Escalation in X Module

Description:
The X module in linux-guardian allows local privilege escalation
through Y mechanism.

Impact:
A local user can gain root privileges by ...

Steps to Reproduce:
1. Run linux-guardian as non-root user
2. Execute command X
3. Observe Y

Affected Versions:
0.1.0 - 0.1.5

Suggested Fix:
Add input validation in module X at line Y
```

## Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 5 business days
- **Fix Development**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Next release

## Disclosure Policy

We follow **responsible disclosure**:

1. You report the vulnerability privately
2. We confirm and investigate
3. We develop and test a fix
4. We release the fix
5. We publicly disclose the vulnerability (with credit to reporter)

### Disclosure Timeline

- **Critical Vulnerabilities**: 30 days after fix release
- **Other Vulnerabilities**: 90 days after fix release

## Security Considerations for Users

### Running Linux Guardian Safely

Linux Guardian is designed for **defensive security** purposes only.

**Best Practices:**

1. **Run with Appropriate Permissions**
   ```bash
   # Most checks require root
   sudo linux-guardian

   # Some checks work without root
   linux-guardian --skip-privilege-check
   ```

2. **Review Findings Before Acting**
   - Not all findings are guaranteed true positives
   - Investigate before making system changes
   - Use `--verbose` to see more details

3. **Keep Updated**
   ```bash
   # Check for updates regularly
   git pull origin main
   cargo build --release
   ```

4. **Verify Source**
   - Only download from official GitHub repository
   - Verify commit signatures when possible
   - Build from source for maximum security

5. **Secure Your CVE Database**
   - Database cached in `~/.cache/linux-guardian/`
   - Ensure cache directory has appropriate permissions
   - Database refreshes automatically

### What Linux Guardian Does NOT Do

Linux Guardian is **read-only** and **defensive**:

- Does NOT modify system files
- Does NOT send data externally
- Does NOT create backdoors
- Does NOT perform offensive operations
- Does NOT require network access (except CVE DB updates)

### Known Limitations

1. **False Positives**: Possible with generic checks
   - Use `--verbose` to investigate
   - See `docs/VERIFICATION_GUIDE.md`

2. **Privilege Requirements**: Many checks require root
   - Running as non-root limits detection capability
   - Use `--skip-privilege-check` if needed

3. **Platform Specific**: Designed for Linux only
   - Tested on Debian/Ubuntu primarily
   - May work on RHEL/CentOS/Fedora
   - Not tested on all distributions

## Security Features

### Built-in Security

1. **No Remote Code Execution**
   - All code runs locally
   - No dynamic code loading
   - No external dependencies at runtime

2. **Minimal Attack Surface**
   - Pure Rust implementation
   - Memory safety guaranteed
   - No unsafe code (except in dependencies)

3. **Sandboxing Friendly**
   - Can run in containers
   - Works with AppArmor/SELinux
   - No special kernel modules required

4. **Privacy Preserving**
   - No telemetry
   - No data collection
   - All processing local

### CVE Database Security

The CVE database integration:

- Uses HTTPS for downloads
- Validates JSON schemas
- Caches locally (no repeated downloads)
- Uses official NIST/CISA sources only

## Threat Model

### What We Protect Against

Linux Guardian helps detect:

- ✅ Privilege escalation vulnerabilities
- ✅ Cryptominers and malware
- ✅ Rootkits and backdoors
- ✅ SSH attacks and unauthorized access
- ✅ Known CVEs in installed packages
- ✅ Misconfigurations

### What We Don't Protect Against

- ❌ Zero-day exploits (until CVE published)
- ❌ Hardware vulnerabilities
- ❌ Physical access attacks
- ❌ Social engineering
- ❌ Network-level attacks
- ❌ Application-level exploits (outside scope)

## Security Updates

### How We Handle Security Issues

1. **Immediate Action**: Critical vulnerabilities are addressed immediately
2. **Patch Release**: Security fixes released as patch versions (0.1.x)
3. **Security Advisory**: Published on GitHub Security tab
4. **CHANGELOG**: All security fixes documented

### Verifying Releases

Future releases may include:

- GPG signed tags
- Checksums for binaries
- Reproducible builds

## Audit History

| Date | Auditor | Type | Result |
|------|---------|------|--------|
| TBD  | TBD     | TBD  | TBD    |

*No formal audits conducted yet. Contributions welcome!*

## Security Checklist for Contributors

Before submitting code:

- [ ] No hardcoded credentials or secrets
- [ ] Input validation on all external data
- [ ] No SQL injection risks (using parameterized queries)
- [ ] No command injection (using safe APIs)
- [ ] Error messages don't leak sensitive info
- [ ] Dependencies are up to date
- [ ] No known vulnerable dependencies
- [ ] Tests include security edge cases

## Dependencies Security

We monitor dependencies for known vulnerabilities:

```bash
# Check for vulnerable dependencies
cargo audit

# Update dependencies
cargo update
```

### Dependency Policy

- Regular dependency updates
- Security patches applied promptly
- Minimal dependency footprint
- Prefer well-maintained crates

## Resources

- **NIST NVD**: https://nvd.nist.gov/
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Rust Security**: https://rustsec.org/
- **OWASP**: https://owasp.org/

## Credits

We appreciate responsible disclosure from security researchers. Contributors will be acknowledged in:

- Security advisories
- CHANGELOG.md
- README.md (if desired)

---

**Thank you for helping keep Linux Guardian secure!**
