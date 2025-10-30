# CVE Database Documentation

## Overview

Linux Guardian uses a local SQLite database to efficiently match installed packages against known vulnerabilities. The database combines two authoritative sources:

1. **CISA KEV (Known Exploited Vulnerabilities)** - ~1,450 CVEs actively exploited in the wild
2. **NVD (National Vulnerability Database)** - Critical CVEs with CVSS ≥ 7.0

This approach provides:
- ⚡ **Fast scanning** - Local database queries in milliseconds
- 🎯 **High accuracy** - Version-specific matching, not just package names
- 🔒 **Privacy** - No data sent to external servers
- 📴 **Offline capability** - Works without internet after initial download

## Quick Start

### First-Time Setup

```bash
# Download and build the CVE database (requires internet, ~2-5 minutes)
linux-guardian --update-cve-db
```

This creates a local database at `~/.cache/linux-guardian/cve.db` (or `/var/cache/linux-guardian/cve.db` with root).

### Regular Scans

```bash
# Normal scan (automatically uses CVE database if available)
linux-guardian

# Skip CVE checks (faster)
linux-guardian --no-cve-db
```

### Updating the Database

```bash
# Update weekly to catch new vulnerabilities
linux-guardian --update-cve-db

# Check database statistics
linux-guardian --cve-db-stats
```

## How It Works

### 1. Package Collection

Linux Guardian collects installed package information from multiple sources:

**Package Managers:**
- `dpkg` (Debian/Ubuntu) - via `dpkg-query -W`
- `rpm` (RHEL/Fedora/CentOS) - via `rpm -qa`
- `pacman` (Arch Linux) - planned

**Binary Version Detection:**
- Sudo - `sudo --version`
- Kernel - `/proc/version`
- OpenSSH - `ssh -V`
- systemd - `systemctl --version`
- glibc - `ldd --version`
- polkit - `pkexec --version`
- XZ Utils - `xz --version`

**Why both?** Package managers might have outdated metadata, while direct binary checks ensure accuracy for critical components.

### 2. Version Parsing

Versions are normalized to remove distro-specific suffixes:

```
Input:  1.9.15p2-1ubuntu1.2
Output: 1.9.15

Input:  5.15.0-97-generic
Output: 5.15.0

Input:  2.39-0ubuntu8.3
Output: 2.39
```

### 3. CVE Matching

The database stores:
- **CVE ID** (e.g., CVE-2025-32462)
- **Product name** (normalized: "sudo", "linux kernel", "openssh")
- **Vendor** (canonical, debian, redhat, etc.)
- **CVSS score** (severity rating 0-10)
- **Description** (what the vulnerability does)
- **CPE criteria** (version ranges affected)
- **Exploitation status** (actively exploited? ransomware campaigns?)

**Matching algorithm:**
1. Normalize package name (remove `-dev`, `-common`, `lib` prefixes)
2. Fuzzy match against CVE product names
3. Check version against CPE ranges (if available)
4. Flag if vulnerable version detected

### 4. Result Prioritization

CVEs are prioritized by:
1. **CISA KEV entries** → Critical (actively exploited)
2. **Ransomware campaigns** → Critical
3. **CVSS 9.0+** → Critical
4. **CVSS 7.0-8.9** → High

## Database Schema

### Tables

**`cves`** - Main vulnerability table
```sql
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    vendor TEXT,
    description TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    published_date TEXT,
    last_modified TEXT,
    actively_exploited INTEGER,  -- 1 if in CISA KEV
    ransomware_use INTEGER,      -- 1 if used in ransomware
    source TEXT,                 -- "CISA_KEV" or "NVD"
    created_at TEXT
);
```

**`cpe_matches`** - Version range criteria
```sql
CREATE TABLE cpe_matches (
    id INTEGER PRIMARY KEY,
    cve_id TEXT,
    cpe_criteria TEXT,           -- e.g., "cpe:2.3:a:sudo_project:sudo:*:*"
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    vulnerable INTEGER,
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);
```

**`cve_references`** - Advisory URLs
```sql
CREATE TABLE cve_references (
    id INTEGER PRIMARY KEY,
    cve_id TEXT,
    url TEXT,
    source TEXT,
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);
```

**`metadata`** - Database info
```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
```

### Indexes

Performance is critical for fast scanning:
- `idx_cves_product` - Fast product name lookups
- `idx_cves_cvss` - Sort by severity
- `idx_cves_exploited` - Filter actively exploited
- `idx_cpe_cve` - Join CVEs with version ranges

## Data Sources

### CISA KEV Catalog

**Source:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Content:** ~1,450 CVEs that are:
- Actively exploited in the wild
- Used in ransomware campaigns
- Prioritized by US government for patching

**Format:** JSON feed, updated daily

**Example entry:**
```json
{
  "cveID": "CVE-2025-32462",
  "vendorProject": "Sudo Project",
  "product": "Sudo",
  "vulnerabilityName": "Sudo Policy-Check Bypass",
  "dateAdded": "2025-01-20",
  "shortDescription": "Sudo contains a policy-check bypass allowing privilege escalation",
  "requiredAction": "Apply updates per vendor instructions",
  "dueDate": "2025-02-10",
  "knownRansomwareCampaignUse": "Known"
}
```

**Why CISA KEV?**
- High signal-to-noise ratio
- Only includes vulnerabilities actively exploited
- Government-vetted threat intelligence
- Free, no API key required

### NVD (National Vulnerability Database)

**Source:** https://services.nvd.nist.gov/rest/json/cves/2.0

**Content:** Critical vulnerabilities (CVSS ≥ 7.0)

**Format:** JSON API with pagination

**Rate Limiting:**
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds
- Linux Guardian implements smart rate limiting and caching

**Example entry:**
```json
{
  "cve": {
    "id": "CVE-2024-12345",
    "descriptions": [
      {
        "lang": "en",
        "value": "Buffer overflow in component X allows remote code execution"
      }
    ],
    "metrics": {
      "cvssMetricV31": [
        {
          "cvssData": {
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL"
          }
        }
      ]
    },
    "configurations": [
      {
        "nodes": [
          {
            "cpeMatch": [
              {
                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.0",
                "versionEndExcluding": "2.5",
                "vulnerable": true
              }
            ]
          }
        ]
      }
    ]
  }
}
```

**Why NVD?**
- Comprehensive vulnerability database
- Structured CPE version matching
- CVSS scoring for prioritization
- Version range specifications

## Database Updates

### Update Process

```bash
linux-guardian --update-cve-db
```

**Steps:**
1. **Download CISA KEV** (~1MB, ~5 seconds)
   - Fetches JSON catalog
   - Processes 1,450+ entries
   - Inserts into database

2. **Download NVD CVEs** (~50MB, ~2-4 minutes)
   - Fetches critical CVEs (CVSS ≥ 7.0)
   - Smart rate limiting (respects API limits)
   - Processes ~50,000+ CVEs
   - Inserts with version ranges

3. **Update Metadata**
   - Stores last update timestamp
   - Records database version

### Update Frequency

**Recommended:** Weekly

**Why weekly?**
- New critical CVEs appear daily
- CISA KEV updated as threats emerge
- Balance between freshness and bandwidth

**Automation:**
```bash
# Weekly cron job
0 3 * * 0 /usr/local/bin/linux-guardian --update-cve-db >> /var/log/cve-update.log 2>&1
```

### Database Age Check

The scanner automatically checks database age:
- **< 7 days old**: Uses database
- **> 7 days old**: Warns to update, falls back to built-in knowledge base
- **Missing**: Warns to run `--update-cve-db`

### Manual Cache Management

```bash
# Clear database (forces fresh download on next update)
rm ~/.cache/linux-guardian/cve.db

# Or system-wide (with root)
sudo rm /var/cache/linux-guardian/cve.db
```

## Performance Optimization

### Package Caching

First scan builds a package list (~5-10 seconds):
```bash
# First run
linux-guardian  # Takes 15-20 seconds

# Subsequent runs
linux-guardian  # Takes 10-12 seconds (cached packages)
```

Cache location: `~/.cache/linux-guardian/packages.json`

Cache invalidated: When package manager databases are updated

### Database Queries

Optimized queries with indexes:
```sql
-- Fast product lookup
SELECT * FROM cves
WHERE product LIKE '%sudo%'
AND actively_exploited = 1
ORDER BY cvss_score DESC;

-- Version range check
SELECT c.*, m.*
FROM cves c
JOIN cpe_matches m ON c.cve_id = m.cve_id
WHERE c.product = 'sudo'
AND m.version_start_including <= '1.9.15'
AND (m.version_end_excluding > '1.9.15' OR m.version_end_excluding IS NULL);
```

Query time: < 10ms per package

### Parallel Processing

Package checks are parallelized using Rayon:
- CPU cores utilized: All available
- Speedup: ~4-8x on multi-core systems

## Troubleshooting

### Foreign Key Constraint Error

**Error:** `FOREIGN KEY constraint failed`

**Cause:** Old database schema without cascade deletes

**Fix:**
```bash
# Remove old database
rm ~/.cache/linux-guardian/cve.db
# Or with root
sudo rm /var/cache/linux-guardian/cve.db

# Update with new schema
linux-guardian --update-cve-db
```

### Rate Limiting Errors

**Error:** `NVD rate limit exceeded`

**Cause:** Too many requests to NVD API

**Fix:**
- Wait 30 seconds and retry
- Consider getting an NVD API key (free)
- Linux Guardian automatically retries with exponential backoff

### Database Corruption

**Error:** `database disk image is malformed`

**Fix:**
```bash
rm ~/.cache/linux-guardian/cve.db
linux-guardian --update-cve-db
```

### Missing Packages

**Issue:** CVE not detected for installed package

**Possible causes:**
1. Package name mismatch (distro vs. upstream naming)
2. Version parsing failed
3. CPE criteria not in database

**Debug:**
```bash
# Check detected packages
linux-guardian --debug 2>&1 | grep "Found.*packages"

# See package list
cat ~/.cache/linux-guardian/packages.json | jq
```

### Slow Updates

**Issue:** NVD download takes 10+ minutes

**Causes:**
- Slow internet connection
- API rate limiting
- Large number of CVEs

**Solutions:**
- Run during off-peak hours
- Get NVD API key for higher rate limits
- Be patient (it's downloading 50,000+ CVEs)

## Accuracy & False Positives

### Known Limitations

1. **Fuzzy Matching**
   - Product names may differ between distros
   - Example: "linux-kernel" vs. "kernel" vs. "linux"
   - May cause false positives or missed detections

2. **Version Complexity**
   - Distro-specific patches not accounted for
   - Backported security fixes not detected
   - Example: Ubuntu patches CVE in older version

3. **Package Naming**
   - Libraries may have different names
   - Example: "openssl" vs. "libssl" vs. "libssl3"

### Reducing False Positives

1. **Cross-reference findings**
   ```bash
   # Check if distro has patched it
   apt-cache policy <package>
   ```

2. **Verify CVE applicability**
   - Check vendor security advisories
   - Look for distro-specific patches

3. **Update regularly**
   - Newer database versions improve accuracy
   - Better product name mappings added

### Reporting Issues

Found a false positive or missed CVE?

1. Check if it's a known limitation
2. Verify with vendor security advisory
3. Open GitHub issue with:
   - Package name and version
   - CVE ID (if applicable)
   - Distro and version
   - Expected vs. actual behavior

## Security Considerations

### Database Integrity

The CVE database is downloaded from authoritative sources:
- CISA (US Government)
- NIST NVD (US Government)

**Risks:**
- MITM attacks (downloads over HTTPS)
- Compromised CISA/NVD infrastructure (unlikely)

**Mitigations:**
- HTTPS for all downloads
- Regular updates (catch tampering quickly)
- Open source (audit the code)

### Privacy

The CVE database is **100% local**:
- ✅ No package list sent to external servers
- ✅ No scan results uploaded
- ✅ No telemetry or tracking
- ✅ Works completely offline after download

### Permissions

Database locations:
- **User cache:** `~/.cache/linux-guardian/` (no special permissions)
- **System cache:** `/var/cache/linux-guardian/` (requires root to write)

Running as regular user:
- Can read existing database
- Can update to user cache
- Cannot write to system cache

## API Reference

### Command-Line Options

```bash
# Update CVE database
linux-guardian --update-cve-db

# Show database statistics
linux-guardian --cve-db-stats

# Skip CVE checks (faster scans)
linux-guardian --no-cve-db

# Use specific database path
linux-guardian --cve-db-path /path/to/cve.db
```

### Programmatic Usage

```rust
use linux_guardian::cve_db;

// Initialize database
let conn = cve_db::init_database()?;

// Check if update needed
if cve_db::needs_update(&conn)? {
    println!("Database is outdated");
}

// Get installed packages
let packages = vec![
    ("sudo".to_string(), "1.9.15".to_string()),
    ("openssh".to_string(), "8.2".to_string()),
];

// Check for CVEs
let findings = cve_db::check_installed_packages(&packages)?;
for finding in findings {
    println!("{}: {}", finding.title, finding.description);
}
```

## Further Reading

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [CPE Specification](https://nvd.nist.gov/products/cpe)
- [CVSS Scoring Guide](https://www.first.org/cvss/)
- [Verification Guide](VERIFICATION_GUIDE.md)
