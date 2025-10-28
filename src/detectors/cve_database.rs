use crate::models::Finding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

/// CISA Known Exploited Vulnerabilities Catalog URL
const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Local cache directory for CVE database
const CACHE_DIR: &str = "/var/cache/linux-guardian";
const KEV_CACHE_FILE: &str = "cisa_kev.json";

/// CISA KEV Database Structure
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CisaKevDatabase {
    title: String,
    catalog_version: String,
    date_released: String,
    count: usize,
    vulnerabilities: Vec<CisaVulnerability>,
}

/// Individual CVE entry from CISA KEV
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CisaVulnerability {
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
    required_action: String,
    due_date: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    cwes: Vec<String>,
}

/// Installed package information
#[derive(Debug, Clone)]
struct InstalledPackage {
    name: String,
    version: String,
    source: String, // dpkg, rpm, binary
}

/// Check for known exploited vulnerabilities from CISA KEV
pub async fn check_known_exploited_vulnerabilities() -> Result<Vec<Finding>> {
    info!("🔍 Checking CISA Known Exploited Vulnerabilities catalog...");
    let mut findings = Vec::new();

    // Get KEV database (download or use cache)
    let kev_db = match get_kev_database().await {
        Ok(db) => db,
        Err(e) => {
            warn!("Failed to load KEV database: {}. Skipping CVE checks.", e);
            return Ok(findings);
        }
    };

    info!("  Loaded {} known exploited vulnerabilities", kev_db.count);

    // Get installed packages
    let packages = get_installed_packages();
    debug!("Found {} installed packages", packages.len());

    // Match packages against CVEs
    for cve in &kev_db.vulnerabilities {
        for package in &packages {
            if package_matches_cve(package, cve) {
                findings.push(create_cve_finding(cve, package));
            }
        }
    }

    // Also check kernel version
    if let Ok(kernel_findings) = check_kernel_cves(&kev_db).await {
        findings.extend(kernel_findings);
    }

    info!("  Found {} CVE matches", findings.len());
    Ok(findings)
}

/// Get KEV database (download if needed, use cache if recent)
async fn get_kev_database() -> Result<CisaKevDatabase> {
    let cache_path = get_cache_path();

    // Check if cache exists and is recent (< 24 hours old)
    if let Ok(metadata) = fs::metadata(&cache_path) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();

            if age.as_secs() < 24 * 3600 {
                debug!(
                    "Using cached KEV database (age: {} hours)",
                    age.as_secs() / 3600
                );
                return load_kev_from_cache(&cache_path);
            }
        }
    }

    // Download fresh KEV database
    debug!("Downloading fresh KEV database from CISA...");
    download_kev_database().await
}

/// Download KEV database from CISA
async fn download_kev_database() -> Result<CisaKevDatabase> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(CISA_KEV_URL).send().await?;
    let kev_db: CisaKevDatabase = response.json().await?;

    // Save to cache
    if let Err(e) = save_kev_to_cache(&kev_db) {
        warn!("Failed to cache KEV database: {}", e);
    }

    Ok(kev_db)
}

/// Load KEV database from cache
fn load_kev_from_cache(path: &PathBuf) -> Result<CisaKevDatabase> {
    let contents = fs::read_to_string(path)?;
    let kev_db: CisaKevDatabase = serde_json::from_str(&contents)?;
    Ok(kev_db)
}

/// Save KEV database to cache
fn save_kev_to_cache(kev_db: &CisaKevDatabase) -> Result<()> {
    // Create cache directory if it doesn't exist
    let cache_dir = PathBuf::from(CACHE_DIR);
    if !cache_dir.exists() {
        // Try to create, but don't fail if we can't (no root)
        let _ = fs::create_dir_all(&cache_dir);
    }

    let cache_path = get_cache_path();
    let json = serde_json::to_string_pretty(kev_db)?;
    fs::write(cache_path, json)?;

    Ok(())
}

/// Get cache file path
fn get_cache_path() -> PathBuf {
    let mut path = PathBuf::from(CACHE_DIR);
    path.push(KEV_CACHE_FILE);
    path
}

/// Get installed packages from the system
fn get_installed_packages() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    // Try dpkg (Debian/Ubuntu)
    if let Ok(dpkg_packages) = get_dpkg_packages() {
        packages.extend(dpkg_packages);
    }

    // Try rpm (RHEL/CentOS/Fedora)
    if let Ok(rpm_packages) = get_rpm_packages() {
        packages.extend(rpm_packages);
    }

    // Check common binaries directly
    packages.extend(get_binary_versions());

    packages
}

/// Get packages from dpkg (Debian/Ubuntu)
fn get_dpkg_packages() -> Result<Vec<InstalledPackage>> {
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Package}\t${Version}\n"])
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<InstalledPackage> = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 2 {
                Some(InstalledPackage {
                    name: normalize_package_name(parts[0]),
                    version: parse_version(parts[1]),
                    source: "dpkg".to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    Ok(packages)
}

/// Get packages from rpm (RHEL/CentOS/Fedora)
fn get_rpm_packages() -> Result<Vec<InstalledPackage>> {
    let output = Command::new("rpm")
        .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"])
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<InstalledPackage> = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 2 {
                Some(InstalledPackage {
                    name: normalize_package_name(parts[0]),
                    version: parts[1].to_string(),
                    source: "rpm".to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    Ok(packages)
}

/// Get versions of common binaries directly
fn get_binary_versions() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    // Check sudo
    if let Ok(output) = Command::new("sudo").arg("--version").output() {
        if let Some(version) = extract_sudo_version(&output.stdout) {
            packages.push(InstalledPackage {
                name: "sudo".to_string(),
                version,
                source: "binary".to_string(),
            });
        }
    }

    // Check OpenSSH
    if let Ok(output) = Command::new("ssh").arg("-V").output() {
        // SSH outputs to stderr
        if let Some(version) = extract_openssh_version(&output.stderr) {
            packages.push(InstalledPackage {
                name: "openssh".to_string(),
                version,
                source: "binary".to_string(),
            });
        }
    }

    packages
}

/// Extract sudo version from output
fn extract_sudo_version(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    let re = regex::Regex::new(r"Sudo version (\d+\.\d+\.\d+)").ok()?;
    re.captures(&text)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract OpenSSH version from output
fn extract_openssh_version(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    let re = regex::Regex::new(r"OpenSSH_(\d+\.\d+)").ok()?;
    re.captures(&text)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

/// Normalize package name (remove lib prefix, etc.)
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase()
        .replace("-dev", "")
        .replace("-common", "")
        .replace("lib", "")
}

/// Parse version string (remove debian/ubuntu suffixes)
fn parse_version(version: &str) -> String {
    // Remove debian suffixes like "-1ubuntu1"
    version
        .split('-')
        .next()
        .unwrap_or(version)
        .split('+')
        .next()
        .unwrap_or(version)
        .to_string()
}

/// Check if a package matches a CVE
fn package_matches_cve(package: &InstalledPackage, cve: &CisaVulnerability) -> bool {
    let cve_product = cve.product.to_lowercase();
    let pkg_name = package.name.to_lowercase();

    // Check if product name matches (fuzzy matching)
    if !pkg_name.contains(&cve_product) && !cve_product.contains(&pkg_name) {
        // Also try without spaces
        let cve_product_nospace = cve_product.replace(" ", "");
        if !pkg_name.contains(&cve_product_nospace) && !cve_product_nospace.contains(&pkg_name) {
            return false;
        }
    }

    // TODO: Version range checking
    // For now, we flag any version as it's in the KEV (actively exploited)
    // A full implementation would parse version ranges from NVD

    true
}

/// Check kernel version against CVEs
async fn check_kernel_cves(kev_db: &CisaKevDatabase) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let kernel_version = fs::read_to_string("/proc/version")?;
    debug!("Kernel version: {}", kernel_version);

    // Check for kernel-related CVEs in KEV
    for cve in &kev_db.vulnerabilities {
        let product_lower = cve.product.to_lowercase();
        if product_lower.contains("linux") && product_lower.contains("kernel") {
            findings.push(
                Finding::high(
                    "cve_database",
                    &format!("{} - Linux Kernel Vulnerability", cve.cve_id),
                    &format!(
                        "{}: {}. This vulnerability is actively exploited in the wild.",
                        cve.vulnerability_name, cve.short_description
                    ),
                )
                .with_cve(&cve.cve_id)
                .with_remediation(&format!(
                    "Required action: {}. Due date: {}",
                    cve.required_action, cve.due_date
                )),
            );
        }
    }

    Ok(findings)
}

/// Create a finding from a CVE match
fn create_cve_finding(cve: &CisaVulnerability, package: &InstalledPackage) -> Finding {
    let severity = if cve.known_ransomware_campaign_use.to_lowercase() == "known" {
        "critical"
    } else {
        "high"
    };

    let finding = Finding {
        severity: severity.to_string(),
        category: "cve_database".to_string(),
        title: format!(
            "{} - {} Vulnerability (Actively Exploited)",
            cve.cve_id, cve.product
        ),
        description: format!(
            "{} version {} is affected by {}: {}. \
             This vulnerability is in CISA's Known Exploited Vulnerabilities catalog, \
             meaning it is actively being exploited in the wild. \
             Date added to KEV: {}",
            package.name,
            package.version,
            cve.vulnerability_name,
            cve.short_description,
            cve.date_added
        ),
        remediation: Some(format!(
            "URGENT: {}. Due date: {}. Update {} immediately.",
            cve.required_action, cve.due_date, package.name
        )),
        cve: Some(cve.cve_id.clone()),
        details: Some(serde_json::json!({
            "vendor_project": cve.vendor_project,
            "product": cve.product,
            "installed_version": package.version,
            "source": package.source,
            "date_added_to_kev": cve.date_added,
            "due_date": cve.due_date,
            "ransomware_use": cve.known_ransomware_campaign_use,
            "notes": cve.notes,
        })),
    };

    finding
}

/// Get KEV statistics
pub async fn get_kev_statistics() -> Result<String> {
    let kev_db = get_kev_database().await?;

    Ok(format!(
        "CISA KEV Catalog v{}: {} known exploited vulnerabilities (released: {})",
        kev_db.catalog_version, kev_db.count, kev_db.date_released
    ))
}
