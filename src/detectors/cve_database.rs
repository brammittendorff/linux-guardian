use crate::models::Finding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
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
    #[serde(alias = "cveID")]
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

// ---------------------------------------------------------------------------
// KEV entries that are relevant to Linux systems.  We match on (vendor, product)
// pairs — NOT on installed packages.  The KEV catalog has no version-range data,
// so we cannot determine whether the installed version is actually vulnerable.
//
// Instead we report which actively-exploited CVEs *could* affect Linux if the
// corresponding software is present, grouped into a single informational finding.
// The real package-to-CVE matching with version ranges lives in:
//   - cve_knowledge_base.rs   (hardcoded critical CVEs with exact version ranges)
//   - cve_database_sqlite.rs  (full NVD-backed local database)
//   - updates.rs              (distro security tracker: apt/dnf/yum)
// ---------------------------------------------------------------------------

/// (vendor substring, product substring) pairs for Linux-relevant KEV entries.
/// Both are matched case-insensitively.  Only entries where both match are
/// considered relevant.
const LINUX_KEV_FILTERS: &[(&str, &str)] = &[
    // Kernel
    ("linux", "kernel"),
    // Core userspace
    ("gnu", "bash"),
    ("gnu", "glibc"),
    ("sudo", "sudo"),
    ("openssh", "openssh"),
    ("openssl", "openssl"),
    // Web servers
    ("apache", "http server"),
    ("apache", "tomcat"),
    ("nginx", "nginx"),
    ("apache", "struts"),
    ("apache", "log4j"),
    // Languages / runtimes
    ("php", "php"),
    ("python", "python"),
    ("oracle", "java"),
    ("red hat", "jboss"),
    // Databases
    ("postgresql", "postgresql"),
    ("oracle", "mysql"),
    ("redis", "redis"),
    // Containers
    ("docker", "docker"),
    ("linux foundation", "runc"),
    // DNS / mail / network
    ("isc", "bind"),
    ("postfix", "postfix"),
    ("exim", "exim"),
    ("samba", "samba"),
    ("openvpn", "openvpn"),
    ("strongswan", "strongswan"),
    // Desktop
    ("mozilla", "firefox"),
    ("mozilla", "thunderbird"),
    ("google", "chromium"),
    // Other common Linux packages
    ("haproxy", "haproxy"),
    ("squid", "squid"),
    ("grafana", "grafana"),
    ("gitlab", "gitlab"),
    ("jenkins", "jenkins"),
    ("elastic", "elasticsearch"),
    ("elastic", "kibana"),
    ("saltstack", "salt"),
    ("puppet", "puppet"),
    ("ansible", "ansible"),
    ("nextcloud", "nextcloud"),
    ("roundcube", "roundcube"),
    ("xz", "xz"),
    ("tukaani", "xz"),
    ("imagemagick", "imagemagick"),
    ("cups", "cups"),
    ("systemd", "systemd"),
    ("polkit", "polkit"),
    ("freedesktop", "polkit"),
];

/// Check CISA KEV for Linux-relevant actively exploited vulnerabilities.
///
/// This detector does NOT match against installed packages — the KEV catalog
/// lacks version-range data, so matching would produce false positives.  Instead
/// it reports a summary of Linux-relevant KEV entries as context.  Actual
/// package-to-CVE matching is handled by cve_knowledge_base.rs and
/// cve_database_sqlite.rs which have proper version-range information.
pub async fn check_known_exploited_vulnerabilities() -> Result<Vec<Finding>> {
    info!("🔍 Checking CISA Known Exploited Vulnerabilities catalog...");

    let kev_db = match get_kev_database().await {
        Ok(db) => db,
        Err(e) => {
            warn!("Failed to load KEV database: {}. Skipping KEV check.", e);
            return Ok(Vec::new());
        }
    };

    info!("  Loaded {} known exploited vulnerabilities", kev_db.count);

    // Filter to Linux-relevant entries
    let linux_cves: Vec<&CisaVulnerability> = kev_db
        .vulnerabilities
        .iter()
        .filter(|cve| is_linux_relevant(cve))
        .collect();

    if linux_cves.is_empty() {
        info!("  No Linux-relevant KEV entries found");
        return Ok(Vec::new());
    }

    // Count by severity (ransomware use = critical context)
    let ransomware_count = linux_cves
        .iter()
        .filter(|c| c.known_ransomware_campaign_use.to_lowercase() == "known")
        .count();

    // Build a summary finding — not per-CVE, just awareness
    let sample_cves: Vec<String> = linux_cves
        .iter()
        .take(10)
        .map(|c| format!("{} ({})", c.cve_id, c.product))
        .collect();

    let finding = Finding::medium(
        "cisa_kev",
        &format!(
            "{} Linux-relevant CVEs in CISA KEV catalog",
            linux_cves.len()
        ),
        &format!(
            "The CISA Known Exploited Vulnerabilities catalog lists {} CVEs \
             affecting Linux-relevant software that are actively exploited in the wild. \
             {} are associated with known ransomware campaigns. \
             Ensure all system packages are up to date. \
             Sample entries: {}{}",
            linux_cves.len(),
            ransomware_count,
            sample_cves.join(", "),
            if linux_cves.len() > 10 { ", ..." } else { "" }
        ),
    )
    .with_remediation(
        "Run your distribution's security update command: \
         apt upgrade (Debian/Ubuntu), dnf update --security (Fedora/RHEL), \
         or check the detailed CVE findings from the knowledge base detector.",
    );

    info!(
        "  Found {} Linux-relevant KEV entries ({} ransomware-linked)",
        linux_cves.len(),
        ransomware_count
    );

    Ok(vec![finding])
}

/// Check if a KEV entry is relevant to Linux systems.
fn is_linux_relevant(cve: &CisaVulnerability) -> bool {
    let vendor = cve.vendor_project.to_lowercase();
    let product = cve.product.to_lowercase();

    LINUX_KEV_FILTERS
        .iter()
        .any(|(v, p)| vendor.contains(v) && product.contains(p))
}

// ---------------------------------------------------------------------------
// KEV database download / cache
// ---------------------------------------------------------------------------

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

    debug!("Downloading fresh KEV database from CISA...");
    download_kev_database().await
}

/// Download KEV database from CISA
async fn download_kev_database() -> Result<CisaKevDatabase> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let response = client.get(CISA_KEV_URL).send().await?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("CISA KEV download returned HTTP {}", status);
    }

    let body = response.text().await?;

    let kev_db: CisaKevDatabase = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse KEV JSON: {} (body starts with: {:?})",
            e,
            &body[..body.len().min(200)]
        )
    })?;

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
    let cache_dir = PathBuf::from(CACHE_DIR);
    if !cache_dir.exists() {
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

/// Get KEV statistics
pub async fn get_kev_statistics() -> Result<String> {
    let kev_db = get_kev_database().await?;

    let linux_count = kev_db
        .vulnerabilities
        .iter()
        .filter(|c| is_linux_relevant(c))
        .count();

    Ok(format!(
        "CISA KEV Catalog v{}: {} total ({} Linux-relevant) known exploited vulnerabilities (released: {})",
        kev_db.catalog_version, kev_db.count, linux_count, kev_db.date_released
    ))
}
