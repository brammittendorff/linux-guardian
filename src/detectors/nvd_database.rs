use crate::models::Finding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// NVD API v2.0 endpoint
const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Cache directory
const CACHE_DIR: &str = "/var/cache/linux-guardian";
#[allow(dead_code)]
const NVD_CACHE_FILE: &str = "nvd_cache.json";

/// NVD CVE Response Structure (API 2.0)
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    results_per_page: usize,
    start_index: usize,
    total_results: usize,
    format: String,
    version: String,
    timestamp: String,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct NvdVulnerability {
    cve: CveItem,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct CveItem {
    id: String,
    #[serde(rename = "sourceIdentifier")]
    source_identifier: Option<String>,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    #[serde(rename = "vulnStatus")]
    vuln_status: Option<String>,
    descriptions: Vec<Description>,
    metrics: Option<Metrics>,
    #[serde(default)]
    configurations: Vec<Configuration>,
    references: Option<Vec<Reference>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Metrics {
    cvss_metric_v31: Option<Vec<CvssMetric>>,
    cvss_metric_v3: Option<Vec<CvssMetric>>,
    cvss_metric_v2: Option<Vec<CvssMetric>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CvssMetric {
    source: String,
    cvss_data: CvssData,
    exploitability_score: Option<f32>,
    impact_score: Option<f32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    version: String,
    vector_string: String,
    base_score: f32,
    base_severity: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Configuration {
    nodes: Option<Vec<ConfigNode>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ConfigNode {
    operator: Option<String>,
    negate: Option<bool>,
    cpe_match: Option<Vec<CpeMatch>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    match_criteria_id: Option<String>,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Reference {
    url: String,
    source: Option<String>,
}

/// Simplified NVD cache structure for faster lookups
#[derive(Debug, Deserialize, Serialize, Clone)]
struct NvdCache {
    last_updated: String,
    cve_count: usize,
    critical_cves: Vec<CachedCve>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct CachedCve {
    cve_id: String,
    description: String,
    cvss_score: f32,
    severity: String,
    products: Vec<String>, // List of affected products
    version_ranges: Vec<VersionRange>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct VersionRange {
    product: String,
    start_including: Option<String>,
    start_excluding: Option<String>,
    end_including: Option<String>,
    end_excluding: Option<String>,
}

/// Check for NVD vulnerabilities (comprehensive but slower than KEV)
pub async fn check_nvd_vulnerabilities(product_filter: Option<&str>) -> Result<Vec<Finding>> {
    info!("🔍 Checking NVD database for vulnerabilities...");
    let mut findings = Vec::new();

    // Get packages
    let packages = get_system_packages();

    // For MVP, we'll check specific high-value products
    let target_products = product_filter.map_or_else(
        || vec!["linux", "sudo", "openssh", "apache", "nginx", "mysql"],
        |p| vec![p],
    );

    for product in target_products {
        match query_nvd_for_product(product).await {
            Ok(cves) => {
                debug!("Found {} CVEs for {}", cves.len(), product);
                // Match against installed packages
                for cve in cves {
                    if let Some(finding) = match_cve_to_packages(&cve, &packages) {
                        findings.push(finding);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to query NVD for {}: {}", product, e);
            }
        }
    }

    info!("  Found {} NVD vulnerability matches", findings.len());
    Ok(findings)
}

/// Query NVD API for specific product
async fn query_nvd_for_product(product: &str) -> Result<Vec<CachedCve>> {
    let cache_path = get_nvd_cache_path(product);

    // Check cache (7 days validity)
    if let Ok(cached) = load_nvd_cache(&cache_path) {
        debug!("Using cached NVD data for {}", product);
        return Ok(cached.critical_cves);
    }

    // Query NVD API
    debug!("Querying NVD API for {}", product);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("linux-guardian/0.1.0")
        .build()?;

    // NVD API v2.0 with keyword search
    let url = format!(
        "{}?keywordSearch={}&resultsPerPage=100",
        NVD_API_BASE, product
    );

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "NVD API returned status: {}",
            response.status()
        ));
    }

    let nvd_response: NvdResponse = response.json().await?;

    // Convert to cache format (only high/critical)
    let cached_cves: Vec<CachedCve> = nvd_response
        .vulnerabilities
        .into_iter()
        .filter_map(|vuln| convert_to_cached_cve(vuln.cve))
        .collect();

    // Save to cache
    let cache = NvdCache {
        last_updated: chrono::Utc::now().to_rfc3339(),
        cve_count: nvd_response.total_results,
        critical_cves: cached_cves.clone(),
    };

    let _ = save_nvd_cache(&cache_path, &cache);

    Ok(cached_cves)
}

/// Convert NVD CVE to cached format
fn convert_to_cached_cve(cve: CveItem) -> Option<CachedCve> {
    // Get CVSS score
    let cvss_score = extract_cvss_score(&cve.metrics)?;

    // Only cache high/critical (CVSS >= 7.0)
    if cvss_score < 7.0 {
        return None;
    }

    let severity = if cvss_score >= 9.0 {
        "CRITICAL"
    } else if cvss_score >= 7.0 {
        "HIGH"
    } else {
        "MEDIUM"
    };

    // Get description
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_else(|| "No description available".to_string());

    // Extract products from configurations
    let products = extract_products(&cve.configurations);
    let version_ranges = extract_version_ranges(&cve.configurations);

    Some(CachedCve {
        cve_id: cve.id,
        description,
        cvss_score,
        severity: severity.to_string(),
        products,
        version_ranges,
    })
}

/// Extract CVSS score from metrics
fn extract_cvss_score(metrics: &Option<Metrics>) -> Option<f32> {
    metrics.as_ref().and_then(|m| {
        m.cvss_metric_v31
            .as_ref()
            .or(m.cvss_metric_v3.as_ref())
            .or(m.cvss_metric_v2.as_ref())
            .and_then(|metrics| metrics.first())
            .map(|metric| metric.cvss_data.base_score)
    })
}

/// Extract product names from CVE configurations
fn extract_products(configurations: &[Configuration]) -> Vec<String> {
    let mut products = Vec::new();

    for config in configurations {
        if let Some(nodes) = &config.nodes {
            for node in nodes {
                if let Some(cpe_matches) = &node.cpe_match {
                    for cpe in cpe_matches {
                        if cpe.vulnerable {
                            // Parse CPE: cpe:2.3:a:vendor:product:version:...
                            if let Some(product) = parse_cpe_product(&cpe.criteria) {
                                products.push(product);
                            }
                        }
                    }
                }
            }
        }
    }

    products.sort();
    products.dedup();
    products
}

/// Extract version ranges from configurations
fn extract_version_ranges(configurations: &[Configuration]) -> Vec<VersionRange> {
    let mut ranges = Vec::new();

    for config in configurations {
        if let Some(nodes) = &config.nodes {
            for node in nodes {
                if let Some(cpe_matches) = &node.cpe_match {
                    for cpe in cpe_matches {
                        if cpe.vulnerable {
                            if let Some(product) = parse_cpe_product(&cpe.criteria) {
                                ranges.push(VersionRange {
                                    product: product.clone(),
                                    start_including: cpe.version_start_including.clone(),
                                    start_excluding: cpe.version_start_excluding.clone(),
                                    end_including: cpe.version_end_including.clone(),
                                    end_excluding: cpe.version_end_excluding.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    ranges
}

/// Parse product name from CPE string
/// CPE format: cpe:2.3:a:vendor:product:version:...
fn parse_cpe_product(cpe: &str) -> Option<String> {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 5 {
        Some(parts[4].to_string())
    } else {
        None
    }
}

/// Get system packages (simplified - reuse from cve_database)
fn get_system_packages() -> Vec<(String, String)> {
    // This would ideally reuse the package detection from cve_database
    // For now, return empty - full implementation would detect packages
    Vec::new()
}

/// Match CVE to installed packages
fn match_cve_to_packages(cve: &CachedCve, packages: &[(String, String)]) -> Option<Finding> {
    for (pkg_name, pkg_version) in packages {
        for product in &cve.products {
            if pkg_name.to_lowercase().contains(&product.to_lowercase()) {
                // TODO: Check version ranges
                return Some(create_nvd_finding(cve, pkg_name, pkg_version));
            }
        }
    }
    None
}

/// Create finding from NVD CVE
fn create_nvd_finding(cve: &CachedCve, package: &str, version: &str) -> Finding {
    let severity = match cve.severity.as_str() {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        _ => "medium",
    };

    Finding {
        severity: severity.to_string(),
        category: "nvd_vulnerability".to_string(),
        title: format!(
            "{} - {} Vulnerability (CVSS {:.1})",
            cve.cve_id, package, cve.cvss_score
        ),
        description: format!(
            "{} version {} is affected by {}. CVSS Score: {:.1} ({}).",
            package, version, cve.description, cve.cvss_score, cve.severity
        ),
        remediation: Some(format!(
            "Update {} to latest version. Check vendor advisories.",
            package
        )),
        cve: Some(cve.cve_id.clone()),
        details: Some(serde_json::json!({
            "cvss_score": cve.cvss_score,
            "severity": cve.severity,
            "products": cve.products,
        })),
    }
}

/// Get NVD cache path for product
fn get_nvd_cache_path(product: &str) -> PathBuf {
    let mut path = PathBuf::from(CACHE_DIR);
    path.push(format!("nvd_{}.json", product));
    path
}

/// Load NVD cache
fn load_nvd_cache(path: &PathBuf) -> Result<NvdCache> {
    // Check if cache is recent (7 days)
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();

            if age.as_secs() < 7 * 24 * 3600 {
                let contents = fs::read_to_string(path)?;
                let cache: NvdCache = serde_json::from_str(&contents)?;
                return Ok(cache);
            }
        }
    }

    Err(anyhow::anyhow!("Cache not found or expired"))
}

/// Save NVD cache
fn save_nvd_cache(path: &PathBuf, cache: &NvdCache) -> Result<()> {
    let cache_dir = PathBuf::from(CACHE_DIR);
    if !cache_dir.exists() {
        let _ = fs::create_dir_all(&cache_dir);
    }

    let json = serde_json::to_string_pretty(cache)?;
    fs::write(path, json)?;
    Ok(())
}

/// Get NVD statistics
pub async fn get_nvd_statistics() -> Result<String> {
    Ok("NVD Database: 314,000+ CVEs available via API".to_string())
}
