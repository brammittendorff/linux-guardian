/// Download and import CVE data from various sources
use super::schema;
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// CISA KEV URL (no API key needed!)
const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// NVD API 2.0 (no API key for basic use, rate limited)
const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// CISA KEV JSON Structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CisaKevCatalog {
    title: String,
    catalog_version: String,
    date_released: String,
    count: usize,
    vulnerabilities: Vec<CisaVulnerability>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CisaVulnerability {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: String,
    product: String,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "shortDescription")]
    short_description: String,
    #[serde(rename = "requiredAction")]
    required_action: String,
    #[serde(rename = "dueDate")]
    due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    known_ransomware_campaign_use: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    cwes: Vec<String>,
}

/// Download and import CISA KEV into database
pub async fn download_cisa_kev(conn: &Connection) -> Result<()> {
    info!("📥 Downloading CISA KEV catalog...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(CISA_KEV_URL).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "CISA KEV download failed: HTTP {}",
            response.status()
        ));
    }

    let text = response.text().await?;
    debug!("Downloaded {} bytes from CISA KEV", text.len());

    let catalog: CisaKevCatalog = match serde_json::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse CISA KEV JSON: {}", e);
            warn!(
                "First 500 chars: {}",
                &text.chars().take(500).collect::<String>()
            );
            return Err(anyhow::anyhow!("JSON parsing error: {}", e));
        }
    };

    info!("  Processing {} KEV entries...", catalog.count);

    // Clear old CISA data
    schema::clear_cves_by_source(conn, "CISA_KEV")?;

    // Insert all CVEs
    for vuln in &catalog.vulnerabilities {
        let ransomware = vuln.known_ransomware_campaign_use.to_lowercase() == "known";

        schema::upsert_cve(
            conn,
            &vuln.cve_id,
            &vuln.product.to_lowercase(),
            Some(&vuln.vendor_project),
            &vuln.short_description,
            8.0, // KEV doesn't provide CVSS, assume high
            "HIGH",
            &vuln.date_added,
            &vuln.date_added,
            true, // All KEV entries are actively exploited
            ransomware,
            "CISA_KEV",
        )?;
    }

    info!(
        "✅ Imported {} CVEs from CISA KEV",
        catalog.vulnerabilities.len()
    );
    Ok(())
}

/// NVD Response Structure (simplified)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: usize,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCveItem,
}

#[derive(Debug, Deserialize)]
struct NvdCveItem {
    id: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    cvss_metric_v3: Option<Vec<NvdCvssMetric>>,
    cvss_metric_v2: Option<Vec<NvdCvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssMetricV2 {
    cvss_data: NvdCvssDataV2,
    base_severity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssDataV2 {
    base_score: f32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssMetric {
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssData {
    base_score: f32,
    base_severity: String,
}

/// Download NVD critical CVEs (CVSS >= 7.0)
/// Smart rate limiting - polls test endpoint every second until ready
pub async fn download_nvd_critical(conn: &Connection) -> Result<()> {
    info!("📥 Downloading NVD critical CVEs (smart rate limiting)...");

    // For MVP, download recent critical CVEs for common Linux products
    let products = ["linux", "sudo", "openssh", "systemd", "glibc"];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("linux-guardian/0.1.0")
        .build()?;

    schema::clear_cves_by_source(conn, "NVD")?;

    let mut total_imported = 0;
    let mut request_count = 0;

    for product in &products {
        info!("  Downloading HIGH/CRITICAL CVEs for {}...", product);

        // Download in two batches: CRITICAL, then HIGH
        for severity in &["CRITICAL", "HIGH"] {
            let mut start_index = 0;
            let results_per_page = 2000; // Maximum allowed
            let mut severity_imported = 0;

            loop {
                let url = format!(
                    "{}?keywordSearch={}&cvssV3Severity={}&startIndex={}&resultsPerPage={}",
                    NVD_API_BASE, product, severity, start_index, results_per_page
                );

                debug!(
                    "Querying NVD {} severity page {} for {}",
                    severity,
                    start_index / results_per_page,
                    product
                );

                // Wait until API is ready (poll every second)
                wait_for_nvd_ready(&client, &mut request_count).await;

                // Make request
                match client.get(&url).send().await {
                    Ok(response) => {
                        let status = response.status();
                        request_count += 1;

                        // If still rate limited (shouldn't happen after wait_for_nvd_ready)
                        if status.as_u16() == 429 {
                            warn!("Still rate limited, waiting 6 seconds...");
                            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
                            request_count = 0; // Reset counter
                            continue; // Retry
                        }

                        if status.is_success() {
                            match response.json::<NvdResponse>().await {
                                Ok(nvd_response) => {
                                    let total_available = nvd_response.total_results;
                                    let returned_count = nvd_response.vulnerabilities.len();

                                    debug!(
                                        "  Page {}: Got {} CVEs (total available: {})",
                                        start_index / results_per_page,
                                        returned_count,
                                        total_available
                                    );

                                    // Process CVEs
                                    for vuln_wrapper in &nvd_response.vulnerabilities {
                                        let cve = &vuln_wrapper.cve;

                                        let description = cve
                                            .descriptions
                                            .iter()
                                            .find(|d| d.lang == "en")
                                            .map(|d| d.value.clone())
                                            .unwrap_or_else(|| "No description".to_string());

                                        let (cvss_score, cvss_severity) =
                                            extract_cvss_score(&cve.metrics);

                                        // Store all (already filtered by API for HIGH/CRITICAL)
                                        // But double-check CVSS >= 7.0 in case of edge cases
                                        if cvss_score >= 7.0 {
                                            schema::upsert_cve(
                                                conn,
                                                &cve.id,
                                                product,
                                                None,
                                                &description,
                                                cvss_score,
                                                &cvss_severity,
                                                &cve.published,
                                                &cve.last_modified,
                                                false,
                                                false,
                                                "NVD",
                                            )?;

                                            severity_imported += 1;
                                            total_imported += 1;
                                        }
                                    }

                                    // Check if we need more pages
                                    start_index += returned_count;

                                    if start_index >= total_available || returned_count == 0 {
                                        // Got all results for this severity
                                        if severity_imported > 0 {
                                            info!(
                                                "     ✓ {} {} CVEs for {}",
                                                severity_imported, severity, product
                                            );
                                        }
                                        break;
                                    }

                                    // Prevent infinite loops
                                    if start_index > 5000 {
                                        warn!(
                                            "  Stopping at 5,000 CVEs for {} {} (limit reached)",
                                            product, severity
                                        );
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to parse NVD response for {} {}: {}",
                                        product, severity, e
                                    );
                                    break;
                                }
                            }
                        } else {
                            warn!(
                                "NVD API returned error for {} {}: {}",
                                product, severity, status
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to download NVD data for {} {}: {}",
                            product, severity, e
                        );
                        break;
                    }
                } // End match
            } // End pagination loop
        } // End severity loop
    } // End product loop

    info!("✅ Imported {} CVEs from NVD", total_imported);
    Ok(())
}

/// Wait for NVD API to be ready (poll every second until not rate limited)
/// NVD allows 5 requests per 30 seconds without API key
async fn wait_for_nvd_ready(client: &reqwest::Client, request_count: &mut usize) {
    // If we haven't made 5 requests yet, we're good
    if *request_count < 5 {
        return;
    }

    // We've made 5+ requests, need to wait for rate limit window
    // Poll test endpoint every second until we get non-429
    let test_url = format!("{}?resultsPerPage=1", NVD_API_BASE);

    info!("     Checking NVD rate limit status...");

    loop {
        match client.get(&test_url).send().await {
            Ok(response) => {
                if response.status().as_u16() == 429 {
                    debug!("Still rate limited, waiting 1 second...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                } else {
                    // API is ready!
                    debug!("NVD API ready, continuing...");
                    *request_count = 1; // Reset counter (counting this test request)
                    return;
                }
            }
            Err(_) => {
                // Network error, wait and retry
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}

/// Extract CVSS score from NVD metrics (handles v3.1, v3.0, and v2.0)
fn extract_cvss_score(metrics: &Option<NvdMetrics>) -> (f32, String) {
    if let Some(m) = metrics {
        // Prefer CVSS v3.1
        if let Some(v31) = &m.cvss_metric_v31 {
            if let Some(first) = v31.first() {
                return (
                    first.cvss_data.base_score,
                    first.cvss_data.base_severity.clone(),
                );
            }
        }

        // Fall back to CVSS v3.0
        if let Some(v3) = &m.cvss_metric_v3 {
            if let Some(first) = v3.first() {
                return (
                    first.cvss_data.base_score,
                    first.cvss_data.base_severity.clone(),
                );
            }
        }

        // Fall back to CVSS v2.0
        if let Some(v2) = &m.cvss_metric_v2 {
            if let Some(first) = v2.first() {
                return (first.cvss_data.base_score, first.base_severity.clone());
            }
        }
    }

    (0.0, "UNKNOWN".to_string())
}
