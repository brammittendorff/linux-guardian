/// Match installed packages against CVE database
use crate::models::Finding;
use crate::utils::version::{compare_versions, parse_version};
use anyhow::Result;
use rusqlite::Connection;
use std::cmp::Ordering;
use tracing::debug;

/// Find CVEs matching a specific product and version
pub fn find_matching_cves(conn: &Connection, product: &str, version: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Query CVEs for this product (strict matching to avoid false positives)
    let mut stmt = conn.prepare(
        "SELECT cve_id, product, vendor, description, cvss_score, cvss_severity,
                actively_exploited, ransomware_use
         FROM cves
         WHERE LOWER(product) = ?
            OR LOWER(product) LIKE ? || '%'
            OR LOWER(product) LIKE '% ' || ? || ' %'
         ORDER BY cvss_score DESC, actively_exploited DESC
         LIMIT 100",
    )?;

    let cve_iter = stmt.query_map(
        rusqlite::params![
            product.to_lowercase(),
            product.to_lowercase(),
            product.to_lowercase()
        ],
        |row| {
            Ok(CveRow {
                cve_id: row.get(0)?,
                product: row.get(1)?,
                vendor: row.get(2)?,
                description: row.get(3)?,
                cvss_score: row.get(4)?,
                cvss_severity: row.get(5)?,
                actively_exploited: row.get::<_, i32>(6)? == 1,
                ransomware_use: row.get::<_, i32>(7)? == 1,
            })
        },
    )?;

    for cve in cve_iter.flatten() {
        // Aggressively filter non-Linux vendors
        if let Some(ref vendor) = cve.vendor {
            let vendor_lower = vendor.to_lowercase();
            let irrelevant_vendors = [
                "cisco",
                "qualcomm",
                "microsoft",
                "adobe",
                "apple",
                "android",
                "oracle",
                "symantec",
                "intel corporation",
                "samsung",
                "sk hynix",
                "micron",
                "nvidia",
                "amd",
                "broadcom",
                "mediatek",
                "huawei",
                "tenda",
                "totolink",
                "d-link",
                "netgear",
                "tp-link",
            ];

            if irrelevant_vendors.iter().any(|v| vendor_lower.contains(v)) {
                debug!(
                    "Skipping {} - vendor {} not relevant for Linux desktop",
                    cve.cve_id, vendor
                );
                continue;
            }
        }

        // Generic filter: skip CVEs about other platforms
        let desc_lower = cve.description.to_lowercase();
        let irrelevant_keywords = [
            "windows", "android", "ios", "macos", "solaris", "aix", "hpux",
        ];

        if irrelevant_keywords.iter().any(|k| desc_lower.contains(k)) {
            debug!(
                "Skipping {} - description contains irrelevant OS",
                cve.cve_id
            );
            continue;
        }

        // CRITICAL: Only proceed if CVE has CPE matches that actually reference this product
        // This is the generic solution - filters out CVEs that mention the product
        // but are actually about other software
        if !has_relevant_cpe_matches(conn, &cve.cve_id, product)? {
            debug!(
                "Skipping {} - CPE doesn't match product '{}' (false positive)",
                cve.cve_id, product
            );
            continue;
        }

        // Check if version is vulnerable using CPE matches
        if is_version_vulnerable(conn, &cve.cve_id, product, version)? {
            findings.push(create_finding_from_cve(&cve, product, version));
        }
    }

    Ok(findings)
}

#[derive(Debug)]
struct CveRow {
    cve_id: String,
    product: String,
    vendor: Option<String>,
    description: String,
    cvss_score: f32,
    cvss_severity: String,
    actively_exploited: bool,
    ransomware_use: bool,
}

/// Check if a CVE has CPE matches that actually reference this product
/// This is the key to filtering false positives - only trust CVEs where
/// the CPE criteria mentions the actual product we're checking
fn has_relevant_cpe_matches(conn: &Connection, cve_id: &str, product: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT cpe_criteria FROM cpe_matches
         WHERE cve_id = ?
         AND (version_start_including IS NOT NULL
              OR version_start_excluding IS NOT NULL
              OR version_end_including IS NOT NULL
              OR version_end_excluding IS NOT NULL)",
    )?;

    let cpe_iter = stmt.query_map([cve_id], |row| row.get::<_, String>(0))?;

    // Check if ANY CPE criteria mentions this product
    // CPE format: cpe:2.3:a:vendor:product:version:...
    let product_lower = product.to_lowercase().replace("-", "_");

    for cpe in cpe_iter.flatten() {
        let cpe_lower = cpe.to_lowercase();

        // Extract product from CPE (5th field after splitting by ':')
        let parts: Vec<&str> = cpe_lower.split(':').collect();
        if parts.len() >= 5 {
            let cpe_product = parts[4];

            // IMPORTANT: Use exact match, not substring match
            // "linux" should NOT match "anti-virus_for_linux_server"
            // But "linux_kernel" should match "linux_kernel"
            if cpe_product == product_lower {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Check if a version is vulnerable based on CPE version ranges
fn is_version_vulnerable(
    conn: &Connection,
    cve_id: &str,
    product: &str,
    version: &str,
) -> Result<bool> {
    // IMPORTANT: Only check CPE matches that have actual version constraints
    // AND that match the product we're checking (to avoid matching against
    // other products' version ranges, e.g., openssh vs mac_os_x)
    let mut stmt = conn.prepare(
        "SELECT cpe_criteria, version_start_including, version_start_excluding,
                version_end_including, version_end_excluding
         FROM cpe_matches
         WHERE cve_id = ? AND vulnerable = 1
         AND (version_start_including IS NOT NULL
              OR version_start_excluding IS NOT NULL
              OR version_end_including IS NOT NULL
              OR version_end_excluding IS NOT NULL)",
    )?;

    let matches = stmt.query_map([cve_id], |row| {
        Ok(CpeVersionRange {
            cpe_criteria: row.get(0)?,
            start_including: row.get(1)?,
            start_excluding: row.get(2)?,
            end_including: row.get(3)?,
            end_excluding: row.get(4)?,
        })
    })?;

    let version_parsed = parse_version(version);
    let product_lower = product.to_lowercase().replace("-", "_");

    for range in matches.flatten() {
        // CRITICAL FIX: Only check version ranges for CPE entries that match this product
        // CPE format: cpe:2.3:a:vendor:product:version:...
        // Extract product from CPE (5th field after splitting by ':')
        let cpe_lower = range.cpe_criteria.to_lowercase();
        let parts: Vec<&str> = cpe_lower.split(':').collect();

        if parts.len() >= 5 {
            let cpe_product = parts[4];

            // Only check this range if CPE product matches our product (exact match)
            // IMPORTANT: "linux" should NOT match "anti-virus_for_linux_server"
            if cpe_product == product_lower && version_matches_range(&version_parsed, &range) {
                return Ok(true);
            }
        }
    }

    // If no matching CPE ranges, don't match
    Ok(false)
}

#[derive(Debug)]
struct CpeVersionRange {
    cpe_criteria: String,
    start_including: Option<String>,
    start_excluding: Option<String>,
    end_including: Option<String>,
    end_excluding: Option<String>,
}

/// Check if version matches a CPE version range
fn version_matches_range(version: &[u32], range: &CpeVersionRange) -> bool {
    // Check start_including
    if let Some(ref start_inc) = range.start_including {
        let start_ver = parse_version(start_inc);
        if compare_versions(version, &start_ver) == Ordering::Less {
            return false;
        }
    }

    // Check start_excluding
    if let Some(ref start_exc) = range.start_excluding {
        let start_ver = parse_version(start_exc);
        if compare_versions(version, &start_ver) != Ordering::Greater {
            return false;
        }
    }

    // Check end_including
    if let Some(ref end_inc) = range.end_including {
        let end_ver = parse_version(end_inc);
        if compare_versions(version, &end_ver) == Ordering::Greater {
            return false;
        }
    }

    // Check end_excluding
    if let Some(ref end_exc) = range.end_excluding {
        let end_ver = parse_version(end_exc);
        if compare_versions(version, &end_ver) != Ordering::Less {
            return false;
        }
    }

    true
}

/// Create Finding from CVE database row
fn create_finding_from_cve(cve: &CveRow, product: &str, installed_version: &str) -> Finding {
    let severity = if cve.cvss_score >= 9.0 || cve.actively_exploited {
        "critical"
    } else if cve.cvss_score >= 7.0 {
        "high"
    } else {
        "medium"
    };

    let exploit_status = if cve.actively_exploited {
        "ACTIVELY EXPLOITED IN THE WILD"
    } else if cve.cvss_score >= 9.0 {
        "Critical severity"
    } else {
        "Known vulnerability"
    };

    let ransomware_notice = if cve.ransomware_use {
        " ⚠️ USED IN RANSOMWARE CAMPAIGNS."
    } else {
        ""
    };

    Finding {
        severity: severity.to_string(),
        category: "cve_database".to_string(),
        title: format!("{} - {} Vulnerability (Database)", cve.cve_id, product),
        description: format!(
            "{} version {} is affected by: {}. {} CVSS: {:.1}/10.0{}",
            product,
            installed_version,
            cve.description,
            exploit_status,
            cve.cvss_score,
            ransomware_notice
        ),
        remediation: Some(format!(
            "Update {} immediately. Check vendor security advisories.",
            product
        )),
        cve: Some(cve.cve_id.clone()),
        details: Some(serde_json::json!({
            "installed_version": installed_version,
            "cvss_score": cve.cvss_score,
            "cvss_severity": cve.cvss_severity,
            "actively_exploited": cve.actively_exploited,
            "ransomware_use": cve.ransomware_use,
            "product": cve.product,
            "vendor": cve.vendor,
        })),
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_product_normalization() {
        let normalized = "linux-kernel"
            .to_lowercase()
            .replace("-", "")
            .replace("_", "");
        assert_eq!(normalized, "linuxkernel");
    }

    #[test]
    fn test_version_range_matching() {
        let version = vec![1, 9, 15];

        let range1 = CpeVersionRange {
            cpe_criteria: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*".to_string(),
            start_including: Some("1.9.14".to_string()),
            start_excluding: None,
            end_including: Some("1.9.17".to_string()),
            end_excluding: None,
        };

        assert!(version_matches_range(&version, &range1));

        let range2 = CpeVersionRange {
            cpe_criteria: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*".to_string(),
            start_including: Some("1.9.16".to_string()),
            start_excluding: None,
            end_including: None,
            end_excluding: None,
        };

        assert!(!version_matches_range(&version, &range2)); // 1.9.15 < 1.9.16
    }
}
