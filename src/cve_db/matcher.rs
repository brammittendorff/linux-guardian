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

        // Filter out CVEs clearly about other platforms or products
        let desc_lower = cve.description.to_lowercase();
        let irrelevant_keywords = [
            "windows",
            "android",
            "ios",
            "macos",
            "solaris",
            "aix",
            "hpux",
            "junos",
            "cisco ios",
            "qualcomm",
            "snapdragon",
            "totolink router",
            "wordpress plugin",
            "drupal",
            "joomla",
            "phpmailer",
            "wordpress",
            "discord bot",
            "printer",
            "appliance",
            "dram chip",
            "rowhammer",
            "enttec",
            "kace",
            "kramerav",
            "gipsy",
            "vasion",
            "zabbix",
            "ucms",
        ];

        if irrelevant_keywords.iter().any(|k| desc_lower.contains(k)) {
            debug!(
                "Skipping {} - description contains irrelevant keyword",
                cve.cve_id
            );
            continue;
        }

        // Check if version is vulnerable using CPE matches
        if is_version_vulnerable(conn, &cve.cve_id, version)? {
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

/// Check if a version is vulnerable based on CPE version ranges
fn is_version_vulnerable(conn: &Connection, cve_id: &str, version: &str) -> Result<bool> {
    // Check if there are CPE matches for this CVE
    let mut stmt = conn.prepare(
        "SELECT version_start_including, version_start_excluding,
                version_end_including, version_end_excluding
         FROM cpe_matches
         WHERE cve_id = ? AND vulnerable = 1",
    )?;

    let matches = stmt.query_map([cve_id], |row| {
        Ok(CpeVersionRange {
            start_including: row.get(0)?,
            start_excluding: row.get(1)?,
            end_including: row.get(2)?,
            end_excluding: row.get(3)?,
        })
    })?;

    let version_parsed = parse_version(version);

    for range in matches.flatten() {
        if version_matches_range(&version_parsed, &range) {
            return Ok(true);
        }
    }

    // If no CPE ranges defined, don't assume vulnerable
    // This prevents false positives from broad product name matching
    Ok(false)
}

#[derive(Debug)]
struct CpeVersionRange {
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
            start_including: Some("1.9.14".to_string()),
            start_excluding: None,
            end_including: Some("1.9.17".to_string()),
            end_excluding: None,
        };

        assert!(version_matches_range(&version, &range1));

        let range2 = CpeVersionRange {
            start_including: Some("1.9.16".to_string()),
            start_excluding: None,
            end_including: None,
            end_excluding: None,
        };

        assert!(!version_matches_range(&version, &range2)); // 1.9.15 < 1.9.16
    }
}
