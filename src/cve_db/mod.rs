pub mod downloader;
pub mod matcher;
pub mod package_cache;
/// SQLite-based CVE database for fast local lookups
/// Supports NVD, CISA KEV, and custom CVE feeds
pub mod schema;

use crate::models::Finding;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use tracing::info;

/// Get CVE database path (with fallback to user home)
fn get_db_path() -> PathBuf {
    let system_path = PathBuf::from("/var/cache/linux-guardian/cve.db");

    // Check if system path exists and is accessible
    if system_path.exists() {
        // If database exists, check if we can read and write to it
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&system_path)
            .is_ok()
        {
            return system_path;
        }
        // Database exists but we don't have permissions - use user home
    } else {
        // Try to create system path if we have permissions
        if let Some(parent) = system_path.parent() {
            if std::fs::create_dir_all(parent).is_ok()
                && std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&system_path)
                    .is_ok()
            {
                return system_path;
            }
        }
    }

    // Fall back to user home directory
    if let Ok(home) = std::env::var("HOME") {
        let mut user_path = PathBuf::from(home);
        user_path.push(".cache/linux-guardian/cve.db");

        if let Some(parent) = user_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        return user_path;
    }

    // Last resort: current directory
    PathBuf::from("./cve.db")
}

/// Initialize CVE database
pub fn init_database() -> Result<Connection> {
    let db_path = get_db_path();

    // Create directory if needed
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let conn = Connection::open(&db_path)?;

    // Create schema
    schema::create_tables(&conn)?;

    Ok(conn)
}

/// Check if database needs update
pub fn needs_update(conn: &Connection) -> Result<bool> {
    // Check last update time
    let last_update: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'last_update'",
            [],
            |row| row.get(0),
        )
        .ok();

    if let Some(last_update_str) = last_update {
        // Parse timestamp
        if let Ok(last_update) = chrono::DateTime::parse_from_rfc3339(&last_update_str) {
            let age =
                chrono::Utc::now().signed_duration_since(last_update.with_timezone(&chrono::Utc));

            // Update if older than 7 days
            return Ok(age.num_days() > 7);
        }
    }

    // No last update recorded, needs update
    Ok(true)
}

/// Update CVE database from all sources
pub async fn update_database() -> Result<()> {
    info!("🔄 Updating CVE database...");

    let conn = init_database()?;

    // Download and import CISA KEV
    info!("  Downloading CISA KEV catalog (1,400+ actively exploited CVEs)...");
    downloader::download_cisa_kev(&conn).await?;

    // Download and import NVD critical CVEs (CVSS >= 7.0)
    info!("  Downloading NVD critical CVEs (CVSS >= 7.0)...");
    downloader::download_nvd_critical(&conn).await?;

    // Update metadata
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        params!["last_update", chrono::Utc::now().to_rfc3339()],
    )?;

    // Get statistics
    let total_cves: i64 = conn.query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;
    let critical_cves: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0 OR actively_exploited = 1",
        [],
        |row| row.get(0),
    )?;

    info!(
        "✅ CVE database updated: {} total CVEs ({} critical/exploited)",
        total_cves, critical_cves
    );

    Ok(())
}

/// Query CVEs for installed packages
pub fn check_installed_packages(packages: &[(String, String)]) -> Result<Vec<Finding>> {
    let conn = init_database()?;
    let mut findings = Vec::new();

    info!(
        "🔍 Checking {} packages against local CVE database...",
        packages.len()
    );

    for (product, version) in packages {
        let cves = matcher::find_matching_cves(&conn, product, version)?;

        for cve in cves {
            findings.push(cve);
        }
    }

    info!("  Found {} CVE matches in database", findings.len());
    Ok(findings)
}

/// Get database statistics
pub fn get_database_stats() -> Result<DatabaseStats> {
    let conn = init_database()?;

    let total_cves: i64 = conn.query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;
    let critical_cves: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0",
        [],
        |row| row.get(0),
    )?;
    let actively_exploited: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cves WHERE actively_exploited = 1",
        [],
        |row| row.get(0),
    )?;

    let last_update: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'last_update'",
            [],
            |row| row.get(0),
        )
        .ok();

    Ok(DatabaseStats {
        total_cves: total_cves as usize,
        critical_cves: critical_cves as usize,
        actively_exploited: actively_exploited as usize,
        last_update,
    })
}

#[derive(Debug)]
pub struct DatabaseStats {
    pub total_cves: usize,
    pub critical_cves: usize,
    pub actively_exploited: usize,
    pub last_update: Option<String>,
}
