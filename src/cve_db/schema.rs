/// CVE Database Schema for SQLite
use rusqlite::{Connection, Result};

/// Create all database tables
pub fn create_tables(conn: &Connection) -> Result<()> {
    // CVE main table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            product TEXT NOT NULL,
            vendor TEXT,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            published_date TEXT,
            last_modified TEXT,
            actively_exploited INTEGER DEFAULT 0,
            ransomware_use INTEGER DEFAULT 0,
            source TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // CPE (Common Platform Enumeration) table for version matching
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cpe_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            cpe_criteria TEXT NOT NULL,
            version_start_including TEXT,
            version_start_excluding TEXT,
            version_end_including TEXT,
            version_end_excluding TEXT,
            vulnerable INTEGER DEFAULT 1,
            FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
        )",
        [],
    )?;

    // CVE references (URLs, advisories)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            url TEXT,
            source TEXT,
            FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
        )",
        [],
    )?;

    // Metadata table (last update, version, etc.)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )",
        [],
    )?;

    // Create indexes for fast lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score DESC)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cves_exploited ON cves(actively_exploited)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_matches(cve_id)",
        [],
    )?;

    Ok(())
}

/// Insert or update CVE
#[allow(clippy::too_many_arguments)]
pub fn upsert_cve(
    conn: &Connection,
    cve_id: &str,
    product: &str,
    vendor: Option<&str>,
    description: &str,
    cvss_score: f32,
    cvss_severity: &str,
    published: &str,
    modified: &str,
    actively_exploited: bool,
    ransomware_use: bool,
    source: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO cves
         (cve_id, product, vendor, description, cvss_score, cvss_severity,
          published_date, last_modified, actively_exploited, ransomware_use, source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            cve_id,
            product,
            vendor,
            description,
            cvss_score,
            cvss_severity,
            published,
            modified,
            actively_exploited as i32,
            ransomware_use as i32,
            source,
        ],
    )?;

    Ok(())
}

/// Insert CPE match criteria
pub fn insert_cpe_match(
    conn: &Connection,
    cve_id: &str,
    cpe_criteria: &str,
    version_start_including: Option<&str>,
    version_start_excluding: Option<&str>,
    version_end_including: Option<&str>,
    version_end_excluding: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO cpe_matches
         (cve_id, cpe_criteria, version_start_including, version_start_excluding,
          version_end_including, version_end_excluding)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            cve_id,
            cpe_criteria,
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        ],
    )?;

    Ok(())
}

/// Clear old CVE data (for fresh update)
pub fn clear_cves_by_source(conn: &Connection, source: &str) -> Result<()> {
    conn.execute("DELETE FROM cves WHERE source = ?", [source])?;
    Ok(())
}
