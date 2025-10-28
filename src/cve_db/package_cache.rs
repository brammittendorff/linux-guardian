/// Package List Cache - Avoid re-querying dpkg/rpm every scan
/// Caches installed packages for 24 hours
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info};

const CACHE_FILE: &str = "packages.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageCache {
    pub timestamp: String,
    pub packages: Vec<(String, String)>, // (name, version)
}

/// Get package cache path
fn get_cache_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let mut path = PathBuf::from(home);
        path.push(".cache/linux-guardian");
        path.push(CACHE_FILE);
        return path;
    }

    // Fallback
    PathBuf::from("/tmp/linux-guardian-packages.json")
}

/// Load package cache if recent (< 24 hours)
pub fn load_package_cache() -> Option<Vec<(String, String)>> {
    let cache_path = get_cache_path();

    if !cache_path.exists() {
        debug!("Package cache not found");
        return None;
    }

    // Check age
    if let Ok(metadata) = fs::metadata(&cache_path) {
        if let Ok(modified) = metadata.modified() {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();

            if age.as_secs() > 24 * 3600 {
                debug!(
                    "Package cache expired (age: {} hours)",
                    age.as_secs() / 3600
                );
                return None;
            }
        }
    }

    // Load cache
    if let Ok(content) = fs::read_to_string(&cache_path) {
        if let Ok(cache) = serde_json::from_str::<PackageCache>(&content) {
            info!(
                "📦 Using cached package list ({} packages, age: fresh)",
                cache.packages.len()
            );
            return Some(cache.packages);
        }
    }

    None
}

/// Save package list to cache
pub fn save_package_cache(packages: &[(String, String)]) -> Result<()> {
    let cache_path = get_cache_path();

    // Create directory
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let cache = PackageCache {
        timestamp: chrono::Utc::now().to_rfc3339(),
        packages: packages.to_vec(),
    };

    let json = serde_json::to_string_pretty(&cache)?;
    fs::write(&cache_path, json)?;

    debug!("Saved {} packages to cache", packages.len());
    Ok(())
}
