/// Check versions of common desktop applications (Chrome, VS Code, Firefox, etc.)
/// These are often installed via snap, flatpak, or direct downloads - not package managers!
use crate::models::Finding;
use anyhow::Result;
use std::process::Command;
use tracing::{debug, info};

/// Check desktop application versions for vulnerabilities
pub async fn check_application_versions() -> Result<Vec<Finding>> {
    info!("🔍 Checking desktop application versions (snap, flatpak, direct installs)...");
    let findings = Vec::new();

    // Get all application versions
    let apps = get_application_versions().await;

    info!("  Found {} applications to check", apps.len());

    // For now, just log what we found
    for (app, version, install_method) in &apps {
        debug!(
            "  {} version {} (installed via {})",
            app, version, install_method
        );
    }

    // TODO: Check against CVE database
    // This would query the SQLite database for each app

    Ok(findings)
}

/// Get versions of common desktop applications
pub async fn get_application_versions() -> Vec<(String, String, String)> {
    let mut apps = Vec::new();

    // Check snap packages
    apps.extend(get_snap_packages().await);

    // Check flatpak packages
    apps.extend(get_flatpak_packages().await);

    // Check browsers
    apps.extend(check_browsers().await);

    // Check IDEs
    apps.extend(check_ides().await);

    apps
}

/// Get snap packages
async fn get_snap_packages() -> Vec<(String, String, String)> {
    let mut packages = Vec::new();

    let output = Command::new("snap").args(["list"]).output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Parse: Name    Version   Rev   Tracking  Publisher
            for line in stdout.lines().skip(1) {
                // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0].to_string();
                    let version = parts[1].to_string();
                    packages.push((name, version, "snap".to_string()));
                }
            }

            debug!("Found {} snap packages", packages.len());
        }
    }

    packages
}

/// Get flatpak packages
async fn get_flatpak_packages() -> Vec<(String, String, String)> {
    let mut packages = Vec::new();

    let output = Command::new("flatpak")
        .args(["list", "--app", "--columns=application,version"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 2 {
                    let name = parts[0].to_string();
                    let version = parts[1].to_string();
                    packages.push((name, version, "flatpak".to_string()));
                }
            }

            debug!("Found {} flatpak packages", packages.len());
        }
    }

    packages
}

/// Check browser versions
async fn check_browsers() -> Vec<(String, String, String)> {
    let mut browsers = Vec::new();

    // Chrome
    if let Ok(ver) = get_chrome_version() {
        browsers.push(("chrome".to_string(), ver, "direct".to_string()));
    }

    // Chromium
    if let Ok(ver) = get_chromium_version() {
        browsers.push(("chromium".to_string(), ver, "direct".to_string()));
    }

    // Firefox
    if let Ok(ver) = get_firefox_version() {
        browsers.push(("firefox".to_string(), ver, "direct".to_string()));
    }

    // Brave
    if let Ok(ver) = get_brave_version() {
        browsers.push(("brave".to_string(), ver, "direct".to_string()));
    }

    browsers
}

/// Check IDE versions
async fn check_ides() -> Vec<(String, String, String)> {
    let mut ides = Vec::new();

    // VS Code
    if let Ok(ver) = get_vscode_version() {
        ides.push(("vscode".to_string(), ver, "direct".to_string()));
    }

    // Sublime Text
    if let Ok(ver) = get_sublime_version() {
        ides.push(("sublime".to_string(), ver, "direct".to_string()));
    }

    ides
}

/// Get Chrome version
fn get_chrome_version() -> Result<String> {
    let output = Command::new("google-chrome").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let re = regex::Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }

    Err(anyhow::anyhow!("Could not parse Chrome version"))
}

/// Get Chromium version
fn get_chromium_version() -> Result<String> {
    let output = Command::new("chromium").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let re = regex::Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }

    Err(anyhow::anyhow!("Could not parse Chromium version"))
}

/// Get Firefox version
fn get_firefox_version() -> Result<String> {
    let output = Command::new("firefox").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    // Parse: Mozilla Firefox 120.0.1
    let re = regex::Regex::new(r"Firefox (\d+\.\d+(?:\.\d+)?)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }

    Err(anyhow::anyhow!("Could not parse Firefox version"))
}

/// Get Brave version
fn get_brave_version() -> Result<String> {
    let output = Command::new("brave-browser").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let re = regex::Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }

    Err(anyhow::anyhow!("Could not parse Brave version"))
}

/// Get VS Code version
fn get_vscode_version() -> Result<String> {
    let output = Command::new("code").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    // First line is version
    if let Some(first_line) = text.lines().next() {
        return Ok(first_line.trim().to_string());
    }

    Err(anyhow::anyhow!("Could not parse VS Code version"))
}

/// Get Sublime Text version
fn get_sublime_version() -> Result<String> {
    let output = Command::new("subl").arg("--version").output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let re = regex::Regex::new(r"Build (\d+)").unwrap();
    if let Some(caps) = re.captures(&text) {
        return Ok(caps[1].to_string());
    }

    Err(anyhow::anyhow!("Could not parse Sublime version"))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_chrome_version_parsing() {
        let output = "Google Chrome 120.0.6099.109";
        let re = regex::Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
        if let Some(caps) = re.captures(output) {
            assert_eq!(caps[1].to_string(), "120.0.6099.109");
        }
    }

    #[test]
    fn test_firefox_version_parsing() {
        let output = "Mozilla Firefox 121.0";
        let re = regex::Regex::new(r"Firefox (\d+\.\d+(?:\.\d+)?)").unwrap();
        if let Some(caps) = re.captures(output) {
            assert_eq!(caps[1].to_string(), "121.0");
        }
    }
}
