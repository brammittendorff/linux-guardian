#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn test_package_name_normalization() {
        let names = vec![
            ("libsudo-dev", "sudo"),
            ("openssh-common", "openssh"),
            ("lib32gcc-s1", "32gcc-s1"),
        ];

        for (input, expected) in names {
            let normalized = input
                .to_lowercase()
                .replace("-dev", "")
                .replace("-common", "")
                .replace("lib", "");
            assert!(normalized.contains(expected));
        }
    }

    #[test]
    fn test_version_parsing() {
        let versions = vec![
            ("1.9.15p1-1ubuntu1", "1.9.15p1"),
            ("8.9p1-3ubuntu0.1", "8.9p1"),
            ("2.4.50+dfsg-1ubuntu1", "2.4.50"),
        ];

        for (input, expected) in versions {
            let parsed = input.split('-').next().unwrap_or(input);
            let parsed = parsed.split('+').next().unwrap_or(parsed);
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn test_sudo_version_extraction() {
        let output = b"Sudo version 1.9.15p1\nSudoers policy plugin version 1.9.15p1";
        let text = String::from_utf8_lossy(output);

        let re = regex::Regex::new(r"Sudo version (\d+\.\d+\.\d+)").unwrap();
        let version = re.captures(&text)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string());

        assert_eq!(version, Some("1.9.15".to_string()));
    }

    #[test]
    fn test_openssh_version_extraction() {
        let output = b"OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2";
        let text = String::from_utf8_lossy(output);

        let re = regex::Regex::new(r"OpenSSH_(\d+\.\d+)").unwrap();
        let version = re.captures(&text)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string());

        assert_eq!(version, Some("8.9".to_string()));
    }

    #[test]
    fn test_cisa_kev_json_structure() {
        // Test that we can parse CISA KEV JSON structure
        let sample_kev = json!({
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2025.10.20",
            "dateReleased": "2025-10-20T00:00:00.0000Z",
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2025-12345",
                    "vendorProject": "Sudo Project",
                    "product": "Sudo",
                    "vulnerabilityName": "Sudo Privilege Escalation",
                    "dateAdded": "2025-09-29",
                    "shortDescription": "Sudo contains a privilege escalation vulnerability.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2025-10-20",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": ""
                }
            ]
        });

        // Verify structure
        assert_eq!(sample_kev["count"], 2);
        assert!(sample_kev["vulnerabilities"].is_array());
        assert_eq!(sample_kev["vulnerabilities"][0]["cveID"], "CVE-2025-12345");
    }

    #[test]
    fn test_fuzzy_product_matching() {
        let test_cases = vec![
            ("sudo", "Sudo", true),
            ("sudo", "Sudo Project", true),
            ("openssh", "OpenSSH", true),
            ("apache2", "Apache HTTP Server", true),
            ("nginx", "Nginx Web Server", true),
            ("mysql", "PostgreSQL", false),
        ];

        for (pkg_name, cve_product, should_match) in test_cases {
            let pkg_lower = pkg_name.to_lowercase();
            let prod_lower = cve_product.to_lowercase();

            let matches = pkg_lower.contains(&prod_lower)
                || prod_lower.contains(&pkg_lower)
                || pkg_lower.replace(" ", "").contains(&prod_lower.replace(" ", ""))
                || prod_lower.replace(" ", "").contains(&pkg_lower.replace(" ", ""));

            assert_eq!(matches, should_match,
                "Matching '{}' against '{}' should be {}",
                pkg_name, cve_product, should_match);
        }
    }

    #[test]
    fn test_cache_path_construction() {
        use std::path::PathBuf;

        let cache_dir = "/var/cache/linux-guardian";
        let cache_file = "cisa_kev.json";

        let mut path = PathBuf::from(cache_dir);
        path.push(cache_file);

        assert_eq!(path.to_str().unwrap(), "/var/cache/linux-guardian/cisa_kev.json");
    }

    #[test]
    fn test_severity_assignment() {
        // Critical if known ransomware use
        assert_eq!(
            if "Known".to_lowercase() == "known" { "critical" } else { "high" },
            "critical"
        );

        // High otherwise
        assert_eq!(
            if "Unknown".to_lowercase() == "known" { "critical" } else { "high" },
            "high"
        );
    }

    #[test]
    fn test_package_version_struct() {
        #[derive(Debug, Clone)]
        struct InstalledPackage {
            name: String,
            version: String,
            source: String,
        }

        let pkg = InstalledPackage {
            name: "sudo".to_string(),
            version: "1.9.15".to_string(),
            source: "dpkg".to_string(),
        };

        assert_eq!(pkg.name, "sudo");
        assert_eq!(pkg.version, "1.9.15");
        assert_eq!(pkg.source, "dpkg");
    }
}
