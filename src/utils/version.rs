/// Version comparison utilities for CVE matching
use std::cmp::Ordering;

/// Parse a version string into comparable components
/// Examples: "1.9.15" → [1, 9, 15], "2.4.50" → [2, 4, 50]
pub fn parse_version(version: &str) -> Vec<u32> {
    version
        .split(&['.', '-', '+'][..])
        .filter_map(|part| {
            // Remove non-numeric prefixes (like "p1" in "1.9.15p1")
            let numeric: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            numeric.parse().ok()
        })
        .collect()
}

/// Compare two version vectors
/// Returns: Less, Equal, or Greater
pub fn compare_versions(v1: &[u32], v2: &[u32]) -> Ordering {
    let max_len = v1.len().max(v2.len());

    for i in 0..max_len {
        let part1 = v1.get(i).copied().unwrap_or(0);
        let part2 = v2.get(i).copied().unwrap_or(0);

        match part1.cmp(&part2) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            Ordering::Equal => continue,
        }
    }

    Ordering::Equal
}

/// Check if a version is in a specified range
/// version: "1.9.15"
/// min: Some("1.9.14"), max: Some("1.9.17")
/// Returns: true if 1.9.14 <= 1.9.15 <= 1.9.17
pub fn version_in_range(
    version: &str,
    min_inclusive: Option<&str>,
    max_inclusive: Option<&str>,
) -> bool {
    let ver = parse_version(version);

    // Check minimum (inclusive)
    if let Some(min) = min_inclusive {
        let min_ver = parse_version(min);
        if compare_versions(&ver, &min_ver) == Ordering::Less {
            return false;
        }
    }

    // Check maximum (inclusive)
    if let Some(max) = max_inclusive {
        let max_ver = parse_version(max);
        if compare_versions(&ver, &max_ver) == Ordering::Greater {
            return false;
        }
    }

    true
}

/// Check if version is vulnerable based on excluding ranges
pub fn version_in_range_excluding(
    version: &str,
    min_excluding: Option<&str>,
    max_excluding: Option<&str>,
) -> bool {
    let ver = parse_version(version);

    // Check minimum (excluding)
    if let Some(min) = min_excluding {
        let min_ver = parse_version(min);
        if compare_versions(&ver, &min_ver) != Ordering::Greater {
            return false;
        }
    }

    // Check maximum (excluding)
    if let Some(max) = max_excluding {
        let max_ver = parse_version(max);
        if compare_versions(&ver, &max_ver) != Ordering::Less {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.9.15"), vec![1, 9, 15]);
        assert_eq!(parse_version("1.9.15p1"), vec![1, 9, 15]); // p1 is stripped (non-numeric)
        assert_eq!(parse_version("2.4.50-1ubuntu1"), vec![2, 4, 50, 1]);
        assert_eq!(parse_version("5.15.0"), vec![5, 15, 0]);
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(
            compare_versions(&[1, 9, 15], &[1, 9, 14]),
            Ordering::Greater
        );
        assert_eq!(compare_versions(&[1, 9, 15], &[1, 9, 15]), Ordering::Equal);
        assert_eq!(compare_versions(&[1, 9, 15], &[1, 9, 16]), Ordering::Less);
        assert_eq!(compare_versions(&[1, 9], &[1, 9, 0]), Ordering::Equal);
    }

    #[test]
    fn test_version_in_range() {
        // CVE-2025-32463: sudo 1.9.14 - 1.9.17
        assert!(version_in_range("1.9.14", Some("1.9.14"), Some("1.9.17")));
        assert!(version_in_range("1.9.15", Some("1.9.14"), Some("1.9.17")));
        assert!(version_in_range("1.9.17", Some("1.9.14"), Some("1.9.17")));

        assert!(!version_in_range("1.9.13", Some("1.9.14"), Some("1.9.17")));
        assert!(!version_in_range("1.9.18", Some("1.9.14"), Some("1.9.17")));
    }

    #[test]
    fn test_real_world_versions() {
        // Test with actual package versions
        assert!(version_in_range("1.9.15p1", Some("1.9.14"), Some("1.9.17")));
        assert!(version_in_range(
            "5.15.0-52-generic",
            Some("5.14"),
            Some("6.6")
        ));
        // 1.9.17p1 is parsed as [1,9,17] which equals max [1,9,17], so it IS in range (inclusive)
        assert!(version_in_range("1.9.17p1", Some("1.9.14"), Some("1.9.17")));
        // Test outside range
        assert!(!version_in_range("1.9.18", Some("1.9.14"), Some("1.9.17")));
    }

    #[test]
    fn test_no_bounds() {
        // No minimum
        assert!(version_in_range("1.0.0", None, Some("2.0.0")));
        // No maximum
        assert!(version_in_range("9.9.9", Some("1.0.0"), None));
        // No bounds
        assert!(version_in_range("5.5.5", None, None));
    }
}
