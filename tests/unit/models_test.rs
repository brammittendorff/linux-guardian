use linux_guardian::models::*;

#[test]
fn test_finding_critical() {
    let finding = Finding::critical(
        "test_category",
        "Test Title",
        "Test description",
    );

    assert_eq!(finding.severity, "critical");
    assert_eq!(finding.category, "test_category");
    assert_eq!(finding.title, "Test Title");
    assert_eq!(finding.description, "Test description");
    assert!(finding.remediation.is_none());
    assert!(finding.cve.is_none());
}

#[test]
fn test_finding_with_cve() {
    let finding = Finding::high("category", "title", "description")
        .with_cve("CVE-2025-12345");

    assert_eq!(finding.severity, "high");
    assert_eq!(finding.cve, Some("CVE-2025-12345".to_string()));
}

#[test]
fn test_finding_with_remediation() {
    let finding = Finding::medium("category", "title", "description")
        .with_remediation("Update package");

    assert_eq!(finding.remediation, Some("Update package".to_string()));
}

#[test]
fn test_finding_with_details() {
    let details = serde_json::json!({"key": "value"});
    let finding = Finding::low("category", "title", "description")
        .with_details(details.clone());

    assert!(finding.details.is_some());
    assert_eq!(finding.details.unwrap(), details);
}

#[test]
fn test_finding_builder_chain() {
    let finding = Finding::critical("priv_esc", "Sudo Vuln", "Description")
        .with_cve("CVE-2025-32463")
        .with_remediation("Update sudo");

    assert_eq!(finding.severity, "critical");
    assert_eq!(finding.cve, Some("CVE-2025-32463".to_string()));
    assert_eq!(finding.remediation, Some("Update sudo".to_string()));
}

#[test]
fn test_finding_json_serialization() {
    let finding = Finding::critical("test", "Test", "Desc");
    let json = serde_json::to_string(&finding);
    assert!(json.is_ok());
}
