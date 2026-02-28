package csf.auto_remediate_low

# Auto-remediate low severity (1) compliance findings (class_uid 2003)
result := {"decision": "auto_remediate", "reason": reason} {
    input.class_uid == 2003
    input.severity_id == 1
    reason := sprintf("Auto-remediating low severity compliance finding: %s", [input.compliance.control])
}
