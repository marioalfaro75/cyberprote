package csf.unpatched_critical

# Immediate action for unpatched critical vulnerabilities older than 30 days
result := {"decision": "immediate_action", "reason": reason} {
    input.class_uid == 2002
    input.severity_id >= 5
    input.finding.created_time
    input.finding.remediation.is_patched == false
    age_days := (time.now_ns() - input.finding.created_time * 1000000000) / (1000000000 * 86400)
    age_days > 30
    reason := sprintf("Unpatched critical vulnerability older than 30 days: severity_id=%d, age=%d days", [input.severity_id, age_days])
}
