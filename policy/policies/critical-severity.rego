package csf.critical_severity

# Escalate any finding with critical or fatal severity
result := {"decision": "escalate", "reason": reason} {
    input.severity_id >= 5
    reason := sprintf("Critical/Fatal severity finding: severity_id=%d", [input.severity_id])
}
