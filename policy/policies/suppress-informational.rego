package csf.suppress_informational

# Suppress purely informational findings
result := {"decision": "suppress", "reason": "Informational severity finding"} {
    input.severity_id == 1
}
