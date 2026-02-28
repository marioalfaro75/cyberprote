package csf.compliance_failure

# Flag compliance failures on critical infrastructure
result := {"decision": "escalate", "reason": reason} {
    input.class_uid == 2003
    input.compliance.status == "FAILED"
    input.severity_id >= 3
    reason := sprintf("Compliance failure: %s", [input.compliance.control])
}
