package csf.public_critical_vuln

# Immediate action for critical vulnerabilities on public-facing resources
result := {"decision": "immediate_action", "reason": reason} {
    input.class_uid == 2002
    input.severity_id >= 4
    some i
    input.resources[i].labels[_] == "public"
    reason := sprintf("Critical vulnerability on public-facing resource %s", [input.resources[i].uid])
}
