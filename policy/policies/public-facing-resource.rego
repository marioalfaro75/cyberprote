package csf.public_facing_resource

# Escalate if resource is public-facing and severity >= 3
result := {"decision": "escalate", "reason": reason} {
    input.severity_id >= 3
    some i
    input.resources[i].labels[_] == "public"
    reason := sprintf("Public-facing resource %s with severity_id=%d", [input.resources[i].uid, input.severity_id])
}
