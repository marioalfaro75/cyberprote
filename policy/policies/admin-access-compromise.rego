package csf.admin_access_compromise

# Immediate action for admin/root identity findings with severity >= 4
result := {"decision": "immediate_action", "reason": reason} {
    input.severity_id >= 4
    identity_type := input.actor.user.type
    identity_type == "Admin"
    reason := sprintf("Admin identity compromise detected: user=%s severity_id=%d", [input.actor.user.name, input.severity_id])
}

result := {"decision": "immediate_action", "reason": reason} {
    input.severity_id >= 4
    input.actor.user.name == "root"
    reason := sprintf("Root identity compromise detected: severity_id=%d", [input.severity_id])
}
