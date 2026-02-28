package csf.container_escape

# Immediate action for container escape vulnerability findings
result := {"decision": "immediate_action", "reason": reason} {
    contains(lower(input.finding.title), "container escape")
    reason := sprintf("Container escape vulnerability detected: %s", [input.finding.title])
}

result := {"decision": "immediate_action", "reason": reason} {
    some i
    input.attacks[i].technique.name
    contains(lower(input.attacks[i].technique.name), "container escape")
    reason := sprintf("Container escape technique detected: %s", [input.attacks[i].technique.name])
}
