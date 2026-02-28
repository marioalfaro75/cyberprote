package csf.privilege_escalation

# Immediate action for privilege escalation findings
result := {"decision": "immediate_action", "reason": reason} {
    some i
    input.attacks[i].technique.uid
    contains(lower(input.attacks[i].technique.name), "privilege escalation")
    reason := sprintf("Privilege escalation detected: technique=%s", [input.attacks[i].technique.name])
}

result := {"decision": "immediate_action", "reason": reason} {
    contains(lower(input.finding.title), "privilege escalation")
    reason := sprintf("Privilege escalation finding: %s", [input.finding.title])
}
