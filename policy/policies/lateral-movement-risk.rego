package csf.lateral_movement_risk

# Escalate detection findings (class_uid 2004) indicating lateral movement
result := {"decision": "escalate", "reason": reason} {
    input.class_uid == 2004
    contains(lower(input.finding.title), "lateral movement")
    reason := sprintf("Lateral movement risk detected: %s", [input.finding.title])
}

result := {"decision": "escalate", "reason": reason} {
    input.class_uid == 2004
    some i
    input.attacks[i].technique.name
    contains(lower(input.attacks[i].technique.name), "lateral movement")
    reason := sprintf("Lateral movement technique detected: %s", [input.attacks[i].technique.name])
}
