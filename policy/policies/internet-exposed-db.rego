package csf.internet_exposed_db

# Immediate action for internet-exposed database findings
result := {"decision": "immediate_action", "reason": reason} {
    some i
    input.resources[i].type == "database"
    input.resources[i].labels[_] == "public"
    reason := sprintf("Internet-exposed database detected: %s", [input.resources[i].uid])
}

result := {"decision": "immediate_action", "reason": reason} {
    some i
    input.resources[i].type == "database"
    input.resources[i].labels[_] == "internet-facing"
    reason := sprintf("Internet-exposed database detected: %s", [input.resources[i].uid])
}
