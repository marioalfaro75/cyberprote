package csf.suppress_resolved

# Suppress findings with status "Resolved"
result := {"decision": "suppress", "reason": "Finding status is Resolved"} {
    input.status == "Resolved"
}
