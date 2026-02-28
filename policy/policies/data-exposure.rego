package csf.data_exposure

# Escalate data security findings (class_uid 2006)
result := {"decision": "escalate", "reason": reason} {
    input.class_uid == 2006
    reason := sprintf("Data exposure finding detected: severity_id=%d", [input.severity_id])
}
