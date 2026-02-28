package csf.secret_exposure

# Escalate secret exposure findings
result := {"decision": "escalate", "reason": reason} {
    input.class_uid == 2001
    input.unmapped.secret_type
    reason := sprintf("Exposed secret of type %s detected", [input.unmapped.secret_type])
}
