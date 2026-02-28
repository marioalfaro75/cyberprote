package csf.multi_cloud_spread

# Escalate if finding affects resources in multiple cloud providers
result := {"decision": "escalate", "reason": reason} {
    providers := {input.resources[i].cloud.provider | some i; input.resources[i].cloud.provider}
    count(providers) > 1
    reason := sprintf("Finding spans multiple cloud providers: %v", [providers])
}
