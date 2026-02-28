package csf.kev_immediate

# Require immediate action for findings exploiting known exploited vulnerabilities
result := {"decision": "immediate_action", "reason": reason} {
    some i
    input.vulnerabilities[i].cve.is_exploited == true
    reason := sprintf("CVE %s is in CISA KEV catalog", [input.vulnerabilities[i].cve.uid])
}
