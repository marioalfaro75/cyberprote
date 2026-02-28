package csf.supply_chain_risk

# Escalate dependency/supply-chain vulnerability findings
result := {"decision": "escalate", "reason": reason} {
    some i
    input.vulnerabilities[i].packages[_]
    input.vulnerabilities[i].cve.uid
    input.severity_id >= 3
    reason := sprintf("Supply-chain vulnerability in package dependency: %s severity_id=%d", [input.vulnerabilities[i].cve.uid, input.severity_id])
}
