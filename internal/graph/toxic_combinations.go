package graph

// ToxicCombinationQueries contains pre-built Cypher queries that detect
// dangerous security patterns ("toxic combinations") in the graph.
var ToxicCombinationQueries = map[string]string{

	// 1. Public-facing resource with critical vulnerability
	"public_facing_critical_vuln": `
		MATCH (r:Resource)-[:EXPOSES]->(n:NetworkPath {is_public: true}),
		      (f:Finding)-[:AFFECTS]->(r),
		      (f)-[:EXPLOITS]->(v:Vulnerability)
		WHERE f.severity_id >= 4 AND v.cvss_score >= 9.0
		RETURN r.uid AS resource, v.uid AS cve, f.uid AS finding, v.cvss_score AS score
	`,

	// 2. Admin identity with credential exposure finding
	"admin_credential_exposure": `
		MATCH (i:Identity {type: 'admin'})-[:HAS_ACCESS_TO]->(r:Resource),
		      (f:Finding)-[:AFFECTS]->(r)
		WHERE f.class_uid = 2001 AND f.title CONTAINS 'credential'
		RETURN i.uid AS identity, r.uid AS resource, f.uid AS finding
	`,

	// 3. Resource chain: public → private with lateral movement
	"lateral_movement_path": `
		MATCH path = (pub:Resource)-[:EXPOSES]->(n:NetworkPath {is_public: true}),
		      (f1:Finding)-[:AFFECTS]->(pub),
		      (pub)-[:DEPENDS_ON*1..3]->(priv:Resource),
		      (f2:Finding)-[:AFFECTS]->(priv)
		WHERE f1.severity_id >= 3 AND f2.severity_id >= 4
		RETURN pub.uid AS entry_point, priv.uid AS target, f1.uid AS entry_finding, f2.uid AS target_finding
	`,

	// 4. Overprivileged identity with access to sensitive resource under finding
	"overprivileged_sensitive_access": `
		MATCH (i:Identity)-[:HAS_ACCESS_TO]->(r:Resource),
		      (f:Finding)-[:AFFECTS]->(r)
		WHERE f.severity_id >= 4
		      AND i.type IN ['admin', 'power_user']
		RETURN i.uid AS identity, i.type AS role, r.uid AS resource, f.title AS finding_title
	`,

	// 5. Unpatched vulnerability in internet-exposed resource
	"unpatched_internet_exposed": `
		MATCH (r:Resource)-[:EXPOSES]->(n:NetworkPath {is_public: true}),
		      (f:Finding)-[:AFFECTS]->(r),
		      (f)-[:EXPLOITS]->(v:Vulnerability)
		WHERE f.status <> 'Resolved'
		RETURN r.uid AS resource, v.uid AS cve, v.cvss_score AS cvss, f.status AS status
		ORDER BY v.cvss_score DESC
	`,

	// 6. Cross-account role assumption chain
	"cross_account_assumption": `
		MATCH (i1:Identity)-[:ASSUMES]->(i2:Identity)
		WHERE i1.account_id <> i2.account_id
		RETURN i1.uid AS source_identity, i1.account_id AS source_account,
		       i2.uid AS target_identity, i2.account_id AS target_account
	`,

	// 7. Resource with multiple critical findings
	"multi_critical_findings": `
		MATCH (f:Finding)-[:AFFECTS]->(r:Resource)
		WHERE f.severity_id >= 4
		WITH r, count(f) AS crit_count, collect(f.uid) AS finding_ids
		WHERE crit_count >= 3
		RETURN r.uid AS resource, crit_count, finding_ids
		ORDER BY crit_count DESC
	`,

	// 8. Data exposure: public resource with data security finding
	"data_exposure_public": `
		MATCH (r:Resource)-[:EXPOSES]->(n:NetworkPath {is_public: true}),
		      (f:Finding)-[:AFFECTS]->(r)
		WHERE f.class_uid = 2006
		RETURN r.uid AS resource, f.uid AS finding, f.title AS title
	`,

	// 9. Compliance failure on critical infrastructure
	"compliance_gap_critical_infra": `
		MATCH (f:Finding)-[:AFFECTS]->(r:Resource)
		WHERE f.class_uid = 2003 AND f.status <> 'Resolved'
		WITH r, count(f) AS compliance_gaps, collect(f.title) AS gap_titles
		WHERE compliance_gaps >= 2
		RETURN r.uid AS resource, compliance_gaps, gap_titles
		ORDER BY compliance_gaps DESC
	`,

	// 10. Identity with access to resources across multiple accounts
	"cross_account_access": `
		MATCH (i:Identity)-[:HAS_ACCESS_TO]->(r:Resource)
		WITH i, count(DISTINCT r.account_id) AS account_count, collect(DISTINCT r.account_id) AS accounts
		WHERE account_count >= 2
		RETURN i.uid AS identity, account_count, accounts
		ORDER BY account_count DESC
	`,

	// 11. Exploitable vulnerability with known exploit (KEV)
	"kev_exploitable_vuln": `
		MATCH (f:Finding)-[:EXPLOITS]->(v:Vulnerability)
		WHERE v.is_exploited = true AND f.status <> 'Resolved'
		MATCH (f)-[:AFFECTS]->(r:Resource)
		RETURN v.uid AS cve, r.uid AS resource, f.uid AS finding, v.cvss_score AS cvss
		ORDER BY v.cvss_score DESC
	`,

	// 12. Shadow admin: identity with admin-equivalent permissions but not labeled admin
	"shadow_admin": `
		MATCH (i:Identity)-[:HAS_ACCESS_TO]->(r:Resource)
		WHERE i.type <> 'admin'
		WITH i, count(r) AS resource_count
		WHERE resource_count >= 10
		RETURN i.uid AS identity, i.type AS labeled_type, resource_count
		ORDER BY resource_count DESC
	`,

	// 13. Cross-cloud lateral movement: finding in one provider leads to resources in another
	"cross_cloud_lateral_movement": `
		MATCH (f1:Finding)-[:AFFECTS]->(r1:Resource),
		      (r1)-[:DEPENDS_ON]->(r2:Resource),
		      (f2:Finding)-[:AFFECTS]->(r2)
		WHERE r1.cloud_provider <> r2.cloud_provider
		      AND f1.severity_id >= 3
		RETURN r1.uid AS source_resource, r1.cloud_provider AS source_cloud,
		       r2.uid AS target_resource, r2.cloud_provider AS target_cloud,
		       f1.uid AS source_finding, f2.uid AS target_finding
	`,

	// 14. Multi-cloud identity: identity with access across cloud providers
	"multi_cloud_identity_risk": `
		MATCH (i:Identity)-[:HAS_ACCESS_TO]->(r:Resource)
		WITH i, collect(DISTINCT r.cloud_provider) AS providers, count(r) AS resource_count
		WHERE size(providers) >= 2
		RETURN i.uid AS identity, providers, resource_count
		ORDER BY resource_count DESC
	`,

	// 15. Cross-cloud data exposure: public resource in one cloud with data findings in another
	"cross_cloud_data_exposure": `
		MATCH (r1:Resource)-[:EXPOSES]->(n:NetworkPath {is_public: true}),
		      (r1)-[:DEPENDS_ON]->(r2:Resource),
		      (f:Finding)-[:AFFECTS]->(r2)
		WHERE f.class_uid = 2006
		      AND r1.cloud_provider <> r2.cloud_provider
		RETURN r1.uid AS public_resource, r1.cloud_provider AS public_cloud,
		       r2.uid AS data_resource, r2.cloud_provider AS data_cloud,
		       f.uid AS data_finding
	`,
}
