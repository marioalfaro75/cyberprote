// Package graph provides the GraphService for interacting with the Apache AGE
// graph database that stores the Cloud Security Fabric security graph.
package graph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// GraphService manages the connection to PostgreSQL/AGE and provides
// graph operations for the security fabric.
type GraphService struct {
	db        *sql.DB
	graphName string
	mu        sync.Mutex
}

// NewGraphService creates a new GraphService and verifies connectivity.
func NewGraphService(dsn string, graphName string) (*GraphService, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	gs := &GraphService{
		db:        db,
		graphName: graphName,
	}

	if err := gs.initAGE(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("init AGE: %w", err)
	}

	return gs, nil
}

// initAGE loads the AGE extension and sets the search path.
func (gs *GraphService) initAGE(ctx context.Context) error {
	stmts := []string{
		"LOAD 'age'",
		`SET search_path = ag_catalog, "$user", public`,
	}
	for _, stmt := range stmts {
		if _, err := gs.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("exec %q: %w", stmt, err)
		}
	}
	return nil
}

// Close closes the underlying database connection.
func (gs *GraphService) Close() error {
	return gs.db.Close()
}

// DB returns the underlying *sql.DB for direct access when needed.
func (gs *GraphService) DB() *sql.DB {
	return gs.db
}

// execCypher runs a Cypher query against the graph via AGE's cypher() function.
// It acquires a single connection to ensure LOAD 'age' and the Cypher query
// share the same session.
func (gs *GraphService) execCypher(ctx context.Context, query string) error {
	conn, err := gs.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "LOAD 'age'"); err != nil {
		return fmt.Errorf("load age: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SET search_path = ag_catalog, "$user", public`); err != nil {
		return fmt.Errorf("set search_path: %w", err)
	}
	stmt := fmt.Sprintf(
		`SELECT * FROM cypher('%s', $$ %s $$) as (result agtype)`,
		gs.graphName, query,
	)
	_, err = conn.ExecContext(ctx, stmt)
	return err
}

// queryCypherCollect runs a Cypher query on a dedicated connection (with AGE loaded)
// and collects all row data as raw strings before returning. This avoids issues
// with connection pooling and multi-statement queries.
func (gs *GraphService) queryCypherCollect(ctx context.Context, query string, returnCols string, numCols int) ([][]string, error) {
	conn, err := gs.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "LOAD 'age'"); err != nil {
		return nil, fmt.Errorf("load age: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SET search_path = ag_catalog, "$user", public`); err != nil {
		return nil, fmt.Errorf("set search_path: %w", err)
	}
	stmt := fmt.Sprintf(
		`SELECT * FROM cypher('%s', $$ %s $$) as (%s)`,
		gs.graphName, query, returnCols,
	)
	rows, err := conn.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results [][]string
	for rows.Next() {
		cols := make([]string, numCols)
		ptrs := make([]interface{}, numCols)
		for i := range cols {
			ptrs[i] = &cols[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		results = append(results, cols)
	}
	return results, rows.Err()
}

// queryCypher is a convenience wrapper for single-column Cypher queries.
func (gs *GraphService) queryCypher(ctx context.Context, query string, returnCols string) ([]string, error) {
	collected, err := gs.queryCypherCollect(ctx, query, returnCols, 1)
	if err != nil {
		return nil, err
	}
	results := make([]string, len(collected))
	for i, row := range collected {
		results[i] = row[0]
	}
	return results, nil
}

// queryCypher2 is a convenience wrapper for two-column Cypher queries.
func (gs *GraphService) queryCypher2(ctx context.Context, query string, returnCols string) ([][2]string, error) {
	collected, err := gs.queryCypherCollect(ctx, query, returnCols, 2)
	if err != nil {
		return nil, err
	}
	results := make([][2]string, len(collected))
	for i, row := range collected {
		results[i] = [2]string{row[0], row[1]}
	}
	return results, nil
}

// propsJSON converts a map to an AGE-compatible Cypher map literal string.
// AGE requires unquoted keys and single-quoted string values:
//
//	{uid: 'abc', severity_id: 3, is_public: true}
func propsJSON(props map[string]interface{}) string {
	if len(props) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(props))
	for k, v := range props {
		switch val := v.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s: '%s'", k, escapeString(val)))
		case bool:
			parts = append(parts, fmt.Sprintf("%s: %t", k, val))
		default:
			parts = append(parts, fmt.Sprintf("%s: %v", k, val))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// escapeString escapes single quotes for Cypher string literals.
func escapeString(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

// UpsertResource creates or updates a Resource node in the graph.
func (gs *GraphService) UpsertResource(ctx context.Context, uid, resourceType, name, provider, accountID, region string) error {
	props := map[string]interface{}{
		"uid":          uid,
		"type":         resourceType,
		"name":         name,
		"provider":     provider,
		"account_id":   accountID,
		"region":       region,
		"updated_at":   time.Now().Unix(),
	}
	query := fmt.Sprintf(
		`MERGE (r:Resource {uid: '%s'}) SET r = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// FindingExtra holds optional additional properties for a Finding node.
type FindingExtra struct {
	ComplianceStatus    string
	ComplianceControl   string
	ComplianceStandards string // comma-separated
	AttackTechniques    string // comma-separated technique UIDs
	AttackTactics       string // comma-separated tactic UIDs
}

// UpsertFinding creates or updates a Finding node.
func (gs *GraphService) UpsertFinding(ctx context.Context, uid string, classUID int32, severityID int32, title, message, provider, status string) error {
	return gs.UpsertFindingWithExtra(ctx, uid, classUID, severityID, title, message, provider, status, nil)
}

// UpsertFindingWithExtra creates or updates a Finding node with optional extra properties.
func (gs *GraphService) UpsertFindingWithExtra(ctx context.Context, uid string, classUID int32, severityID int32, title, message, provider, status string, extra *FindingExtra) error {
	props := map[string]interface{}{
		"uid":         uid,
		"class_uid":   classUID,
		"severity_id": severityID,
		"title":       title,
		"message":     message,
		"provider":    provider,
		"status":      status,
		"updated_at":  time.Now().Unix(),
	}
	if extra != nil {
		if extra.ComplianceStatus != "" {
			props["compliance_status"] = extra.ComplianceStatus
		}
		if extra.ComplianceControl != "" {
			props["compliance_control"] = extra.ComplianceControl
		}
		if extra.ComplianceStandards != "" {
			props["compliance_standards"] = extra.ComplianceStandards
		}
		if extra.AttackTechniques != "" {
			props["attack_techniques"] = extra.AttackTechniques
		}
		if extra.AttackTactics != "" {
			props["attack_tactics"] = extra.AttackTactics
		}
	}
	query := fmt.Sprintf(
		`MERGE (f:Finding {uid: '%s'}) SET f = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// UpsertVulnerability creates or updates a Vulnerability node.
func (gs *GraphService) UpsertVulnerability(ctx context.Context, uid, title, severity string, cvssScore float64, epssScore float64, isExploited bool) error {
	props := map[string]interface{}{
		"uid":          uid,
		"title":        title,
		"severity":     severity,
		"cvss_score":   cvssScore,
		"epss_score":   epssScore,
		"is_exploited": isExploited,
		"updated_at":   time.Now().Unix(),
	}
	query := fmt.Sprintf(
		`MERGE (v:Vulnerability {uid: '%s'}) SET v = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// UpsertIdentity creates or updates an Identity node.
func (gs *GraphService) UpsertIdentity(ctx context.Context, uid, name, identityType, provider, accountID string) error {
	props := map[string]interface{}{
		"uid":        uid,
		"name":       name,
		"type":       identityType,
		"provider":   provider,
		"account_id": accountID,
		"updated_at": time.Now().Unix(),
	}
	query := fmt.Sprintf(
		`MERGE (i:Identity {uid: '%s'}) SET i = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// UpsertNetworkPath creates or updates a NetworkPath node.
func (gs *GraphService) UpsertNetworkPath(ctx context.Context, uid, endpoint, protocol string, port int, isPublic bool) error {
	props := map[string]interface{}{
		"uid":        uid,
		"endpoint":   endpoint,
		"protocol":   protocol,
		"port":       port,
		"is_public":  isPublic,
		"updated_at": time.Now().Unix(),
	}
	query := fmt.Sprintf(
		`MERGE (n:NetworkPath {uid: '%s'}) SET n = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// UpsertAccount creates or updates an Account node.
func (gs *GraphService) UpsertAccount(ctx context.Context, uid, name, provider string) error {
	props := map[string]interface{}{
		"uid":        uid,
		"name":       name,
		"provider":   provider,
		"updated_at": time.Now().Unix(),
	}
	query := fmt.Sprintf(
		`MERGE (a:Account {uid: '%s'}) SET a = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// EdgeType represents a typed relationship in the security graph.
type EdgeType string

const (
	EdgeAFFECTS      EdgeType = "AFFECTS"
	EdgeEXPLOITS     EdgeType = "EXPLOITS"
	EdgeHAS_ACCESS   EdgeType = "HAS_ACCESS_TO"
	EdgeASSUMES      EdgeType = "ASSUMES"
	EdgeEXPOSES      EdgeType = "EXPOSES"
	EdgeBELONGS_TO   EdgeType = "BELONGS_TO"
	EdgeCONTAINS     EdgeType = "CONTAINS"
	EdgeDEPENDS_ON   EdgeType = "DEPENDS_ON"
	EdgeHAS_FINDING  EdgeType = "HAS_FINDING"
	EdgeHOSTS        EdgeType = "HOSTS"
	EdgeREMEDIATES   EdgeType = "REMEDIATES"
)

// CreateEdge creates a typed edge between two nodes identified by their UIDs.
func (gs *GraphService) CreateEdge(ctx context.Context, fromLabel, fromUID, toLabel, toUID string, edgeType EdgeType, props map[string]interface{}) error {
	propsStr := ""
	if len(props) > 0 {
		propsStr = propsJSON(props)
	} else {
		propsStr = "{}"
	}
	query := fmt.Sprintf(
		`MATCH (a:%s {uid: '%s'}), (b:%s {uid: '%s'}) MERGE (a)-[r:%s]->(b) SET r = %s`,
		fromLabel, escapeString(fromUID),
		toLabel, escapeString(toUID),
		string(edgeType), propsStr,
	)
	return gs.execCypher(ctx, query)
}

// QueryToxicCombinations executes a named pre-built Cypher query for toxic combinations.
func (gs *GraphService) QueryToxicCombinations(ctx context.Context, queryName string) ([]map[string]interface{}, error) {
	query, ok := ToxicCombinationQueries[queryName]
	if !ok {
		return nil, fmt.Errorf("unknown toxic combination query: %s", queryName)
	}

	rawRows, err := gs.queryCypher(ctx, query, "result agtype")
	if err != nil {
		return nil, fmt.Errorf("query toxic combination %s: %w", queryName, err)
	}

	var results []map[string]interface{}
	for _, raw := range rawRows {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			results = append(results, map[string]interface{}{"raw": raw})
		} else {
			results = append(results, m)
		}
	}
	return results, nil
}

// QueryFindings returns all findings ordered by severity, up to the given limit.
func (gs *GraphService) QueryFindings(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	query := fmt.Sprintf("MATCH (f:Finding) RETURN f ORDER BY f.severity_id DESC LIMIT %d", limit)
	rawRows, err := gs.queryCypher(ctx, query, "f agtype")
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	var results []map[string]interface{}
	for _, raw := range rawRows {
		props := extractVertexProperties(raw)
		if props != nil {
			results = append(results, props)
		}
	}
	return results, nil
}

// ComplianceFindingRow represents a compliance finding returned from a graph query.
type ComplianceFindingRow struct {
	UID               string `json:"uid"`
	Title             string `json:"title"`
	SeverityID        int32  `json:"severity_id"`
	Status            string `json:"status"`
	Provider          string `json:"provider"`
	ComplianceStatus  string `json:"compliance_status"`
	ComplianceControl string `json:"compliance_control"`
	ComplianceStandards string `json:"compliance_standards"`
}

// QueryComplianceFindings returns all findings that have compliance metadata.
func (gs *GraphService) QueryComplianceFindings(ctx context.Context) ([]ComplianceFindingRow, error) {
	query := `MATCH (f:Finding) WHERE f.compliance_control IS NOT NULL RETURN f`
	rawRows, err := gs.queryCypher(ctx, query, "f agtype")
	if err != nil {
		return nil, fmt.Errorf("query compliance findings: %w", err)
	}

	var results []ComplianceFindingRow
	for _, raw := range rawRows {
		props := extractVertexProperties(raw)
		if props == nil {
			continue
		}
		row := ComplianceFindingRow{}
		if v, ok := props["uid"].(string); ok {
			row.UID = v
		}
		if v, ok := props["title"].(string); ok {
			row.Title = v
		}
		if v, ok := props["severity_id"].(float64); ok {
			row.SeverityID = int32(v)
		}
		if v, ok := props["status"].(string); ok {
			row.Status = v
		}
		if v, ok := props["provider"].(string); ok {
			row.Provider = v
		}
		if v, ok := props["compliance_status"].(string); ok {
			row.ComplianceStatus = v
		}
		if v, ok := props["compliance_control"].(string); ok {
			row.ComplianceControl = v
		}
		if v, ok := props["compliance_standards"].(string); ok {
			row.ComplianceStandards = v
		}
		results = append(results, row)
	}
	return results, nil
}

// extractVertexProperties parses an AGE vertex string (e.g., `{...}::vertex`)
// and returns the properties map. Falls back to top-level keys if no properties field.
func extractVertexProperties(raw string) map[string]interface{} {
	// Strip AGE type suffix like ::vertex or ::edge
	cleaned := raw
	for _, suffix := range []string{"::vertex", "::edge"} {
		if strings.HasSuffix(cleaned, suffix) {
			cleaned = strings.TrimSuffix(cleaned, suffix)
			break
		}
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(cleaned), &m); err != nil {
		return nil
	}
	// AGE vertices have {id, label, properties} — extract properties
	if props, ok := m["properties"].(map[string]interface{}); ok {
		return props
	}
	// Fallback: treat as flat map
	return m
}

// CountNodes returns the total number of nodes with a given label.
func (gs *GraphService) CountNodes(ctx context.Context, label string) (int64, error) {
	query := fmt.Sprintf("MATCH (n:%s) RETURN count(n)", label)
	rawRows, err := gs.queryCypher(ctx, query, "cnt agtype")
	if err != nil {
		return 0, err
	}
	if len(rawRows) == 0 {
		return 0, nil
	}
	var cnt int64
	if err := json.Unmarshal([]byte(rawRows[0]), &cnt); err != nil {
		// Try parsing as string
		s := strings.TrimSpace(rawRows[0])
		if n, err2 := strconv.ParseInt(s, 10, 64); err2 == nil {
			return n, nil
		}
		return 0, fmt.Errorf("parse count: %w", err)
	}
	return cnt, nil
}

// VulnerabilityFindingRow represents a finding joined with its vulnerability data.
type VulnerabilityFindingRow struct {
	FindingUID   string  `json:"finding_uid"`
	FindingTitle string  `json:"finding_title"`
	SeverityID   int32   `json:"severity_id"`
	Status       string  `json:"status"`
	Provider     string  `json:"provider"`
	VulnUID      string  `json:"vuln_uid"`
	VulnTitle    string  `json:"vuln_title"`
	VulnSeverity string  `json:"vuln_severity"`
	CVSSScore    float64 `json:"cvss_score"`
	EPSSScore    float64 `json:"epss_score"`
	IsExploited  bool    `json:"is_exploited"`
}

// QueryVulnerabilityFindings returns all findings linked to vulnerabilities via EXPLOITS edges.
func (gs *GraphService) QueryVulnerabilityFindings(ctx context.Context) ([]VulnerabilityFindingRow, error) {
	query := `MATCH (f:Finding)-[:EXPLOITS]->(v:Vulnerability) RETURN f, v`
	rawRows, err := gs.queryCypher2(ctx, query, "f agtype, v agtype")
	if err != nil {
		return nil, fmt.Errorf("query vulnerability findings: %w", err)
	}

	var results []VulnerabilityFindingRow
	for _, pair := range rawRows {
		fProps := extractVertexProperties(pair[0])
		vProps := extractVertexProperties(pair[1])
		if fProps == nil || vProps == nil {
			continue
		}
		row := VulnerabilityFindingRow{}
		if v, ok := fProps["uid"].(string); ok {
			row.FindingUID = v
		}
		if v, ok := fProps["title"].(string); ok {
			row.FindingTitle = v
		}
		if v, ok := fProps["severity_id"].(float64); ok {
			row.SeverityID = int32(v)
		}
		if v, ok := fProps["status"].(string); ok {
			row.Status = v
		}
		if v, ok := fProps["provider"].(string); ok {
			row.Provider = v
		}
		if v, ok := vProps["uid"].(string); ok {
			row.VulnUID = v
		}
		if v, ok := vProps["title"].(string); ok {
			row.VulnTitle = v
		}
		if v, ok := vProps["severity"].(string); ok {
			row.VulnSeverity = v
		}
		if v, ok := vProps["cvss_score"].(float64); ok {
			row.CVSSScore = v
		}
		if v, ok := vProps["epss_score"].(float64); ok {
			row.EPSSScore = v
		}
		if v, ok := vProps["is_exploited"].(bool); ok {
			row.IsExploited = v
		}
		results = append(results, row)
	}
	return results, nil
}

// AttackFindingRow represents a finding that has ATT&CK technique/tactic data.
type AttackFindingRow struct {
	UID              string `json:"uid"`
	Title            string `json:"title"`
	SeverityID       int32  `json:"severity_id"`
	Status           string `json:"status"`
	Provider         string `json:"provider"`
	AttackTechniques string `json:"attack_techniques"`
	AttackTactics    string `json:"attack_tactics"`
}

// QueryFindingsWithAttacks returns all findings that have ATT&CK technique annotations.
func (gs *GraphService) QueryFindingsWithAttacks(ctx context.Context) ([]AttackFindingRow, error) {
	query := `MATCH (f:Finding) WHERE f.attack_techniques IS NOT NULL RETURN f`
	rawRows, err := gs.queryCypher(ctx, query, "f agtype")
	if err != nil {
		return nil, fmt.Errorf("query findings with attacks: %w", err)
	}

	var results []AttackFindingRow
	for _, raw := range rawRows {
		props := extractVertexProperties(raw)
		if props == nil {
			continue
		}
		row := AttackFindingRow{}
		if v, ok := props["uid"].(string); ok {
			row.UID = v
		}
		if v, ok := props["title"].(string); ok {
			row.Title = v
		}
		if v, ok := props["severity_id"].(float64); ok {
			row.SeverityID = int32(v)
		}
		if v, ok := props["status"].(string); ok {
			row.Status = v
		}
		if v, ok := props["provider"].(string); ok {
			row.Provider = v
		}
		if v, ok := props["attack_techniques"].(string); ok {
			row.AttackTechniques = v
		}
		if v, ok := props["attack_tactics"].(string); ok {
			row.AttackTactics = v
		}
		results = append(results, row)
	}
	return results, nil
}

// ExposedResourceRow represents a resource exposed through a public network path.
type ExposedResourceRow struct {
	ResourceUID  string `json:"resource_uid"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Provider     string `json:"provider"`
	Endpoint     string `json:"endpoint"`
	Protocol     string `json:"protocol"`
	Port         int    `json:"port"`
	IsPublic     bool   `json:"is_public"`
}

// QueryExposedResources returns resources linked to public network paths via EXPOSES edges.
func (gs *GraphService) QueryExposedResources(ctx context.Context) ([]ExposedResourceRow, error) {
	query := `MATCH (r:Resource)-[:EXPOSES]->(n:NetworkPath {is_public: true}) RETURN r, n`
	rawRows, err := gs.queryCypher2(ctx, query, "r agtype, n agtype")
	if err != nil {
		return nil, fmt.Errorf("query exposed resources: %w", err)
	}

	var results []ExposedResourceRow
	for _, pair := range rawRows {
		rProps := extractVertexProperties(pair[0])
		nProps := extractVertexProperties(pair[1])
		if rProps == nil || nProps == nil {
			continue
		}
		row := ExposedResourceRow{IsPublic: true}
		if v, ok := rProps["uid"].(string); ok {
			row.ResourceUID = v
		}
		if v, ok := rProps["type"].(string); ok {
			row.ResourceType = v
		}
		if v, ok := rProps["name"].(string); ok {
			row.ResourceName = v
		}
		if v, ok := rProps["provider"].(string); ok {
			row.Provider = v
		}
		if v, ok := nProps["endpoint"].(string); ok {
			row.Endpoint = v
		}
		if v, ok := nProps["protocol"].(string); ok {
			row.Protocol = v
		}
		if v, ok := nProps["port"].(float64); ok {
			row.Port = int(v)
		}
		results = append(results, row)
	}
	return results, nil
}
