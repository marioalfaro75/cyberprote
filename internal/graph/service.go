// Package graph provides the GraphService for interacting with the Apache AGE
// graph database that stores the Cloud Security Fabric security graph.
package graph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
func (gs *GraphService) execCypher(ctx context.Context, query string) error {
	stmt := fmt.Sprintf(
		`SELECT * FROM cypher('%s', $$ %s $$) as (result agtype)`,
		gs.graphName, query,
	)
	_, err := gs.db.ExecContext(ctx, stmt)
	return err
}

// queryCypher runs a Cypher query and returns rows.
func (gs *GraphService) queryCypher(ctx context.Context, query string, returnCols string) (*sql.Rows, error) {
	stmt := fmt.Sprintf(
		`SELECT * FROM cypher('%s', $$ %s $$) as (%s)`,
		gs.graphName, query, returnCols,
	)
	return gs.db.QueryContext(ctx, stmt)
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
	ComplianceStatus   string
	ComplianceControl  string
	ComplianceStandards string // comma-separated
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
	}
	query := fmt.Sprintf(
		`MERGE (f:Finding {uid: '%s'}) SET f = %s`,
		escapeString(uid), propsJSON(props),
	)
	return gs.execCypher(ctx, query)
}

// UpsertVulnerability creates or updates a Vulnerability node.
func (gs *GraphService) UpsertVulnerability(ctx context.Context, uid, title, severity string, cvssScore float64) error {
	props := map[string]interface{}{
		"uid":        uid,
		"title":      title,
		"severity":   severity,
		"cvss_score": cvssScore,
		"updated_at": time.Now().Unix(),
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

	rows, err := gs.queryCypher(ctx, query, "result agtype")
	if err != nil {
		return nil, fmt.Errorf("query toxic combination %s: %w", queryName, err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			results = append(results, map[string]interface{}{"raw": raw})
		} else {
			results = append(results, m)
		}
	}
	return results, rows.Err()
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
	rows, err := gs.queryCypher(ctx, query, "f agtype")
	if err != nil {
		return nil, fmt.Errorf("query compliance findings: %w", err)
	}
	defer rows.Close()

	var results []ComplianceFindingRow
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue
		}
		row := ComplianceFindingRow{}
		if v, ok := m["uid"].(string); ok {
			row.UID = v
		}
		if v, ok := m["title"].(string); ok {
			row.Title = v
		}
		if v, ok := m["severity_id"].(float64); ok {
			row.SeverityID = int32(v)
		}
		if v, ok := m["status"].(string); ok {
			row.Status = v
		}
		if v, ok := m["provider"].(string); ok {
			row.Provider = v
		}
		if v, ok := m["compliance_status"].(string); ok {
			row.ComplianceStatus = v
		}
		if v, ok := m["compliance_control"].(string); ok {
			row.ComplianceControl = v
		}
		if v, ok := m["compliance_standards"].(string); ok {
			row.ComplianceStandards = v
		}
		results = append(results, row)
	}
	return results, rows.Err()
}

// CountNodes returns the total number of nodes with a given label.
func (gs *GraphService) CountNodes(ctx context.Context, label string) (int64, error) {
	query := fmt.Sprintf("MATCH (n:%s) RETURN count(n)", label)
	rows, err := gs.queryCypher(ctx, query, "cnt agtype")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	if rows.Next() {
		var cnt int64
		if err := rows.Scan(&cnt); err != nil {
			return 0, err
		}
		return cnt, nil
	}
	return 0, nil
}
