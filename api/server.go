// Package api provides the REST API server for the Cloud Security Fabric dashboard.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cloud-security-fabric/csf/internal/graph"
	"github.com/cloud-security-fabric/csf/internal/settings"
	"github.com/cloud-security-fabric/csf/policy"
	"github.com/cloud-security-fabric/csf/scoring"
)

// Server is the CSF REST API server.
type Server struct {
	graphService  *graph.GraphService
	policyEngine  *policy.Engine
	scoringEngine *scoring.Engine
	settingsStore *settings.FileStore
	httpServer    *http.Server
}

// NewServer creates a new API server.
func NewServer(gs *graph.GraphService, pe *policy.Engine, se *scoring.Engine, ss *settings.FileStore) *Server {
	s := &Server{
		graphService:  gs,
		policyEngine:  pe,
		scoringEngine: se,
		settingsStore: ss,
	}
	return s
}

// Start begins listening on the given address.
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      corsMiddleware(loggingMiddleware(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/findings", s.handleListFindings)
	mux.HandleFunc("GET /api/v1/risk/toxic-combinations", s.handleToxicCombinations)
	mux.HandleFunc("GET /api/v1/risk/toxic-combinations/{name}", s.handleToxicCombination)
	mux.HandleFunc("GET /api/v1/connectors/status", s.handleConnectorStatus)
	mux.HandleFunc("POST /api/v1/policies/evaluate", s.handleEvaluatePolicy)
	mux.HandleFunc("GET /api/v1/policies", s.handleListPolicies)
	mux.HandleFunc("GET /api/v1/graph/stats", s.handleGraphStats)

	// Settings / connector configuration
	mux.HandleFunc("GET /api/v1/settings/connectors", s.handleGetConnectors)
	mux.HandleFunc("PUT /api/v1/settings/connectors", s.handleUpdateConnectors)
	mux.HandleFunc("PUT /api/v1/settings/connectors/{provider}/secrets", s.handleUpdateSecrets)
	mux.HandleFunc("POST /api/v1/settings/connectors/{provider}/test", s.handleTestConnection)
	mux.HandleFunc("POST /api/v1/settings/apply", s.handleApplySettings)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	query := fmt.Sprintf("MATCH (f:Finding) RETURN f ORDER BY f.severity_id DESC LIMIT %d", limit)
	rows, err := s.graphService.DB().QueryContext(r.Context(),
		fmt.Sprintf(`SELECT * FROM cypher('security_fabric', $$ %s $$) as (f agtype)`, query))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var findings []json.RawMessage
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		findings = append(findings, json.RawMessage(raw))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) handleToxicCombinations(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(graph.ToxicCombinationQueries))
	for name := range graph.ToxicCombinationQueries {
		names = append(names, name)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"toxic_combinations": names,
		"count":              len(names),
	})
}

func (s *Server) handleToxicCombination(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	results, err := s.graphService.QueryToxicCombinations(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":    name,
		"results": results,
		"count":   len(results),
	})
}

func (s *Server) handleConnectorStatus(w http.ResponseWriter, r *http.Request) {
	// Proxy to the collector's health check
	resp, err := http.Get("http://localhost:55679/debug/servicez")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"collector": "unreachable",
			"error":     err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"collector": "healthy",
		"status":    resp.StatusCode,
	})
}

func (s *Server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var finding map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	result, err := s.policyEngine.Evaluate(r.Context(), finding)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.policyEngine.ListPolicies()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	})
}

func (s *Server) handleGraphStats(w http.ResponseWriter, r *http.Request) {
	labels := []string{"Finding", "Resource", "Vulnerability", "Identity", "Account"}
	stats := make(map[string]int64)
	for _, label := range labels {
		count, err := s.graphService.CountNodes(r.Context(), label)
		if err != nil {
			stats[label] = -1
		} else {
			stats[label] = count
		}
	}
	writeJSON(w, http.StatusOK, stats)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
