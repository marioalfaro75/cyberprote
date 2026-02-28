package api

import (
	"net/http"

	"github.com/cloud-security-fabric/csf/internal/compliance"
)

func (s *Server) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"frameworks": []interface{}{}, "count": 0})
		return
	}
	type frameworkInfo struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	fws := make([]frameworkInfo, 0, len(s.catalog.Frameworks))
	for _, fw := range s.catalog.Frameworks {
		fws = append(fws, frameworkInfo{ID: fw.ID, Name: fw.Name, Version: fw.Version})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"frameworks": fws,
		"count":      len(fws),
	})
}

func (s *Server) handleFrameworkPosture(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no catalog loaded"})
		return
	}

	fwID := r.PathValue("id")
	fw := s.catalog.GetFramework(fwID)
	if fw == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "framework not found"})
		return
	}

	findings, err := s.graphService.QueryComplianceFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	posture := compliance.ComputePosture(fw, findings)
	writeJSON(w, http.StatusOK, posture)
}

func (s *Server) handleControlFindings(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no catalog loaded"})
		return
	}

	fwID := r.PathValue("id")
	controlID := r.PathValue("controlId")
	fw := s.catalog.GetFramework(fwID)
	if fw == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "framework not found"})
		return
	}

	// Find the control in the framework
	var ctrl *compliance.Control
	for _, fn := range fw.Functions {
		for _, cat := range fn.Categories {
			for i := range cat.Controls {
				if cat.Controls[i].ID == controlID {
					ctrl = &cat.Controls[i]
					break
				}
			}
		}
	}
	if ctrl == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "control not found"})
		return
	}

	findings, err := s.graphService.QueryComplianceFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	posture := compliance.ComputePosture(fw, findings)

	// Find the control in the posture result
	for _, fn := range posture.Functions {
		for _, cat := range fn.Categories {
			for _, cp := range cat.Controls {
				if cp.ID == controlID {
					writeJSON(w, http.StatusOK, map[string]interface{}{
						"control":  cp,
						"findings": cp.Findings,
						"count":    len(cp.Findings),
					})
					return
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"control":  map[string]string{"id": ctrl.ID, "name": ctrl.Name},
		"findings": []interface{}{},
		"count":    0,
	})
}

func (s *Server) handleComplianceSummary(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"summaries": []interface{}{}, "count": 0})
		return
	}

	findings, err := s.graphService.QueryComplianceFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	summaries := make([]compliance.FrameworkSummary, 0, len(s.catalog.Frameworks))
	for _, fw := range s.catalog.Frameworks {
		posture := compliance.ComputePosture(&fw, findings)
		summaries = append(summaries, compliance.FrameworkSummary{
			FrameworkID: posture.FrameworkID,
			Name:        posture.Name,
			Version:     posture.Version,
			Score:       posture.Score,
			Status:      posture.Status,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"summaries": summaries,
		"count":     len(summaries),
	})
}
