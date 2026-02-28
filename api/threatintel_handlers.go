package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/cloud-security-fabric/csf/internal/graph"
)

func (s *Server) handleThreatIntelOverview(w http.ResponseWriter, r *http.Request) {
	vulnFindings, err := s.graphService.QueryVulnerabilityFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	exposedResources, err := s.graphService.QueryExposedResources(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	cveSet := make(map[string]bool)
	kevCount := 0
	totalEPSS := 0.0
	sevDist := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

	for _, vf := range vulnFindings {
		cveSet[vf.VulnUID] = true
		if vf.IsExploited {
			kevCount++
		}
		totalEPSS += vf.EPSSScore
		switch {
		case vf.SeverityID >= 5:
			sevDist["critical"]++
		case vf.SeverityID == 4:
			sevDist["high"]++
		case vf.SeverityID == 3:
			sevDist["medium"]++
		case vf.SeverityID == 2:
			sevDist["low"]++
		default:
			sevDist["informational"]++
		}
	}

	avgEPSS := 0.0
	if len(vulnFindings) > 0 {
		avgEPSS = totalEPSS / float64(len(vulnFindings))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_cves":            len(cveSet),
		"kev_count":             kevCount,
		"avg_epss":              avgEPSS,
		"exposure_count":        len(exposedResources),
		"severity_distribution": sevDist,
	})
}

func (s *Server) handleKEVFindings(w http.ResponseWriter, r *http.Request) {
	vulnFindings, err := s.graphService.QueryVulnerabilityFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var kevFindings []graph.VulnerabilityFindingRow
	for _, vf := range vulnFindings {
		if vf.IsExploited {
			kevFindings = append(kevFindings, vf)
		}
	}

	sort.Slice(kevFindings, func(i, j int) bool {
		return kevFindings[i].SeverityID > kevFindings[j].SeverityID
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"findings": kevFindings,
		"count":    len(kevFindings),
	})
}

func (s *Server) handleEPSSFindings(w http.ResponseWriter, r *http.Request) {
	threshold := 0.5
	if t := r.URL.Query().Get("threshold"); t != "" {
		if v, err := strconv.ParseFloat(t, 64); err == nil && v >= 0 && v <= 1 {
			threshold = v
		}
	}

	vulnFindings, err := s.graphService.QueryVulnerabilityFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var filtered []graph.VulnerabilityFindingRow
	for _, vf := range vulnFindings {
		if vf.EPSSScore >= threshold {
			filtered = append(filtered, vf)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].EPSSScore > filtered[j].EPSSScore
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"findings":  filtered,
		"count":     len(filtered),
		"threshold": threshold,
	})
}

func (s *Server) handleAttackMatrix(w http.ResponseWriter, r *http.Request) {
	attackFindings, err := s.graphService.QueryFindingsWithAttacks(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Count findings per technique and tactic
	techniqueCounts := make(map[string]int)
	tacticCounts := make(map[string]int)
	for _, af := range attackFindings {
		for _, t := range strings.Split(af.AttackTechniques, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				techniqueCounts[t]++
			}
		}
		for _, t := range strings.Split(af.AttackTactics, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tacticCounts[t]++
			}
		}
	}

	if s.attackMatrix == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"tactics":          []interface{}{},
			"technique_counts": techniqueCounts,
			"tactic_counts":    tacticCounts,
		})
		return
	}

	type techniqueWithCount struct {
		UID          string `json:"uid"`
		Name         string `json:"name"`
		FindingCount int    `json:"finding_count"`
	}
	type tacticWithCoverage struct {
		UID          string               `json:"uid"`
		Name         string               `json:"name"`
		FindingCount int                   `json:"finding_count"`
		Techniques   []techniqueWithCount  `json:"techniques"`
	}

	var tactics []tacticWithCoverage
	for _, tac := range s.attackMatrix.AllTactics() {
		tc := tacticWithCoverage{
			UID:          tac.UID,
			Name:         tac.Name,
			FindingCount: tacticCounts[tac.UID],
		}
		for _, tech := range tac.Techniques {
			tc.Techniques = append(tc.Techniques, techniqueWithCount{
				UID:          tech.UID,
				Name:         tech.Name,
				FindingCount: techniqueCounts[tech.UID],
			})
		}
		tactics = append(tactics, tc)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tactics": tactics,
		"count":   len(tactics),
	})
}

func (s *Server) handleCVEInventory(w http.ResponseWriter, r *http.Request) {
	vulnFindings, err := s.graphService.QueryVulnerabilityFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type cveEntry struct {
		CVEID       string  `json:"cve_id"`
		CVSSScore   float64 `json:"cvss_score"`
		EPSSScore   float64 `json:"epss_score"`
		IsExploited bool    `json:"is_exploited"`
		Severity    string  `json:"severity"`
		Title       string  `json:"title"`
		AffectedCount int  `json:"affected_count"`
	}

	cveMap := make(map[string]*cveEntry)
	for _, vf := range vulnFindings {
		if existing, ok := cveMap[vf.VulnUID]; ok {
			existing.AffectedCount++
		} else {
			cveMap[vf.VulnUID] = &cveEntry{
				CVEID:         vf.VulnUID,
				CVSSScore:     vf.CVSSScore,
				EPSSScore:     vf.EPSSScore,
				IsExploited:   vf.IsExploited,
				Severity:      vf.VulnSeverity,
				Title:         vf.VulnTitle,
				AffectedCount: 1,
			}
		}
	}

	cves := make([]cveEntry, 0, len(cveMap))
	for _, entry := range cveMap {
		cves = append(cves, *entry)
	}
	sort.Slice(cves, func(i, j int) bool {
		return cves[i].CVSSScore > cves[j].CVSSScore
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cves":  cves,
		"count": len(cves),
	})
}

func (s *Server) handleExposure(w http.ResponseWriter, r *http.Request) {
	exposed, err := s.graphService.QueryExposedResources(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"resources": exposed,
		"count":     len(exposed),
	})
}
