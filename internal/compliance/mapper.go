package compliance

import (
	"strings"

	"github.com/cloud-security-fabric/csf/internal/graph"
)

// PostureStatus counts for a single control, category, function, or framework.
type PostureStatus struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

// Score returns a 0-100 compliance score. Returns -1 if no data.
func (ps PostureStatus) Score() float64 {
	total := ps.Pass + ps.Fail + ps.Unknown
	if total == 0 {
		return -1
	}
	return float64(ps.Pass) / float64(total) * 100
}

// ControlPosture is the posture for a single framework control.
type ControlPosture struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Status   PostureStatus `json:"status"`
	Findings []FindingRef  `json:"findings,omitempty"`
}

// FindingRef is a minimal reference to a graph finding.
type FindingRef struct {
	UID              string `json:"uid"`
	Title            string `json:"title"`
	SeverityID       int32  `json:"severity_id"`
	ComplianceStatus string `json:"compliance_status"`
	Provider         string `json:"provider"`
}

// CategoryPosture is the posture for a category containing controls.
type CategoryPosture struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Status   PostureStatus    `json:"status"`
	Controls []ControlPosture `json:"controls"`
}

// FunctionPosture is the posture for a top-level function.
type FunctionPosture struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Status     PostureStatus     `json:"status"`
	Categories []CategoryPosture `json:"categories"`
}

// FrameworkPosture is the full posture for a framework.
type FrameworkPosture struct {
	FrameworkID string            `json:"framework_id"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Score       float64           `json:"score"`
	Status      PostureStatus     `json:"status"`
	Functions   []FunctionPosture `json:"functions"`
}

// FrameworkSummary is a compact summary for the dashboard overview.
type FrameworkSummary struct {
	FrameworkID string        `json:"framework_id"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Score       float64       `json:"score"`
	Status      PostureStatus `json:"status"`
}

// ComputePosture builds the full compliance posture for a framework given graph findings.
func ComputePosture(fw *Framework, findings []graph.ComplianceFindingRow) *FrameworkPosture {
	// Build index: cloud control ID -> findings
	controlFindings := indexFindings(findings)

	posture := &FrameworkPosture{
		FrameworkID: fw.ID,
		Name:        fw.Name,
		Version:     fw.Version,
	}

	for _, fn := range fw.Functions {
		fp := FunctionPosture{ID: fn.ID, Name: fn.Name}
		for _, cat := range fn.Categories {
			cp := CategoryPosture{ID: cat.ID, Name: cat.Name}
			for _, ctrl := range cat.Controls {
				ctrlPosture := computeControlPosture(ctrl, controlFindings)
				cp.Controls = append(cp.Controls, ctrlPosture)
				cp.Status.Pass += ctrlPosture.Status.Pass
				cp.Status.Fail += ctrlPosture.Status.Fail
				cp.Status.Unknown += ctrlPosture.Status.Unknown
			}
			fp.Categories = append(fp.Categories, cp)
			fp.Status.Pass += cp.Status.Pass
			fp.Status.Fail += cp.Status.Fail
			fp.Status.Unknown += cp.Status.Unknown
		}
		posture.Functions = append(posture.Functions, fp)
		posture.Status.Pass += fp.Status.Pass
		posture.Status.Fail += fp.Status.Fail
		posture.Status.Unknown += fp.Status.Unknown
	}

	posture.Score = posture.Status.Score()
	return posture
}

// computeControlPosture computes posture for a single control from matching findings.
func computeControlPosture(ctrl Control, controlFindings map[string][]graph.ComplianceFindingRow) ControlPosture {
	cp := ControlPosture{ID: ctrl.ID, Name: ctrl.Name}

	// Collect all findings matching this control's cloud control IDs.
	seen := make(map[string]bool)
	allCloudIDs := append(append(ctrl.AWSControls, ctrl.GCPControls...), ctrl.AzureControls...)
	for _, cloudID := range allCloudIDs {
		for _, f := range controlFindings[strings.ToUpper(cloudID)] {
			if seen[f.UID] {
				continue
			}
			seen[f.UID] = true

			ref := FindingRef{
				UID:              f.UID,
				Title:            f.Title,
				SeverityID:       f.SeverityID,
				ComplianceStatus: f.ComplianceStatus,
				Provider:         f.Provider,
			}
			cp.Findings = append(cp.Findings, ref)

			switch classifyComplianceStatus(f.ComplianceStatus) {
			case "pass":
				cp.Status.Pass++
			case "fail":
				cp.Status.Fail++
			default:
				cp.Status.Unknown++
			}
		}
	}

	return cp
}

// indexFindings groups findings by their compliance_control field (uppercased).
func indexFindings(findings []graph.ComplianceFindingRow) map[string][]graph.ComplianceFindingRow {
	idx := make(map[string][]graph.ComplianceFindingRow)
	for _, f := range findings {
		if f.ComplianceControl != "" {
			key := strings.ToUpper(f.ComplianceControl)
			idx[key] = append(idx[key], f)
		}
	}
	return idx
}

// classifyComplianceStatus normalizes compliance status strings to pass/fail/unknown.
func classifyComplianceStatus(status string) string {
	switch strings.ToLower(status) {
	case "pass", "passed", "compliant":
		return "pass"
	case "fail", "failed", "non_compliant", "not_available":
		return "fail"
	default:
		return "unknown"
	}
}
