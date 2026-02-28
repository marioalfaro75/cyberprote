package githubghasreceiver

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-github/v60/github"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// MapCodeScanningToOCSF maps a GitHub code scanning alert to OCSF VulnerabilityFinding (2002).
func MapCodeScanningToOCSF(alert *github.Alert, owner, repo string) ([]byte, error) {
	sevID, sevLabel := mapCodeScanningSeverity(alert)

	f := ocsf.VulnerabilityFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ocsf.ClassVulnerabilityFind,
		SeverityID:  sevID,
		Severity:    sevLabel,
		StatusID:    ocsf.StatusNew,
		Status:      "New",
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       "CodeQL",
				VendorName: "GitHub",
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:   fmt.Sprintf("github/%s/%s/code-scanning/%d", owner, repo, alert.GetNumber()),
			Title: alert.GetRule().GetDescription(),
		},
		Resources: []ocsf.Resource{
			{
				UID:  fmt.Sprintf("github.com/%s/%s", owner, repo),
				Type: "CodeRepository",
				Name: repo,
			},
		},
	}

	// Map rule info to vulnerability
	if alert.GetRule() != nil {
		vuln := ocsf.Vulnerability{
			UID:   alert.GetRule().GetID(),
			Title: alert.GetRule().GetDescription(),
		}
		if alert.GetMostRecentInstance() != nil {
			loc := alert.GetMostRecentInstance().GetLocation()
			if loc != nil {
				vuln.AffectedCode = []ocsf.AffectedCode{
					{
						FilePath:  loc.GetPath(),
						StartLine: loc.GetStartLine(),
						EndLine:   loc.GetEndLine(),
					},
				}
			}
		}
		f.Vulnerabilities = append(f.Vulnerabilities, vuln)
	}

	if alert.GetMostRecentInstance() != nil {
		f.Message = alert.GetMostRecentInstance().GetMessage().GetText()
	}

	return json.Marshal(&f)
}

func mapCodeScanningSeverity(alert *github.Alert) (int32, string) {
	severity := ""
	if alert.GetRule() != nil {
		severity = alert.GetRule().GetSeverity()
	}
	switch severity {
	case "error":
		return ocsf.SeverityHigh, "High"
	case "warning":
		return ocsf.SeverityMedium, "Medium"
	case "note":
		return ocsf.SeverityLow, "Low"
	default:
		return ocsf.SeverityInformational, "Informational"
	}
}
