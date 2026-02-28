package githubghasreceiver

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-github/v60/github"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// MapDependabotToOCSF maps a GitHub Dependabot alert to OCSF VulnerabilityFinding (2002).
func MapDependabotToOCSF(alert *github.DependabotAlert, owner, repo string) ([]byte, error) {
	sevID, sevLabel := mapDependabotSeverity(alert)

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
				Name:       "Dependabot",
				VendorName: "GitHub",
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:   fmt.Sprintf("github/%s/%s/dependabot/%d", owner, repo, alert.GetNumber()),
			Title: alert.GetSecurityAdvisory().GetSummary(),
		},
		Resources: []ocsf.Resource{
			{
				UID:  fmt.Sprintf("github.com/%s/%s", owner, repo),
				Type: "CodeRepository",
				Name: repo,
			},
		},
	}

	if alert.GetSecurityAdvisory() != nil {
		advisory := alert.GetSecurityAdvisory()
		f.Message = advisory.GetDescription()

		vuln := ocsf.Vulnerability{
			UID:        advisory.GetGHSAID(),
			Title:      advisory.GetSummary(),
			VendorName: "GitHub",
		}

		// Map CVEs
		if len(advisory.Identifiers) > 0 {
			for _, id := range advisory.Identifiers {
				if id.GetType() == "CVE" {
					vuln.CVE = &ocsf.CVE{UID: id.GetValue()}
					break
				}
			}
		}

		// Map CVSS
		if advisory.GetCVSS() != nil {
			score := advisory.GetCVSS().GetScore()
			if score != nil && *score > 0 {
				cvss := ocsf.CVSS{
					BaseScore:    *score,
					VectorString: advisory.GetCVSS().GetVectorString(),
				}
				if vuln.CVE != nil {
					vuln.CVE.CVSS = append(vuln.CVE.CVSS, cvss)
				}
			}
		}

		// Map package info
		if alert.GetDependency() != nil && alert.GetDependency().GetPackage() != nil {
			pkg := alert.GetDependency().GetPackage()
			vuln.Packages = []ocsf.Package{
				{
					Name:    pkg.GetName(),
					Type:    pkg.GetEcosystem(),
				},
			}
			if alert.GetDependency().GetManifestPath() != "" {
				vuln.AffectedCode = []ocsf.AffectedCode{
					{FilePath: alert.GetDependency().GetManifestPath()},
				}
			}
		}

		// Check for fix
		if !alert.GetFixedAt().IsZero() {
			fixed := true
			vuln.FixAvailable = &fixed
		}

		f.Vulnerabilities = append(f.Vulnerabilities, vuln)
	}

	return json.Marshal(&f)
}

func mapDependabotSeverity(alert *github.DependabotAlert) (int32, string) {
	severity := ""
	if alert.GetSecurityAdvisory() != nil {
		severity = alert.GetSecurityAdvisory().GetSeverity()
	}
	switch severity {
	case "critical":
		return ocsf.SeverityCritical, "Critical"
	case "high":
		return ocsf.SeverityHigh, "High"
	case "medium":
		return ocsf.SeverityMedium, "Medium"
	case "low":
		return ocsf.SeverityLow, "Low"
	default:
		return ocsf.SeverityUnknown, "Unknown"
	}
}
