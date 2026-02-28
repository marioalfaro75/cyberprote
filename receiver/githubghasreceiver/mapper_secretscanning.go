package githubghasreceiver

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-github/v60/github"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// MapSecretScanningToOCSF maps a GitHub secret scanning alert to OCSF SecurityFinding (2001).
func MapSecretScanningToOCSF(alert *github.SecretScanningAlert, owner, repo string) ([]byte, error) {
	f := ocsf.SecurityFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ocsf.ClassSecurityFinding,
		SeverityID:  ocsf.SeverityHigh,
		Severity:    "High",
		StatusID:    ocsf.StatusNew,
		Status:      "New",
		Message:     fmt.Sprintf("Secret of type %s detected in repository", alert.GetSecretType()),
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       "Secret Scanning",
				VendorName: "GitHub",
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:   fmt.Sprintf("github/%s/%s/secret-scanning/%d", owner, repo, alert.GetNumber()),
			Title: fmt.Sprintf("Exposed %s secret detected", alert.GetSecretTypeDisplayName()),
		},
		Resources: []ocsf.Resource{
			{
				UID:  fmt.Sprintf("github.com/%s/%s", owner, repo),
				Type: "CodeRepository",
				Name: repo,
			},
		},
		Unmapped: map[string]interface{}{
			"secret_type":              alert.GetSecretType(),
			"secret_type_display_name": alert.GetSecretTypeDisplayName(),
			"push_protection_bypassed": alert.GetPushProtectionBypassed(),
		},
	}

	if alert.GetCreatedAt() != (github.Timestamp{}) {
		f.Time = ocsf.NewTime(alert.GetCreatedAt().Time)
		f.FindingInfo.CreatedTime = ocsf.NewTime(alert.GetCreatedAt().Time)
	}

	if alert.GetHTMLURL() != "" {
		f.FindingInfo.SrcURL = alert.GetHTMLURL()
	}

	return json.Marshal(&f)
}
