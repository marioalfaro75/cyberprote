package awssechubreceiver

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// MapASSFToOCSF converts an AWS Security Finding Format (ASFF) finding to OCSF JSON.
func MapASSFToOCSF(finding *shtypes.AwsSecurityFinding) ([]byte, error) {
	classUID := determineClassUID(finding)

	switch classUID {
	case ocsf.ClassVulnerabilityFind:
		return mapToVulnerabilityFinding(finding)
	case ocsf.ClassComplianceFinding:
		return mapToComplianceFinding(finding)
	case ocsf.ClassDetectionFinding:
		return mapToDetectionFinding(finding)
	default:
		return mapToSecurityFinding(finding)
	}
}

// determineClassUID inspects the ASFF finding to determine the appropriate OCSF class.
func determineClassUID(finding *shtypes.AwsSecurityFinding) int32 {
	// Check product name first for known vulnerability scanners
	if finding.ProductName != nil {
		pn := strings.ToLower(aws.ToString(finding.ProductName))
		if pn == "inspector" || pn == "amazon inspector" {
			return ocsf.ClassVulnerabilityFind
		}
	}

	// Check finding types for classification
	hasVuln := false
	hasCompliance := false
	hasDetection := false

	for _, ft := range finding.Types {
		ftLower := strings.ToLower(ft)
		if strings.Contains(ftLower, "vulnerabilities") || strings.Contains(ftLower, "cve") {
			hasVuln = true
		}
		if strings.Contains(ftLower, "software and configuration checks") {
			hasCompliance = true
		}
		if strings.Contains(ftLower, "tactic") || strings.Contains(ftLower, "ttps") {
			hasDetection = true
		}
	}

	// Vulnerabilities take priority over compliance
	if hasVuln {
		return ocsf.ClassVulnerabilityFind
	}
	if hasDetection {
		return ocsf.ClassDetectionFinding
	}
	if hasCompliance {
		return ocsf.ClassComplianceFinding
	}

	return ocsf.ClassSecurityFinding
}

// mapSeverity converts ASFF severity to OCSF severity_id.
func mapSeverity(sev *shtypes.Severity) (int32, string) {
	if sev == nil {
		return ocsf.SeverityUnknown, "Unknown"
	}
	switch sev.Label {
	case shtypes.SeverityLabelInformational:
		return ocsf.SeverityInformational, "Informational"
	case shtypes.SeverityLabelLow:
		return ocsf.SeverityLow, "Low"
	case shtypes.SeverityLabelMedium:
		return ocsf.SeverityMedium, "Medium"
	case shtypes.SeverityLabelHigh:
		return ocsf.SeverityHigh, "High"
	case shtypes.SeverityLabelCritical:
		return ocsf.SeverityCritical, "Critical"
	default:
		return ocsf.SeverityUnknown, "Unknown"
	}
}

// mapResources converts ASFF resources to OCSF resources.
func mapResources(resources []shtypes.Resource) []ocsf.Resource {
	var result []ocsf.Resource
	for _, r := range resources {
		res := ocsf.Resource{
			UID:  aws.ToString(r.Id),
			Type: aws.ToString(r.Type),
		}
		if r.Region != nil {
			res.Region = aws.ToString(r.Region)
			res.Cloud = &ocsf.Cloud{
				Provider: "aws",
				Region:   aws.ToString(r.Region),
			}
		}
		if r.Partition != "" {
			if res.Cloud == nil {
				res.Cloud = &ocsf.Cloud{Provider: "aws"}
			}
		}
		result = append(result, res)
	}
	return result
}

// parseTime parses an ASFF timestamp string.
func parseTime(s *string) *ocsf.Time {
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, aws.ToString(s))
	if err != nil {
		return nil
	}
	return ocsf.NewTime(t)
}

// mapStatus converts ASFF workflow status to OCSF status.
func mapStatus(finding *shtypes.AwsSecurityFinding) (int32, string) {
	if finding.Workflow != nil {
		switch finding.Workflow.Status {
		case shtypes.WorkflowStatusNew:
			return ocsf.StatusNew, "New"
		case shtypes.WorkflowStatusNotified:
			return ocsf.StatusInProgress, "In Progress"
		case shtypes.WorkflowStatusResolved:
			return ocsf.StatusResolved, "Resolved"
		case shtypes.WorkflowStatusSuppressed:
			return ocsf.StatusSuppressed, "Suppressed"
		}
	}
	return ocsf.StatusNew, "New"
}

func mapToSecurityFinding(finding *shtypes.AwsSecurityFinding) ([]byte, error) {
	sevID, sevLabel := mapSeverity(finding.Severity)
	statusID, status := mapStatus(finding)

	f := ocsf.SecurityFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ocsf.ClassSecurityFinding,
		SeverityID:  sevID,
		Severity:    sevLabel,
		StatusID:    statusID,
		Status:      status,
		Message:     aws.ToString(finding.Description),
		Time:        parseTime(finding.UpdatedAt),
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       aws.ToString(finding.ProductName),
				VendorName: "AWS",
				UID:        aws.ToString(finding.ProductArn),
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:           aws.ToString(finding.Id),
			Title:         aws.ToString(finding.Title),
			Description:   aws.ToString(finding.Description),
			CreatedTime:   parseTime(finding.CreatedAt),
			ModifiedTime:  parseTime(finding.UpdatedAt),
			Types:         finding.Types,
		},
		Resources: mapResources(finding.Resources),
		Cloud: &ocsf.Cloud{
			Provider:  "aws",
			Region:    aws.ToString(finding.Region),
			AccountID: aws.ToString(finding.AwsAccountId),
		},
	}

	if finding.Remediation != nil && finding.Remediation.Recommendation != nil {
		f.Remediation = &ocsf.Remediation{
			Description: aws.ToString(finding.Remediation.Recommendation.Text),
		}
		if finding.Remediation.Recommendation.Url != nil {
			f.Remediation.References = []string{aws.ToString(finding.Remediation.Recommendation.Url)}
		}
	}

	return json.Marshal(&f)
}

func mapToVulnerabilityFinding(finding *shtypes.AwsSecurityFinding) ([]byte, error) {
	sevID, sevLabel := mapSeverity(finding.Severity)
	statusID, status := mapStatus(finding)

	f := ocsf.VulnerabilityFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ocsf.ClassVulnerabilityFind,
		SeverityID:  sevID,
		Severity:    sevLabel,
		StatusID:    statusID,
		Status:      status,
		Message:     aws.ToString(finding.Description),
		Time:        parseTime(finding.UpdatedAt),
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       aws.ToString(finding.ProductName),
				VendorName: "AWS",
				UID:        aws.ToString(finding.ProductArn),
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:          aws.ToString(finding.Id),
			Title:        aws.ToString(finding.Title),
			Description:  aws.ToString(finding.Description),
			CreatedTime:  parseTime(finding.CreatedAt),
			ModifiedTime: parseTime(finding.UpdatedAt),
			Types:        finding.Types,
		},
		Resources: mapResources(finding.Resources),
		Cloud: &ocsf.Cloud{
			Provider:  "aws",
			Region:    aws.ToString(finding.Region),
			AccountID: aws.ToString(finding.AwsAccountId),
		},
	}

	// Extract vulnerabilities from ASFF
	if finding.Vulnerabilities != nil {
		for _, v := range finding.Vulnerabilities {
			vuln := ocsf.Vulnerability{
				UID:   aws.ToString(v.Id),
				Title: aws.ToString(v.Id),
			}
			if v.Cvss != nil {
				for _, c := range v.Cvss {
					vuln.CVE = &ocsf.CVE{
						UID: aws.ToString(v.Id),
						CVSS: []ocsf.CVSS{
							{
								Version:   aws.ToString(c.Version),
								BaseScore: aws.ToFloat64(c.BaseScore),
							},
						},
					}
				}
			} else if v.Id != nil && strings.HasPrefix(aws.ToString(v.Id), "CVE-") {
				vuln.CVE = &ocsf.CVE{UID: aws.ToString(v.Id)}
			}
			if v.FixAvailable != "" {
				fixAvail := v.FixAvailable == "YES"
				vuln.FixAvailable = &fixAvail
			}
			if v.Vendor != nil && v.Vendor.VendorSeverity != nil {
				vuln.Severity = aws.ToString(v.Vendor.VendorSeverity)
			}
			f.Vulnerabilities = append(f.Vulnerabilities, vuln)
		}
	}

	if finding.Remediation != nil && finding.Remediation.Recommendation != nil {
		f.Remediation = &ocsf.Remediation{
			Description: aws.ToString(finding.Remediation.Recommendation.Text),
		}
	}

	return json.Marshal(&f)
}

func mapToComplianceFinding(finding *shtypes.AwsSecurityFinding) ([]byte, error) {
	sevID, sevLabel := mapSeverity(finding.Severity)
	statusID, status := mapStatus(finding)

	f := ocsf.ComplianceFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ocsf.ClassComplianceFinding,
		SeverityID:  sevID,
		Severity:    sevLabel,
		StatusID:    statusID,
		Status:      status,
		Message:     aws.ToString(finding.Description),
		Time:        parseTime(finding.UpdatedAt),
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       aws.ToString(finding.ProductName),
				VendorName: "AWS",
				UID:        aws.ToString(finding.ProductArn),
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:          aws.ToString(finding.Id),
			Title:        aws.ToString(finding.Title),
			Description:  aws.ToString(finding.Description),
			CreatedTime:  parseTime(finding.CreatedAt),
			ModifiedTime: parseTime(finding.UpdatedAt),
			Types:        finding.Types,
		},
		Resources: mapResources(finding.Resources),
		Cloud: &ocsf.Cloud{
			Provider:  "aws",
			Region:    aws.ToString(finding.Region),
			AccountID: aws.ToString(finding.AwsAccountId),
		},
	}

	// Map compliance information
	if finding.Compliance != nil {
		comp := &ocsf.Compliance{
			Status: string(finding.Compliance.Status),
		}
		if finding.Compliance.StatusReasons != nil {
			for _, r := range finding.Compliance.StatusReasons {
				comp.Requirements = append(comp.Requirements, aws.ToString(r.Description))
			}
		}
		if finding.Compliance.SecurityControlId != nil {
			comp.Control = aws.ToString(finding.Compliance.SecurityControlId)
		}
		if finding.Compliance.AssociatedStandards != nil {
			for _, std := range finding.Compliance.AssociatedStandards {
				comp.Standards = append(comp.Standards, aws.ToString(std.StandardsId))
			}
		}
		f.Compliance = comp
	}

	return json.Marshal(&f)
}

func mapToDetectionFinding(finding *shtypes.AwsSecurityFinding) ([]byte, error) {
	sevID, sevLabel := mapSeverity(finding.Severity)
	statusID, status := mapStatus(finding)

	f := ocsf.DetectionFinding{
		ActivityID:  ocsf.ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ocsf.ClassDetectionFinding,
		SeverityID:  sevID,
		Severity:    sevLabel,
		StatusID:    statusID,
		Status:      status,
		Message:     aws.ToString(finding.Description),
		Time:        parseTime(finding.UpdatedAt),
		Metadata: ocsf.Metadata{
			Product: &ocsf.Product{
				Name:       aws.ToString(finding.ProductName),
				VendorName: "AWS",
				UID:        aws.ToString(finding.ProductArn),
			},
			Version: "1.1.0",
		},
		FindingInfo: &ocsf.FindingInfo{
			UID:          aws.ToString(finding.Id),
			Title:        aws.ToString(finding.Title),
			Description:  aws.ToString(finding.Description),
			CreatedTime:  parseTime(finding.CreatedAt),
			ModifiedTime: parseTime(finding.UpdatedAt),
			Types:        finding.Types,
		},
		Resources: mapResources(finding.Resources),
		Cloud: &ocsf.Cloud{
			Provider:  "aws",
			Region:    aws.ToString(finding.Region),
			AccountID: aws.ToString(finding.AwsAccountId),
		},
	}

	return json.Marshal(&f)
}
