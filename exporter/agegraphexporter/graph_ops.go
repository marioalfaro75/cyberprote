package agegraphexporter

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloud-security-fabric/csf/internal/graph"
	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

// processSecurityFinding extracts nodes and edges from a SecurityFinding.
func processSecurityFinding(ctx context.Context, gs *graph.GraphService, f *ocsf.SecurityFinding) error {
	findingUID := ""
	title := f.Message
	if f.FindingInfo != nil {
		findingUID = f.FindingInfo.UID
		if f.FindingInfo.Title != "" {
			title = f.FindingInfo.Title
		}
	}
	if findingUID == "" {
		findingUID = title
	}

	provider := ""
	if f.Cloud != nil {
		provider = f.Cloud.Provider
	}

	if err := gs.UpsertFinding(ctx, findingUID, f.ClassUID, f.SeverityID, title, f.Message, provider, f.Status); err != nil {
		return err
	}

	for _, res := range f.Resources {
		resProvider := provider
		accountID := ""
		region := ""
		if res.Cloud != nil {
			resProvider = res.Cloud.Provider
			accountID = res.Cloud.AccountID
			region = res.Cloud.Region
		}
		if err := gs.UpsertResource(ctx, res.UID, res.Type, res.Name, resProvider, accountID, region); err != nil {
			return err
		}
		if err := gs.CreateEdge(ctx, "Finding", findingUID, "Resource", res.UID, graph.EdgeAFFECTS, nil); err != nil {
			return err
		}
	}

	return nil
}

// processVulnerabilityFinding extracts nodes and edges from a VulnerabilityFinding.
func processVulnerabilityFinding(ctx context.Context, gs *graph.GraphService, f *ocsf.VulnerabilityFinding) error {
	findingUID := ""
	title := f.Message
	if f.FindingInfo != nil {
		findingUID = f.FindingInfo.UID
		if f.FindingInfo.Title != "" {
			title = f.FindingInfo.Title
		}
	}
	if findingUID == "" {
		findingUID = title
	}

	provider := ""
	if f.Cloud != nil {
		provider = f.Cloud.Provider
	}

	if err := gs.UpsertFinding(ctx, findingUID, f.ClassUID, f.SeverityID, title, f.Message, provider, f.Status); err != nil {
		return err
	}

	for _, vuln := range f.Vulnerabilities {
		cvssScore := 0.0
		if vuln.CVE != nil && len(vuln.CVE.CVSS) > 0 {
			cvssScore = vuln.CVE.CVSS[0].BaseScore
		}
		vulnUID := vuln.UID
		if vulnUID == "" && vuln.CVE != nil {
			vulnUID = vuln.CVE.UID
		}
		if vulnUID == "" {
			continue
		}
		if err := gs.UpsertVulnerability(ctx, vulnUID, vuln.Title, vuln.Severity, cvssScore); err != nil {
			return err
		}
		if err := gs.CreateEdge(ctx, "Finding", findingUID, "Vulnerability", vulnUID, graph.EdgeEXPLOITS, nil); err != nil {
			return err
		}
	}

	for _, res := range f.Resources {
		resProvider := provider
		accountID := ""
		region := ""
		if res.Cloud != nil {
			resProvider = res.Cloud.Provider
			accountID = res.Cloud.AccountID
			region = res.Cloud.Region
		}
		if err := gs.UpsertResource(ctx, res.UID, res.Type, res.Name, resProvider, accountID, region); err != nil {
			return err
		}
		if err := gs.CreateEdge(ctx, "Finding", findingUID, "Resource", res.UID, graph.EdgeAFFECTS, nil); err != nil {
			return err
		}
	}

	return nil
}

// processComplianceFinding extracts nodes and edges from a ComplianceFinding.
func processComplianceFinding(ctx context.Context, gs *graph.GraphService, f *ocsf.ComplianceFinding) error {
	findingUID := ""
	title := f.Message
	if f.FindingInfo != nil {
		findingUID = f.FindingInfo.UID
		if f.FindingInfo.Title != "" {
			title = f.FindingInfo.Title
		}
	}
	if findingUID == "" {
		findingUID = title
	}

	provider := ""
	if f.Cloud != nil {
		provider = f.Cloud.Provider
	}

	var extra *graph.FindingExtra
	if f.Compliance != nil {
		extra = &graph.FindingExtra{
			ComplianceStatus:    f.Compliance.Status,
			ComplianceControl:   f.Compliance.Control,
			ComplianceStandards: strings.Join(f.Compliance.Standards, ","),
		}
	}

	if err := gs.UpsertFindingWithExtra(ctx, findingUID, f.ClassUID, f.SeverityID, title, f.Message, provider, f.Status, extra); err != nil {
		return err
	}

	for _, res := range f.Resources {
		resProvider := provider
		accountID := ""
		region := ""
		if res.Cloud != nil {
			resProvider = res.Cloud.Provider
			accountID = res.Cloud.AccountID
			region = res.Cloud.Region
		}
		if err := gs.UpsertResource(ctx, res.UID, res.Type, res.Name, resProvider, accountID, region); err != nil {
			return err
		}
		if err := gs.CreateEdge(ctx, "Finding", findingUID, "Resource", res.UID, graph.EdgeAFFECTS, nil); err != nil {
			return err
		}
	}

	return nil
}

// processOCSFFinding dispatches a raw OCSF JSON body to the appropriate handler.
func processOCSFFinding(ctx context.Context, gs *graph.GraphService, body []byte) error {
	finding, err := ocsf.ParseFinding(body)
	if err != nil {
		return err
	}

	switch f := finding.(type) {
	case *ocsf.SecurityFinding:
		return processSecurityFinding(ctx, gs, f)
	case *ocsf.VulnerabilityFinding:
		return processVulnerabilityFinding(ctx, gs, f)
	case *ocsf.ComplianceFinding:
		return processComplianceFinding(ctx, gs, f)
	case *ocsf.DetectionFinding:
		return processDetectionFinding(ctx, gs, f)
	case *ocsf.DataSecurityFinding:
		return processDataSecurityFinding(ctx, gs, f)
	default:
		return nil
	}
}

// processDetectionFinding handles detection findings.
func processDetectionFinding(ctx context.Context, gs *graph.GraphService, f *ocsf.DetectionFinding) error {
	findingUID := ""
	title := f.Message
	if f.FindingInfo != nil {
		findingUID = f.FindingInfo.UID
		if f.FindingInfo.Title != "" {
			title = f.FindingInfo.Title
		}
	}
	if findingUID == "" {
		findingUID = title
	}

	provider := ""
	if f.Cloud != nil {
		provider = f.Cloud.Provider
	}

	if err := gs.UpsertFinding(ctx, findingUID, f.ClassUID, f.SeverityID, title, f.Message, provider, f.Status); err != nil {
		return err
	}

	for _, res := range f.Resources {
		resProvider := provider
		accountID := ""
		region := ""
		if res.Cloud != nil {
			resProvider = res.Cloud.Provider
			accountID = res.Cloud.AccountID
			region = res.Cloud.Region
		}
		if err := gs.UpsertResource(ctx, res.UID, res.Type, res.Name, resProvider, accountID, region); err != nil {
			return err
		}
		if err := gs.CreateEdge(ctx, "Finding", findingUID, "Resource", res.UID, graph.EdgeAFFECTS, nil); err != nil {
			return err
		}
	}
	return nil
}

// processDataSecurityFinding handles data security findings.
func processDataSecurityFinding(ctx context.Context, gs *graph.GraphService, f *ocsf.DataSecurityFinding) error {
	findingUID := ""
	title := f.Message
	if f.FindingInfo != nil {
		findingUID = f.FindingInfo.UID
		if f.FindingInfo.Title != "" {
			title = f.FindingInfo.Title
		}
	}
	if findingUID == "" {
		findingUID = title
	}

	provider := ""
	if f.Cloud != nil {
		provider = f.Cloud.Provider
	}

	if err := gs.UpsertFinding(ctx, findingUID, f.ClassUID, f.SeverityID, title, f.Message, provider, f.Status); err != nil {
		return err
	}

	for _, res := range f.Resources {
		resProvider := provider
		accountID := ""
		region := ""
		if res.Cloud != nil {
			resProvider = res.Cloud.Provider
			accountID = res.Cloud.AccountID
			region = res.Cloud.Region
		}
		if err := gs.UpsertResource(ctx, res.UID, res.Type, res.Name, resProvider, accountID, region); err != nil {
			return err
		}
		if err := gs.CreateEdge(ctx, "Finding", findingUID, "Resource", res.UID, graph.EdgeAFFECTS, nil); err != nil {
			return err
		}
	}
	return nil
}

// extractBodyJSON tries to extract a JSON body from a log record body string.
func extractBodyJSON(bodyStr string) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &m); err != nil {
		return nil, err
	}
	return []byte(bodyStr), nil
}
