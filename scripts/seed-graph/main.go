// Package main provides a seed script that generates sample OCSF security findings
// and sends them to the CSF Collector via OTLP/HTTP for testing the pipeline.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

func main() {
	endpoint := "http://localhost:4318/v1/logs"
	if e := os.Getenv("OTLP_ENDPOINT"); e != "" {
		endpoint = e
	}

	findings := generateSampleFindings()
	fmt.Printf("Sending %d sample findings to %s\n", len(findings), endpoint)

	for i, f := range findings {
		body, err := json.Marshal(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal finding %d: %v\n", i, err)
			continue
		}

		payload := buildOTLPPayload(body)
		payloadBytes, _ := json.Marshal(payload)

		resp, err := http.Post(endpoint, "application/json", bytes.NewReader(payloadBytes))
		if err != nil {
			fmt.Fprintf(os.Stderr, "send finding %d: %v\n", i, err)
			continue
		}
		resp.Body.Close()
		fmt.Printf("  [%d] %s → %d\n", i+1, getTitle(f), resp.StatusCode)
	}

	fmt.Println("Done!")
}

func buildOTLPPayload(findingJSON []byte) map[string]interface{} {
	return map[string]interface{}{
		"resourceLogs": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": []map[string]interface{}{
						{"key": "csf.source.platform", "value": map[string]interface{}{"stringValue": "seed"}},
					},
				},
				"scopeLogs": []map[string]interface{}{
					{
						"logRecords": []map[string]interface{}{
							{
								"timeUnixNano": fmt.Sprintf("%d", time.Now().UnixNano()),
								"body":         map[string]interface{}{"stringValue": string(findingJSON)},
							},
						},
					},
				},
			},
		},
	}
}

func getTitle(f interface{}) string {
	switch v := f.(type) {
	case ocsf.SecurityFinding:
		if v.FindingInfo != nil {
			return v.FindingInfo.Title
		}
		return v.Message
	case ocsf.VulnerabilityFinding:
		if v.FindingInfo != nil {
			return v.FindingInfo.Title
		}
		return v.Message
	case ocsf.ComplianceFinding:
		if v.FindingInfo != nil {
			return v.FindingInfo.Title
		}
		return v.Message
	case ocsf.DetectionFinding:
		if v.FindingInfo != nil {
			return v.FindingInfo.Title
		}
		return v.Message
	default:
		return "unknown"
	}
}

func generateSampleFindings() []interface{} {
	now := time.Now()
	confidence := int32(90)

	return []interface{}{
		// 1. GuardDuty detection finding
		ocsf.DetectionFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassDetectionFinding,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
			Time:       ocsf.NewTime(now),
			Confidence: &confidence,
			Metadata:   ocsf.Metadata{Product: &ocsf.Product{Name: "GuardDuty", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:guardduty:us-east-1:123456789012:finding/seed-001",
				Title: "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:user/admin", Type: "AwsIamUser", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud:   &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Attacks: []ocsf.Attack{{Tactic: &ocsf.AttackTactic{UID: "TA0001", Name: "Initial Access"}, Technique: &ocsf.AttackTechnique{UID: "T1078", Name: "Valid Accounts"}}},
		},

		// 2. Inspector vulnerability finding
		ocsf.VulnerabilityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassVulnerabilityFind,
			SeverityID: ocsf.SeverityCritical, Severity: "Critical",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "CVE-2024-1234 — Remote Code Execution in foo",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Inspector", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:inspector2:us-east-1:123456789012:finding/seed-002",
				Title: "CVE-2024-1234 — RCE in foo",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:lambda:us-east-1:123456789012:function:api-handler", Type: "AwsLambdaFunction", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Vulnerabilities: []ocsf.Vulnerability{
				{UID: "CVE-2024-1234", Title: "RCE in foo", CVE: &ocsf.CVE{UID: "CVE-2024-1234", CVSS: []ocsf.CVSS{{Version: "3.1", BaseScore: 9.8, Severity: "Critical"}}}},
			},
		},

		// 3. Security Hub compliance finding
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityMedium, Severity: "Medium",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "S3 bucket missing encryption",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-003",
				Title: "S3.4 S3 buckets should have server-side encryption enabled",
			},
			Compliance: &ocsf.Compliance{
				Requirements: []string{"CIS AWS 2.1.1"}, Status: "FAILED", Control: "S3.4",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:s3:::public-data-bucket", Type: "AwsS3Bucket", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 4. GitHub CodeQL finding
		ocsf.VulnerabilityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassVulnerabilityFind,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "SQL injection in database query",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "CodeQL", VendorName: "GitHub"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "github/myorg/api-server/code-scanning/42",
				Title: "SQL injection vulnerability",
			},
			Resources: []ocsf.Resource{
				{UID: "github.com/myorg/api-server", Type: "CodeRepository", Name: "api-server"},
			},
			Vulnerabilities: []ocsf.Vulnerability{
				{UID: "js/sql-injection", Title: "SQL injection", AffectedCode: []ocsf.AffectedCode{{FilePath: "src/db.js", StartLine: 15, EndLine: 20}}},
			},
		},

		// 5. GitHub secret scanning finding
		ocsf.SecurityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassSecurityFinding,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Exposed AWS Access Key ID detected in repository",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Secret Scanning", VendorName: "GitHub"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "github/myorg/api-server/secret-scanning/3",
				Title: "Exposed AWS Access Key ID secret detected",
			},
			Resources: []ocsf.Resource{
				{UID: "github.com/myorg/api-server", Type: "CodeRepository", Name: "api-server"},
			},
			Unmapped: map[string]interface{}{
				"secret_type": "aws_access_key_id",
			},
		},
	}
}
