// Package main provides a seed script that generates sample OCSF security findings
// and sends them to the CSF Collector via OTLP/HTTP for testing the pipeline.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cloud-security-fabric/csf/internal/graph"
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

	fmt.Println("Done sending findings!")

	// Seed NetworkPath nodes directly to graph for exposure demo
	seedNetworkPaths()
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

func float64Ptr(f float64) *float64 { return &f }
func boolPtr(b bool) *bool         { return &b }

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
				{UID: "CVE-2024-1234", Title: "RCE in foo", CVE: &ocsf.CVE{UID: "CVE-2024-1234", CVSS: []ocsf.CVSS{{Version: "3.1", BaseScore: 9.8, Severity: "Critical"}}, EPSSScore: float64Ptr(0.95), IsExploited: boolPtr(true)}},
			},
		},

		// 3. Security Hub compliance finding — S3.4 FAILED
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

		// --- Additional compliance findings for dashboard demo ---

		// 6. IAM.4 — Root account has access keys (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityCritical, Severity: "Critical",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Root user account has active access keys",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-006",
				Title: "IAM.4 IAM root user access key should not exist",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "IAM.4",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0", "NIST CSF 2.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:root", Type: "AwsIamUser", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 7. IAM.6 — MFA enabled for root (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Hardware MFA is enabled for root user",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-007",
				Title: "IAM.6 Hardware MFA should be enabled for the root user",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "IAM.6",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:root", Type: "AwsIamUser", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 8. CloudTrail.1 — CloudTrail enabled (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "CloudTrail is enabled in all regions",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-008",
				Title: "CloudTrail.1 CloudTrail should be enabled and configured with at least one multi-Region trail",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "CloudTrail.1",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail", Type: "AwsCloudTrailTrail", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 9. EBS.1 — EBS encryption (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "EBS default encryption is enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-009",
				Title: "EBS.1 Amazon EBS snapshots should not be publicly restorable",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "EBS.1",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc123", Type: "AwsEc2Volume", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 10. VPC.1 — Default security group restricts traffic (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Default security group allows unrestricted traffic",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-010",
				Title: "VPC.1 Default security group should restrict all traffic",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "VPC.1",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-default", Type: "AwsEc2SecurityGroup", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 11. GuardDuty.1 — GuardDuty enabled (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "GuardDuty is enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-011",
				Title: "GuardDuty.1 GuardDuty should be enabled",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "GuardDuty.1",
				Standards: []string{"NIST CSF 2.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:guardduty:us-east-1:123456789012:detector/abc123", Type: "AwsGuardDutyDetector", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 12. RDS.3 — RDS encryption (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "RDS DB instance does not have encryption at rest enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-012",
				Title: "RDS.3 RDS DB instances should have encryption at rest enabled",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "RDS.3",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:rds:us-east-1:123456789012:db:prod-db", Type: "AwsRdsDbInstance", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 13. IAM.5 — MFA for console users (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityMedium, Severity: "Medium",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "IAM users with console access do not have MFA enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-013",
				Title: "IAM.5 MFA should be enabled for all IAM users that have console password",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "IAM.5",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:user/developer", Type: "AwsIamUser", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 14. EC2.1 — Security groups restrict SSH (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "No security groups allow unrestricted SSH access",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-014",
				Title: "EC2.1 Amazon EBS snapshots should not be public",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "EC2.1",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-web", Type: "AwsEc2SecurityGroup", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 15. S3.5 — S3 bucket versioning (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityMedium, Severity: "Medium",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "S3 bucket does not have versioning enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-015",
				Title: "S3.5 S3 general purpose buckets should require requests to use SSL",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "S3.5",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:s3:::logs-bucket", Type: "AwsS3Bucket", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 16. IAM.1 — Unused credentials disabled (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "No IAM credentials unused for 45+ days",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-016",
				Title: "IAM.1 IAM policies should not allow full * administrative privileges",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "IAM.1",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:user/svc-deploy", Type: "AwsIamUser", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 17. VPC.2 — VPC flow logs enabled (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityMedium, Severity: "Medium",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "VPC flow logging is not enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-017",
				Title: "VPC.2 VPC default security group should not allow inbound and outbound traffic",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "VPC.2",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-main", Type: "AwsEc2Vpc", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 18. KMS.1 — KMS key rotation (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "KMS customer-managed keys have rotation enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-018",
				Title: "KMS.1 IAM customer managed policies should not allow decryption actions on all KMS keys",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "KMS.1",
				Standards: []string{"NIST CSF 2.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123", Type: "AwsKmsKey", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 19. SecurityHub.1 — Security Hub enabled (PASSED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityInformational, Severity: "Informational",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "AWS Security Hub is enabled",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-019",
				Title: "SecurityHub.1 Security Hub should be enabled",
			},
			Compliance: &ocsf.Compliance{
				Status: "PASSED", Control: "SecurityHub.1",
				Standards: []string{"NIST CSF 2.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:securityhub:us-east-1:123456789012:hub/default", Type: "AwsSecurityHubHub", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
		},

		// 20. IAM.8 — Password policy (FAILED)
		ocsf.ComplianceFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassComplianceFinding,
			SeverityID: ocsf.SeverityMedium, Severity: "Medium",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Password policy does not meet minimum length requirement",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Security Hub", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:securityhub:us-east-1:123456789012:finding/seed-020",
				Title: "IAM.8 Unused IAM user credentials should be removed",
			},
			Compliance: &ocsf.Compliance{
				Status: "FAILED", Control: "IAM.8",
				Standards: []string{"CIS AWS Foundations Benchmark v1.4.0"},
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:account-password-policy", Type: "AwsIamAccountPasswordPolicy", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
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
				{UID: "js/sql-injection", Title: "SQL injection", AffectedCode: []ocsf.AffectedCode{{FilePath: "src/db.js", StartLine: 15, EndLine: 20}}, CVE: &ocsf.CVE{UID: "js/sql-injection", EPSSScore: float64Ptr(0.15)}},
			},
		},

		// --- Additional vulnerability findings with EPSS/KEV for threat intel demo ---

		// Threat Intel: Log4Shell — Critical, high EPSS, KEV
		ocsf.VulnerabilityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassVulnerabilityFind,
			SeverityID: ocsf.SeverityCritical, Severity: "Critical",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "CVE-2021-44228 — Log4Shell Remote Code Execution",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Inspector", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:inspector2:us-east-1:123456789012:finding/seed-ti-001",
				Title: "CVE-2021-44228 — Log4Shell RCE",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:instance/i-java-app", Type: "AwsEc2Instance", Name: "java-app-server", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Vulnerabilities: []ocsf.Vulnerability{
				{UID: "CVE-2021-44228", Title: "Log4Shell RCE", Severity: "Critical", CVE: &ocsf.CVE{UID: "CVE-2021-44228", CVSS: []ocsf.CVSS{{Version: "3.1", BaseScore: 10.0, Severity: "Critical"}}, EPSSScore: float64Ptr(0.972), IsExploited: boolPtr(true)}},
			},
		},

		// Threat Intel: Medium EPSS vuln, not in KEV
		ocsf.VulnerabilityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassVulnerabilityFind,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "CVE-2023-44487 — HTTP/2 Rapid Reset Attack",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Inspector", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:inspector2:us-east-1:123456789012:finding/seed-ti-002",
				Title: "CVE-2023-44487 — HTTP/2 Rapid Reset",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ecs:us-east-1:123456789012:service/api-gateway", Type: "AwsEcsService", Name: "api-gateway", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Vulnerabilities: []ocsf.Vulnerability{
				{UID: "CVE-2023-44487", Title: "HTTP/2 Rapid Reset", Severity: "High", CVE: &ocsf.CVE{UID: "CVE-2023-44487", CVSS: []ocsf.CVSS{{Version: "3.1", BaseScore: 7.5, Severity: "High"}}, EPSSScore: float64Ptr(0.45), IsExploited: boolPtr(false)}},
			},
		},

		// Threat Intel: Low EPSS, low severity
		ocsf.VulnerabilityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassVulnerabilityFind,
			SeverityID: ocsf.SeverityLow, Severity: "Low",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "CVE-2024-5678 — Information disclosure in headers",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Inspector", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:inspector2:us-east-1:123456789012:finding/seed-ti-003",
				Title: "CVE-2024-5678 — Info disclosure",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:instance/i-web-proxy", Type: "AwsEc2Instance", Name: "web-proxy", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Vulnerabilities: []ocsf.Vulnerability{
				{UID: "CVE-2024-5678", Title: "Info disclosure in headers", Severity: "Low", CVE: &ocsf.CVE{UID: "CVE-2024-5678", CVSS: []ocsf.CVSS{{Version: "3.1", BaseScore: 3.1, Severity: "Low"}}, EPSSScore: float64Ptr(0.02), IsExploited: boolPtr(false)}},
			},
		},

		// Threat Intel: KEV, medium EPSS
		ocsf.VulnerabilityFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassVulnerabilityFind,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "CVE-2023-23397 — Outlook Elevation of Privilege",
			Time:     ocsf.NewTime(now),
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "Inspector", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:inspector2:us-east-1:123456789012:finding/seed-ti-004",
				Title: "CVE-2023-23397 — Outlook EoP",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:instance/i-mail-server", Type: "AwsEc2Instance", Name: "mail-server", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Vulnerabilities: []ocsf.Vulnerability{
				{UID: "CVE-2023-23397", Title: "Outlook EoP", Severity: "High", CVE: &ocsf.CVE{UID: "CVE-2023-23397", CVSS: []ocsf.CVSS{{Version: "3.1", BaseScore: 9.8, Severity: "Critical"}}, EPSSScore: float64Ptr(0.72), IsExploited: boolPtr(true)}},
			},
		},

		// --- Additional detection findings with ATT&CK mappings ---

		// Threat Intel: Credential Access detection
		ocsf.DetectionFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassDetectionFinding,
			SeverityID: ocsf.SeverityHigh, Severity: "High",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Unusual credential access pattern detected",
			Time:     ocsf.NewTime(now), Confidence: &confidence,
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "GuardDuty", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:guardduty:us-east-1:123456789012:finding/seed-ti-005",
				Title: "CredentialAccess:IAMUser/AnomalousBehavior",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:iam::123456789012:user/svc-deploy", Type: "AwsIamUser", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Attacks: []ocsf.Attack{
				{Tactic: &ocsf.AttackTactic{UID: "TA0006", Name: "Credential Access"}, Technique: &ocsf.AttackTechnique{UID: "T1110", Name: "Brute Force"}},
			},
		},

		// Threat Intel: Lateral Movement detection
		ocsf.DetectionFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassDetectionFinding,
			SeverityID: ocsf.SeverityCritical, Severity: "Critical",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Lateral movement via SSM detected",
			Time:     ocsf.NewTime(now), Confidence: &confidence,
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "GuardDuty", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:guardduty:us-east-1:123456789012:finding/seed-ti-006",
				Title: "LateralMovement:EC2/SSMSessionFromCompromisedInstance",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:ec2:us-east-1:123456789012:instance/i-compromised", Type: "AwsEc2Instance", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Attacks: []ocsf.Attack{
				{Tactic: &ocsf.AttackTactic{UID: "TA0008", Name: "Lateral Movement"}, Technique: &ocsf.AttackTechnique{UID: "T1021", Name: "Remote Services"}},
			},
		},

		// Threat Intel: Exfiltration detection
		ocsf.DetectionFinding{
			ActivityID: ocsf.ActivityCreate, CategoryUID: 2, ClassUID: ocsf.ClassDetectionFinding,
			SeverityID: ocsf.SeverityCritical, Severity: "Critical",
			StatusID: ocsf.StatusNew, Status: "New",
			Message:  "Large data transfer to external S3 bucket",
			Time:     ocsf.NewTime(now), Confidence: &confidence,
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "GuardDuty", VendorName: "AWS"}},
			FindingInfo: &ocsf.FindingInfo{
				UID:   "arn:aws:guardduty:us-east-1:123456789012:finding/seed-ti-007",
				Title: "Exfiltration:S3/AnomalousDataTransfer",
			},
			Resources: []ocsf.Resource{
				{UID: "arn:aws:s3:::sensitive-data-bucket", Type: "AwsS3Bucket", Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"}},
			},
			Cloud: &ocsf.Cloud{Provider: "aws", AccountID: "123456789012", Region: "us-east-1"},
			Attacks: []ocsf.Attack{
				{Tactic: &ocsf.AttackTactic{UID: "TA0010", Name: "Exfiltration"}, Technique: &ocsf.AttackTechnique{UID: "T1567", Name: "Exfiltration Over Web Service"}},
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

// seedNetworkPaths creates NetworkPath nodes and EXPOSES edges directly in the graph
// for the exposure demo. Resources must already exist from the OTLP pipeline above.
func seedNetworkPaths() {
	dsn := os.Getenv("CSF_DSN")
	if dsn == "" {
		dsn = "postgres://csf:csf-dev-password@localhost:5432/csf?sslmode=disable"
	}

	gs, err := graph.NewGraphService(dsn, "security_fabric")
	if err != nil {
		fmt.Fprintf(os.Stderr, "graph service for network paths: %v\n", err)
		return
	}
	defer gs.Close()

	ctx := context.Background()

	type exposedPath struct {
		pathUID     string
		endpoint    string
		protocol    string
		port        int
		resourceUID string
	}

	paths := []exposedPath{
		{
			pathUID:     "netpath-api-gw-443",
			endpoint:    "api.example.com",
			protocol:    "HTTPS",
			port:        443,
			resourceUID: "arn:aws:ecs:us-east-1:123456789012:service/api-gateway",
		},
		{
			pathUID:     "netpath-web-proxy-80",
			endpoint:    "web.example.com",
			protocol:    "HTTP",
			port:        80,
			resourceUID: "arn:aws:ec2:us-east-1:123456789012:instance/i-web-proxy",
		},
		{
			pathUID:     "netpath-java-app-8080",
			endpoint:    "app.example.com",
			protocol:    "HTTP",
			port:        8080,
			resourceUID: "arn:aws:ec2:us-east-1:123456789012:instance/i-java-app",
		},
	}

	fmt.Printf("Seeding %d network paths directly to graph...\n", len(paths))
	for _, p := range paths {
		if err := gs.UpsertNetworkPath(ctx, p.pathUID, p.endpoint, p.protocol, p.port, true); err != nil {
			fmt.Fprintf(os.Stderr, "  upsert network path %s: %v\n", p.pathUID, err)
			continue
		}
		if err := gs.CreateEdge(ctx, "Resource", p.resourceUID, "NetworkPath", p.pathUID, graph.EdgeEXPOSES, nil); err != nil {
			fmt.Fprintf(os.Stderr, "  create EXPOSES edge %s → %s: %v\n", p.resourceUID, p.pathUID, err)
			continue
		}
		fmt.Printf("  [+] %s → %s:%d\n", p.resourceUID, p.endpoint, p.port)
	}
	fmt.Println("Network paths seeded!")
}
