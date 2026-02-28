package awssechubreceiver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.uber.org/zap"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

func TestMapGuardDutyFinding(t *testing.T) {
	finding := shtypes.AwsSecurityFinding{
		Id:           aws.String("arn:aws:securityhub:us-east-1:123456789012:finding/abc123"),
		ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/guardduty"),
		ProductName:  aws.String("GuardDuty"),
		AwsAccountId: aws.String("123456789012"),
		Region:       aws.String("us-east-1"),
		Types:        []string{"TTPs/Initial Access"},
		CreatedAt:    aws.String("2025-01-15T10:30:00Z"),
		UpdatedAt:    aws.String("2025-01-15T11:00:00Z"),
		Severity:     &shtypes.Severity{Label: shtypes.SeverityLabelHigh},
		Title:        aws.String("UnauthorizedAccess:IAMUser/MaliciousIPCaller"),
		Description:  aws.String("API calls from known malicious IP address"),
		Resources: []shtypes.Resource{
			{
				Type:   aws.String("AwsIamUser"),
				Id:     aws.String("arn:aws:iam::123456789012:user/admin"),
				Region: aws.String("us-east-1"),
			},
		},
		Workflow: &shtypes.Workflow{Status: shtypes.WorkflowStatusNew},
	}

	data, err := MapASSFToOCSF(&finding)
	if err != nil {
		t.Fatal(err)
	}

	// GuardDuty TTPs should map to DetectionFinding (2004)
	parsed, err := ocsf.ParseFinding(data)
	if err != nil {
		t.Fatal(err)
	}

	df, ok := parsed.(*ocsf.DetectionFinding)
	if !ok {
		t.Fatalf("expected DetectionFinding, got %T", parsed)
	}
	if df.SeverityID != ocsf.SeverityHigh {
		t.Errorf("severity_id = %d, want %d", df.SeverityID, ocsf.SeverityHigh)
	}
	if df.Cloud.AccountID != "123456789012" {
		t.Errorf("account_id = %s", df.Cloud.AccountID)
	}
}

func TestMapInspectorFinding(t *testing.T) {
	finding := shtypes.AwsSecurityFinding{
		Id:           aws.String("arn:aws:securityhub:us-east-1:123456789012:finding/def456"),
		ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/inspector"),
		ProductName:  aws.String("Inspector"),
		AwsAccountId: aws.String("123456789012"),
		Region:       aws.String("us-east-1"),
		Types:        []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
		CreatedAt:    aws.String("2025-01-15T09:00:00Z"),
		UpdatedAt:    aws.String("2025-01-15T09:30:00Z"),
		Severity:     &shtypes.Severity{Label: shtypes.SeverityLabelCritical},
		Title:        aws.String("CVE-2024-1234 - foo"),
		Description:  aws.String("Package foo 1.2.3 has a critical vulnerability"),
		Resources: []shtypes.Resource{
			{
				Type:   aws.String("AwsLambdaFunction"),
				Id:     aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-func"),
				Region: aws.String("us-east-1"),
			},
		},
		Vulnerabilities: []shtypes.Vulnerability{
			{
				Id: aws.String("CVE-2024-1234"),
				Cvss: []shtypes.Cvss{
					{Version: aws.String("3.1"), BaseScore: aws.Float64(9.8)},
				},
				FixAvailable: shtypes.VulnerabilityFixAvailableYes,
				Vendor:       &shtypes.VulnerabilityVendor{VendorSeverity: aws.String("CRITICAL")},
			},
		},
		Workflow: &shtypes.Workflow{Status: shtypes.WorkflowStatusNew},
	}

	data, err := MapASSFToOCSF(&finding)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ocsf.ParseFinding(data)
	if err != nil {
		t.Fatal(err)
	}

	vf, ok := parsed.(*ocsf.VulnerabilityFinding)
	if !ok {
		t.Fatalf("expected VulnerabilityFinding, got %T", parsed)
	}
	if vf.SeverityID != ocsf.SeverityCritical {
		t.Errorf("severity_id = %d, want %d", vf.SeverityID, ocsf.SeverityCritical)
	}
	if len(vf.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities count = %d, want 1", len(vf.Vulnerabilities))
	}
	if vf.Vulnerabilities[0].CVE.CVSS[0].BaseScore != 9.8 {
		t.Errorf("cvss = %f, want 9.8", vf.Vulnerabilities[0].CVE.CVSS[0].BaseScore)
	}
}

func TestMapComplianceFinding(t *testing.T) {
	finding := shtypes.AwsSecurityFinding{
		Id:           aws.String("arn:aws:securityhub:us-east-1:123456789012:finding/ghi789"),
		ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
		ProductName:  aws.String("Security Hub"),
		AwsAccountId: aws.String("123456789012"),
		Region:       aws.String("us-east-1"),
		Types:        []string{"Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"},
		Severity:     &shtypes.Severity{Label: shtypes.SeverityLabelMedium},
		Title:        aws.String("S3.4 S3 buckets should have server-side encryption enabled"),
		Description:  aws.String("This control checks whether S3 buckets have SSE enabled"),
		CreatedAt:    aws.String("2025-01-14T08:00:00Z"),
		UpdatedAt:    aws.String("2025-01-15T08:00:00Z"),
		Compliance: &shtypes.Compliance{
			Status:            shtypes.ComplianceStatusFailed,
			SecurityControlId: aws.String("S3.4"),
			AssociatedStandards: []shtypes.AssociatedStandard{
				{StandardsId: aws.String("standards/cis-aws-foundations-benchmark/v/1.4.0")},
			},
		},
		Resources: []shtypes.Resource{
			{
				Type:   aws.String("AwsS3Bucket"),
				Id:     aws.String("arn:aws:s3:::my-unencrypted-bucket"),
				Region: aws.String("us-east-1"),
			},
		},
		Workflow: &shtypes.Workflow{Status: shtypes.WorkflowStatusNew},
	}

	data, err := MapASSFToOCSF(&finding)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ocsf.ParseFinding(data)
	if err != nil {
		t.Fatal(err)
	}

	cf, ok := parsed.(*ocsf.ComplianceFinding)
	if !ok {
		t.Fatalf("expected ComplianceFinding, got %T", parsed)
	}
	if cf.SeverityID != ocsf.SeverityMedium {
		t.Errorf("severity_id = %d, want %d", cf.SeverityID, ocsf.SeverityMedium)
	}
	if cf.Compliance == nil {
		t.Fatal("compliance should not be nil")
	}
	if cf.Compliance.Control != "S3.4" {
		t.Errorf("control = %s, want S3.4", cf.Compliance.Control)
	}
}

func TestMapMacieFinding(t *testing.T) {
	finding := shtypes.AwsSecurityFinding{
		Id:           aws.String("arn:aws:securityhub:us-east-1:123456789012:finding/macie1"),
		ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/macie"),
		ProductName:  aws.String("Macie"),
		AwsAccountId: aws.String("123456789012"),
		Region:       aws.String("us-east-1"),
		Types:        []string{"Sensitive Data Identifications/PII"},
		Severity:     &shtypes.Severity{Label: shtypes.SeverityLabelHigh},
		Title:        aws.String("PII data found in S3 bucket"),
		Description:  aws.String("SSN data detected in s3://my-bucket/data.csv"),
		CreatedAt:    aws.String("2025-01-15T12:00:00Z"),
		UpdatedAt:    aws.String("2025-01-15T12:00:00Z"),
		Resources: []shtypes.Resource{
			{
				Type:   aws.String("AwsS3Bucket"),
				Id:     aws.String("arn:aws:s3:::my-bucket"),
				Region: aws.String("us-east-1"),
			},
		},
		Workflow: &shtypes.Workflow{Status: shtypes.WorkflowStatusNew},
	}

	data, err := MapASSFToOCSF(&finding)
	if err != nil {
		t.Fatal(err)
	}

	// Macie findings should map to SecurityFinding (2001) as default
	var envelope struct {
		ClassUID int32 `json:"class_uid"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ClassUID != ocsf.ClassSecurityFinding {
		t.Errorf("class_uid = %d, want %d", envelope.ClassUID, ocsf.ClassSecurityFinding)
	}
}

func TestMapIAMAccessAnalyzerFinding(t *testing.T) {
	finding := shtypes.AwsSecurityFinding{
		Id:           aws.String("arn:aws:securityhub:us-east-1:123456789012:finding/iamaa1"),
		ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/access-analyzer"),
		ProductName:  aws.String("IAM Access Analyzer"),
		AwsAccountId: aws.String("123456789012"),
		Region:       aws.String("us-east-1"),
		Types:        []string{"Software and Configuration Checks/AWS Security Best Practices/External Access"},
		Severity:     &shtypes.Severity{Label: shtypes.SeverityLabelLow},
		Title:        aws.String("S3 bucket allows public access"),
		Description:  aws.String("S3 bucket policy allows public read"),
		CreatedAt:    aws.String("2025-01-15T07:00:00Z"),
		UpdatedAt:    aws.String("2025-01-15T07:00:00Z"),
		Resources: []shtypes.Resource{
			{
				Type:   aws.String("AwsS3Bucket"),
				Id:     aws.String("arn:aws:s3:::public-bucket"),
				Region: aws.String("us-east-1"),
			},
		},
		Workflow: &shtypes.Workflow{Status: shtypes.WorkflowStatusNew},
	}

	data, err := MapASSFToOCSF(&finding)
	if err != nil {
		t.Fatal(err)
	}

	// IAM AA "Software and Configuration Checks" → ComplianceFinding
	parsed, err := ocsf.ParseFinding(data)
	if err != nil {
		t.Fatal(err)
	}
	cf, ok := parsed.(*ocsf.ComplianceFinding)
	if !ok {
		t.Fatalf("expected ComplianceFinding, got %T", parsed)
	}
	if cf.SeverityID != ocsf.SeverityLow {
		t.Errorf("severity_id = %d, want %d", cf.SeverityID, ocsf.SeverityLow)
	}
}

// mockSecHubClient implements SecurityHubAPI for testing.
type mockSecHubClient struct {
	findings []shtypes.AwsSecurityFinding
}

func (m *mockSecHubClient) GetFindings(ctx context.Context, params *securityhub.GetFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	return &securityhub.GetFindingsOutput{
		Findings: m.findings,
	}, nil
}

func TestReceiverEmitFindings(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{
		Region:       "us-east-1",
		PollInterval: 1,
		BatchSize:    10,
	}
	r, err := newSecHubReceiver(cfg, zap.NewNop(), sink)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := &mockSecHubClient{
		findings: []shtypes.AwsSecurityFinding{
			{
				Id:           aws.String("finding-1"),
				ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/guardduty"),
				ProductName:  aws.String("GuardDuty"),
				AwsAccountId: aws.String("123456789012"),
				Region:       aws.String("us-east-1"),
				Types:        []string{"TTPs/Discovery"},
				Severity:     &shtypes.Severity{Label: shtypes.SeverityLabelMedium},
				Title:        aws.String("Recon:EC2/PortProbeUnprotectedPort"),
				Description:  aws.String("Port probe on unprotected port"),
				CreatedAt:    aws.String("2025-01-15T10:00:00Z"),
				UpdatedAt:    aws.String("2025-01-15T10:00:00Z"),
				Resources: []shtypes.Resource{
					{Type: aws.String("AwsEc2Instance"), Id: aws.String("i-1234567890abcdef0"), Region: aws.String("us-east-1")},
				},
				Workflow: &shtypes.Workflow{Status: shtypes.WorkflowStatusNew},
			},
		},
	}
	r.SetClient(mockClient)

	err = r.emitFindings(context.Background(), mockClient.findings)
	if err != nil {
		t.Fatal(err)
	}

	if sink.LogRecordCount() != 1 {
		t.Errorf("log records = %d, want 1", sink.LogRecordCount())
	}
}
