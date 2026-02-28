package ocsf

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSecurityFindingMarshalRoundTrip(t *testing.T) {
	now := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	confidence := int32(90)
	f := SecurityFinding{
		ActivityID:  ActivityCreate,
		CategoryUID: 2,
		ClassUID:    ClassSecurityFinding,
		Confidence:  &confidence,
		Message:     "Unauthorized API call detected",
		SeverityID:  SeverityHigh,
		Severity:    "High",
		StatusID:    StatusNew,
		Status:      "New",
		Time:        NewTime(now),
		Metadata: Metadata{
			Product: &Product{
				Name:       "GuardDuty",
				VendorName: "AWS",
			},
			Version: "1.1.0",
		},
		FindingInfo: &FindingInfo{
			UID:   "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/xyz",
			Title: "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
		},
		Resources: []Resource{
			{
				UID:  "arn:aws:iam::123456789012:user/admin",
				Type: "AwsIamUser",
				Cloud: &Cloud{
					Provider:  "aws",
					AccountID: "123456789012",
					Region:    "us-east-1",
				},
			},
		},
	}

	data, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var f2 SecurityFinding
	if err := json.Unmarshal(data, &f2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if f2.ClassUID != ClassSecurityFinding {
		t.Errorf("class_uid = %d, want %d", f2.ClassUID, ClassSecurityFinding)
	}
	if f2.SeverityID != SeverityHigh {
		t.Errorf("severity_id = %d, want %d", f2.SeverityID, SeverityHigh)
	}
	if f2.FindingInfo.UID != f.FindingInfo.UID {
		t.Errorf("finding_info.uid mismatch")
	}
	if f2.Resources[0].Cloud.AccountID != "123456789012" {
		t.Errorf("resource cloud account_id mismatch")
	}
}

func TestVulnerabilityFindingJSON(t *testing.T) {
	raw := `{
		"activity_id": 1,
		"category_uid": 2,
		"class_uid": 2002,
		"severity_id": 4,
		"severity": "High",
		"message": "CVE-2024-1234 found in package foo",
		"metadata": {
			"product": {
				"name": "Inspector",
				"vendor_name": "AWS"
			}
		},
		"vulnerabilities": [
			{
				"uid": "CVE-2024-1234",
				"title": "Remote Code Execution in foo",
				"cve": {
					"uid": "CVE-2024-1234",
					"cvss": [
						{
							"version": "3.1",
							"base_score": 9.8,
							"severity": "Critical",
							"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
						}
					]
				},
				"packages": [
					{
						"name": "foo",
						"version": "1.2.3",
						"fixed_in": "1.2.4",
						"purl": "pkg:npm/foo@1.2.3"
					}
				],
				"fix_available": true
			}
		],
		"resources": [
			{
				"uid": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
				"type": "AwsLambdaFunction"
			}
		]
	}`

	var f VulnerabilityFinding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if f.ClassUID != ClassVulnerabilityFind {
		t.Errorf("class_uid = %d, want %d", f.ClassUID, ClassVulnerabilityFind)
	}
	if len(f.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities count = %d, want 1", len(f.Vulnerabilities))
	}
	vuln := f.Vulnerabilities[0]
	if vuln.CVE.UID != "CVE-2024-1234" {
		t.Errorf("cve.uid = %s, want CVE-2024-1234", vuln.CVE.UID)
	}
	if vuln.CVE.CVSS[0].BaseScore != 9.8 {
		t.Errorf("cvss base_score = %f, want 9.8", vuln.CVE.CVSS[0].BaseScore)
	}
	fixAvail := vuln.FixAvailable
	if fixAvail == nil || !*fixAvail {
		t.Errorf("fix_available should be true")
	}
}

func TestComplianceFindingJSON(t *testing.T) {
	raw := `{
		"activity_id": 1,
		"category_uid": 2,
		"class_uid": 2003,
		"severity_id": 3,
		"severity": "Medium",
		"message": "S3 bucket missing encryption",
		"metadata": {
			"product": {
				"name": "Security Hub",
				"vendor_name": "AWS"
			}
		},
		"compliance": {
			"requirements": ["CIS AWS 2.1.1"],
			"status": "FAILED",
			"standards": ["CIS AWS Foundations Benchmark v1.4.0"],
			"control": "2.1.1"
		},
		"resources": [
			{
				"uid": "arn:aws:s3:::my-bucket",
				"type": "AwsS3Bucket"
			}
		]
	}`

	var f ComplianceFinding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.ClassUID != ClassComplianceFinding {
		t.Errorf("class_uid = %d, want %d", f.ClassUID, ClassComplianceFinding)
	}
	if f.Compliance.Control != "2.1.1" {
		t.Errorf("compliance.control = %s, want 2.1.1", f.Compliance.Control)
	}
}

func TestDetectionFindingJSON(t *testing.T) {
	raw := `{
		"activity_id": 1,
		"category_uid": 2,
		"class_uid": 2004,
		"severity_id": 5,
		"severity": "Critical",
		"message": "Suspicious API activity detected",
		"metadata": {
			"product": {
				"name": "GuardDuty",
				"vendor_name": "AWS"
			}
		},
		"attacks": [
			{
				"tactic": {"uid": "TA0001", "name": "Initial Access"},
				"technique": {"uid": "T1078", "name": "Valid Accounts"}
			}
		]
	}`

	var f DetectionFinding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.ClassUID != ClassDetectionFinding {
		t.Errorf("class_uid = %d, want %d", f.ClassUID, ClassDetectionFinding)
	}
	if len(f.Attacks) != 1 {
		t.Fatalf("attacks count = %d, want 1", len(f.Attacks))
	}
	if f.Attacks[0].Technique.UID != "T1078" {
		t.Errorf("technique.uid = %s, want T1078", f.Attacks[0].Technique.UID)
	}
}

func TestDataSecurityFindingJSON(t *testing.T) {
	raw := `{
		"activity_id": 1,
		"category_uid": 2,
		"class_uid": 2006,
		"severity_id": 4,
		"severity": "High",
		"message": "PII data found in S3 bucket",
		"metadata": {
			"product": {
				"name": "Macie",
				"vendor_name": "AWS"
			}
		},
		"data_security": {
			"classification": "PII",
			"data_type": "SSN",
			"status": "DETECTED"
		}
	}`

	var f DataSecurityFinding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.ClassUID != ClassDataSecurityFind {
		t.Errorf("class_uid = %d, want %d", f.ClassUID, ClassDataSecurityFind)
	}
	if f.DataSecurity.Classification != "PII" {
		t.Errorf("data_security.classification = %s, want PII", f.DataSecurity.Classification)
	}
}

func TestParseFindingDispatch(t *testing.T) {
	cases := []struct {
		name     string
		classUID int32
	}{
		{"SecurityFinding", ClassSecurityFinding},
		{"VulnerabilityFinding", ClassVulnerabilityFind},
		{"ComplianceFinding", ClassComplianceFinding},
		{"DetectionFinding", ClassDetectionFinding},
		{"DataSecurityFinding", ClassDataSecurityFind},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]interface{}{
				"class_uid":   tc.classUID,
				"activity_id": 1,
				"severity_id": 3,
				"metadata":    map[string]interface{}{"product": map[string]interface{}{"name": "test"}},
			})
			finding, err := ParseFinding(data)
			if err != nil {
				t.Fatalf("ParseFinding: %v", err)
			}
			if finding == nil {
				t.Fatal("ParseFinding returned nil")
			}
		})
	}
}

func TestParseFindingUnknownClass(t *testing.T) {
	data := []byte(`{"class_uid": 9999}`)
	_, err := ParseFinding(data)
	if err == nil {
		t.Fatal("expected error for unknown class_uid")
	}
}

func TestValidateSecurityFinding(t *testing.T) {
	valid := &SecurityFinding{
		ActivityID:  ActivityCreate,
		ClassUID:    ClassSecurityFinding,
		SeverityID:  SeverityHigh,
		Metadata:    Metadata{Product: &Product{Name: "test"}},
	}
	if err := ValidateSecurityFinding(valid); err != nil {
		t.Errorf("valid finding should pass: %v", err)
	}

	invalid := &SecurityFinding{
		ClassUID:   ClassSecurityFinding,
		SeverityID: 999,
	}
	err := ValidateSecurityFinding(invalid)
	if err == nil {
		t.Fatal("expected validation error")
	}
	ve := err.(*ValidationError)
	if len(ve.Errors) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestTimeSerializationEpochMillis(t *testing.T) {
	ts := NewTime(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
	data, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var ts2 Time
	if err := json.Unmarshal(data, &ts2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !ts.Time.Equal(ts2.Time) {
		t.Errorf("time mismatch: %v vs %v", ts.Time, ts2.Time)
	}
}

func TestTimeSerializationRFC3339Fallback(t *testing.T) {
	data := []byte(`"2025-06-15T12:00:00Z"`)
	var ts Time
	if err := json.Unmarshal(data, &ts); err != nil {
		t.Fatalf("unmarshal RFC3339: %v", err)
	}
	expected := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	if !ts.Time.Equal(expected) {
		t.Errorf("time = %v, want %v", ts.Time, expected)
	}
}
