package compliance

import (
	"testing"

	"github.com/cloud-security-fabric/csf/internal/graph"
)

func TestPostureScoreAllPass(t *testing.T) {
	ps := PostureStatus{Pass: 10, Fail: 0, Unknown: 0}
	if s := ps.Score(); s != 100 {
		t.Errorf("Score() = %f, want 100", s)
	}
}

func TestPostureScoreAllFail(t *testing.T) {
	ps := PostureStatus{Pass: 0, Fail: 10, Unknown: 0}
	if s := ps.Score(); s != 0 {
		t.Errorf("Score() = %f, want 0", s)
	}
}

func TestPostureScoreMixed(t *testing.T) {
	ps := PostureStatus{Pass: 3, Fail: 1, Unknown: 1}
	want := 60.0
	if s := ps.Score(); s != want {
		t.Errorf("Score() = %f, want %f", s, want)
	}
}

func TestPostureScoreNoData(t *testing.T) {
	ps := PostureStatus{}
	if s := ps.Score(); s != -1 {
		t.Errorf("Score() = %f, want -1 (no data)", s)
	}
}

func TestClassifyComplianceStatus(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"pass", "pass"},
		{"PASS", "pass"},
		{"passed", "pass"},
		{"Passed", "pass"},
		{"compliant", "pass"},
		{"fail", "fail"},
		{"FAIL", "fail"},
		{"failed", "fail"},
		{"Failed", "fail"},
		{"non_compliant", "fail"},
		{"not_available", "fail"},
		{"", "unknown"},
		{"something_else", "unknown"},
		{"warning", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := classifyComplianceStatus(tc.input)
			if got != tc.want {
				t.Errorf("classifyComplianceStatus(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestIndexFindings(t *testing.T) {
	findings := []graph.ComplianceFindingRow{
		{UID: "f1", ComplianceControl: "S3.4"},
		{UID: "f2", ComplianceControl: "s3.4"},
		{UID: "f3", ComplianceControl: "IAM.1"},
		{UID: "f4", ComplianceControl: ""},
	}

	idx := indexFindings(findings)

	// S3.4 and s3.4 should both index under "S3.4"
	if len(idx["S3.4"]) != 2 {
		t.Errorf("expected 2 findings for S3.4, got %d", len(idx["S3.4"]))
	}
	if len(idx["IAM.1"]) != 1 {
		t.Errorf("expected 1 finding for IAM.1, got %d", len(idx["IAM.1"]))
	}
	// Empty control should be skipped
	if len(idx[""]) != 0 {
		t.Errorf("expected 0 findings for empty control, got %d", len(idx[""]))
	}
}

func testFramework() *Framework {
	return &Framework{
		ID:      "test-fw",
		Name:    "Test Framework",
		Version: "1.0",
		Functions: []Function{
			{
				ID:   "FN1",
				Name: "Function One",
				Categories: []Category{
					{
						ID:   "FN1.C1",
						Name: "Category One",
						Controls: []Control{
							{
								ID:          "FN1.C1-01",
								Name:        "Control Alpha",
								AWSControls: []string{"S3.4", "EBS.1"},
							},
							{
								ID:          "FN1.C1-02",
								Name:        "Control Beta",
								AWSControls: []string{"IAM.1"},
							},
						},
					},
				},
			},
			{
				ID:   "FN2",
				Name: "Function Two",
				Categories: []Category{
					{
						ID:   "FN2.C1",
						Name: "Category Two",
						Controls: []Control{
							{
								ID:          "FN2.C1-01",
								Name:        "Control Gamma",
								AWSControls: []string{"VPC.1"},
							},
						},
					},
				},
			},
		},
	}
}

func TestComputePostureNoFindings(t *testing.T) {
	fw := testFramework()
	posture := ComputePosture(fw, nil)

	if posture.FrameworkID != "test-fw" {
		t.Errorf("FrameworkID = %q, want %q", posture.FrameworkID, "test-fw")
	}
	if posture.Score != -1 {
		t.Errorf("Score = %f, want -1 (no data)", posture.Score)
	}
	if posture.Status.Pass != 0 || posture.Status.Fail != 0 || posture.Status.Unknown != 0 {
		t.Errorf("expected zero status, got %+v", posture.Status)
	}
	if len(posture.Functions) != 2 {
		t.Errorf("expected 2 functions, got %d", len(posture.Functions))
	}
}

func TestComputePostureWithFindings(t *testing.T) {
	fw := testFramework()
	findings := []graph.ComplianceFindingRow{
		{UID: "f1", ComplianceControl: "S3.4", ComplianceStatus: "pass", SeverityID: 2, Provider: "AWS"},
		{UID: "f2", ComplianceControl: "EBS.1", ComplianceStatus: "fail", SeverityID: 4, Provider: "AWS"},
		{UID: "f3", ComplianceControl: "IAM.1", ComplianceStatus: "passed", SeverityID: 1, Provider: "AWS"},
		{UID: "f4", ComplianceControl: "VPC.1", ComplianceStatus: "non_compliant", SeverityID: 3, Provider: "AWS"},
	}

	posture := ComputePosture(fw, findings)

	// Framework total: 2 pass, 2 fail
	if posture.Status.Pass != 2 {
		t.Errorf("total pass = %d, want 2", posture.Status.Pass)
	}
	if posture.Status.Fail != 2 {
		t.Errorf("total fail = %d, want 2", posture.Status.Fail)
	}
	if posture.Score != 50 {
		t.Errorf("Score = %f, want 50", posture.Score)
	}

	// FN1 should have 2 pass + 1 fail
	fn1 := posture.Functions[0]
	if fn1.Status.Pass != 2 {
		t.Errorf("FN1 pass = %d, want 2", fn1.Status.Pass)
	}
	if fn1.Status.Fail != 1 {
		t.Errorf("FN1 fail = %d, want 1", fn1.Status.Fail)
	}

	// FN2 should have 0 pass + 1 fail
	fn2 := posture.Functions[1]
	if fn2.Status.Pass != 0 {
		t.Errorf("FN2 pass = %d, want 0", fn2.Status.Pass)
	}
	if fn2.Status.Fail != 1 {
		t.Errorf("FN2 fail = %d, want 1", fn2.Status.Fail)
	}
}

func TestComputePostureControlDrilldown(t *testing.T) {
	fw := testFramework()
	findings := []graph.ComplianceFindingRow{
		{UID: "f1", ComplianceControl: "S3.4", ComplianceStatus: "pass", Title: "S3 bucket encrypted", Provider: "AWS"},
		{UID: "f2", ComplianceControl: "S3.4", ComplianceStatus: "fail", Title: "S3 bucket unencrypted", Provider: "AWS"},
	}

	posture := ComputePosture(fw, findings)

	// Control FN1.C1-01 maps S3.4 and EBS.1; should have 2 findings from S3.4
	ctrl := posture.Functions[0].Categories[0].Controls[0]
	if ctrl.ID != "FN1.C1-01" {
		t.Fatalf("expected control FN1.C1-01, got %s", ctrl.ID)
	}
	if len(ctrl.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(ctrl.Findings))
	}
	if ctrl.Status.Pass != 1 || ctrl.Status.Fail != 1 {
		t.Errorf("control status = %+v, want 1 pass / 1 fail", ctrl.Status)
	}
}

func TestComputePostureDeduplicatesFindings(t *testing.T) {
	// A control maps both S3.4 and EBS.1. If a finding has control "S3.4",
	// it should only appear once, not twice.
	fw := &Framework{
		ID:      "dedup-fw",
		Name:    "Dedup Test",
		Version: "1.0",
		Functions: []Function{
			{
				ID:   "F1",
				Name: "Func",
				Categories: []Category{
					{
						ID:   "F1.C1",
						Name: "Cat",
						Controls: []Control{
							{
								ID:          "F1.C1-01",
								Name:        "Ctrl",
								AWSControls: []string{"S3.4", "S3.4"}, // duplicate mapping
							},
						},
					},
				},
			},
		},
	}
	findings := []graph.ComplianceFindingRow{
		{UID: "f1", ComplianceControl: "S3.4", ComplianceStatus: "pass"},
	}

	posture := ComputePosture(fw, findings)
	ctrl := posture.Functions[0].Categories[0].Controls[0]
	if len(ctrl.Findings) != 1 {
		t.Errorf("expected 1 finding (deduped), got %d", len(ctrl.Findings))
	}
}

func TestComputePostureUnknownStatus(t *testing.T) {
	fw := testFramework()
	findings := []graph.ComplianceFindingRow{
		{UID: "f1", ComplianceControl: "S3.4", ComplianceStatus: "warning"},
	}

	posture := ComputePosture(fw, findings)
	if posture.Status.Unknown != 1 {
		t.Errorf("unknown = %d, want 1", posture.Status.Unknown)
	}
	if posture.Status.Pass != 0 || posture.Status.Fail != 0 {
		t.Errorf("expected 0 pass / 0 fail, got %+v", posture.Status)
	}
}

func TestComputePostureWithEmbeddedCatalog(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	nist := cat.GetFramework("nist-csf-2.0")
	if nist == nil {
		t.Fatal("NIST CSF 2.0 not found")
	}

	findings := []graph.ComplianceFindingRow{
		{UID: "f1", ComplianceControl: "S3.4", ComplianceStatus: "pass", Provider: "AWS", SeverityID: 2},
		{UID: "f2", ComplianceControl: "IAM.1", ComplianceStatus: "fail", Provider: "AWS", SeverityID: 4},
		{UID: "f3", ComplianceControl: "CloudTrail.1", ComplianceStatus: "pass", Provider: "AWS", SeverityID: 1},
	}

	posture := ComputePosture(nist, findings)

	if posture.FrameworkID != "nist-csf-2.0" {
		t.Errorf("FrameworkID = %q, want %q", posture.FrameworkID, "nist-csf-2.0")
	}
	total := posture.Status.Pass + posture.Status.Fail + posture.Status.Unknown
	if total != 3 {
		t.Errorf("total findings = %d, want 3", total)
	}
	if posture.Score < 0 || posture.Score > 100 {
		t.Errorf("Score = %f, want 0-100", posture.Score)
	}
}

func TestComputePostureFindingRefFields(t *testing.T) {
	fw := testFramework()
	findings := []graph.ComplianceFindingRow{
		{
			UID:              "finding-123",
			Title:            "My Finding",
			SeverityID:       4,
			ComplianceStatus: "fail",
			ComplianceControl: "S3.4",
			Provider:         "AWS",
		},
	}

	posture := ComputePosture(fw, findings)
	ctrl := posture.Functions[0].Categories[0].Controls[0]
	if len(ctrl.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(ctrl.Findings))
	}

	ref := ctrl.Findings[0]
	if ref.UID != "finding-123" {
		t.Errorf("UID = %q, want %q", ref.UID, "finding-123")
	}
	if ref.Title != "My Finding" {
		t.Errorf("Title = %q, want %q", ref.Title, "My Finding")
	}
	if ref.SeverityID != 4 {
		t.Errorf("SeverityID = %d, want 4", ref.SeverityID)
	}
	if ref.ComplianceStatus != "fail" {
		t.Errorf("ComplianceStatus = %q, want %q", ref.ComplianceStatus, "fail")
	}
	if ref.Provider != "AWS" {
		t.Errorf("Provider = %q, want %q", ref.Provider, "AWS")
	}
}
