package githubghasreceiver

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v60/github"

	"github.com/cloud-security-fabric/csf/internal/ocsf"
)

func TestMapCodeScanningToOCSF(t *testing.T) {
	alert := &github.Alert{
		Number: github.Int(42),
		Rule: &github.Rule{
			ID:          github.String("js/sql-injection"),
			Severity:    github.String("error"),
			Description: github.String("SQL injection vulnerability"),
		},
		MostRecentInstance: &github.MostRecentInstance{
			Location: &github.Location{
				Path:      github.String("src/db.js"),
				StartLine: github.Int(15),
				EndLine:   github.Int(20),
			},
			Message: &github.Message{
				Text: github.String("Unsanitized user input used in SQL query"),
			},
		},
	}

	data, err := MapCodeScanningToOCSF(alert, "myorg", "myrepo")
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
	if vf.SeverityID != ocsf.SeverityHigh {
		t.Errorf("severity_id = %d, want %d", vf.SeverityID, ocsf.SeverityHigh)
	}
	if len(vf.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities count = %d, want 1", len(vf.Vulnerabilities))
	}
	if vf.Vulnerabilities[0].UID != "js/sql-injection" {
		t.Errorf("vuln uid = %s", vf.Vulnerabilities[0].UID)
	}
	if vf.Vulnerabilities[0].AffectedCode[0].FilePath != "src/db.js" {
		t.Errorf("affected_code path = %s", vf.Vulnerabilities[0].AffectedCode[0].FilePath)
	}
}

func TestMapDependabotToOCSF(t *testing.T) {
	alert := &github.DependabotAlert{
		Number: github.Int(7),
		SecurityAdvisory: &github.DependabotSecurityAdvisory{
			GHSAID:   github.String("GHSA-xxxx-yyyy-zzzz"),
			Summary:  github.String("RCE in package foo"),
			Severity: github.String("critical"),
			Description: github.String("A critical RCE vulnerability exists in foo < 2.0"),
			Identifiers: []*github.AdvisoryIdentifier{
				{Type: github.String("CVE"), Value: github.String("CVE-2024-9999")},
				{Type: github.String("GHSA"), Value: github.String("GHSA-xxxx-yyyy-zzzz")},
			},
			CVSS: &github.AdvisoryCVSS{
				Score:        float64Ptr(9.8),
				VectorString: github.String("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			},
		},
		Dependency: &github.Dependency{
			Package: &github.VulnerabilityPackage{
				Name:      github.String("foo"),
				Ecosystem: github.String("npm"),
			},
			ManifestPath: github.String("package-lock.json"),
		},
	}

	data, err := MapDependabotToOCSF(alert, "myorg", "myrepo")
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
		t.Fatal("expected 1 vulnerability")
	}
	vuln := vf.Vulnerabilities[0]
	if vuln.CVE == nil || vuln.CVE.UID != "CVE-2024-9999" {
		t.Errorf("cve uid = %v", vuln.CVE)
	}
	if vuln.Packages[0].Name != "foo" {
		t.Errorf("package name = %s", vuln.Packages[0].Name)
	}
}

func TestMapSecretScanningToOCSF(t *testing.T) {
	alert := &github.SecretScanningAlert{
		Number:                github.Int(3),
		SecretType:            github.String("aws_access_key_id"),
		SecretTypeDisplayName: github.String("AWS Access Key ID"),
		HTMLURL:               github.String("https://github.com/myorg/myrepo/security/secret-scanning/3"),
	}

	data, err := MapSecretScanningToOCSF(alert, "myorg", "myrepo")
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ocsf.ParseFinding(data)
	if err != nil {
		t.Fatal(err)
	}

	sf, ok := parsed.(*ocsf.SecurityFinding)
	if !ok {
		t.Fatalf("expected SecurityFinding, got %T", parsed)
	}
	if sf.SeverityID != ocsf.SeverityHigh {
		t.Errorf("severity_id = %d, want %d", sf.SeverityID, ocsf.SeverityHigh)
	}
	if sf.Unmapped["secret_type"] != "aws_access_key_id" {
		t.Errorf("secret_type = %v", sf.Unmapped["secret_type"])
	}
	if sf.FindingInfo.SrcURL != "https://github.com/myorg/myrepo/security/secret-scanning/3" {
		t.Errorf("src_url = %s", sf.FindingInfo.SrcURL)
	}
}

func TestCodeScanningSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		wantID   int32
	}{
		{"error", ocsf.SeverityHigh},
		{"warning", ocsf.SeverityMedium},
		{"note", ocsf.SeverityLow},
		{"", ocsf.SeverityInformational},
	}

	for _, tc := range tests {
		alert := &github.Alert{
			Rule: &github.Rule{Severity: github.String(tc.severity)},
		}
		id, _ := mapCodeScanningSeverity(alert)
		if id != tc.wantID {
			t.Errorf("severity %q: got %d, want %d", tc.severity, id, tc.wantID)
		}
	}
}

func TestDependabotSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		wantID   int32
	}{
		{"critical", ocsf.SeverityCritical},
		{"high", ocsf.SeverityHigh},
		{"medium", ocsf.SeverityMedium},
		{"low", ocsf.SeverityLow},
		{"", ocsf.SeverityUnknown},
	}

	for _, tc := range tests {
		alert := &github.DependabotAlert{
			SecurityAdvisory: &github.DependabotSecurityAdvisory{
				Severity: github.String(tc.severity),
			},
		}
		id, _ := mapDependabotSeverity(alert)
		if id != tc.wantID {
			t.Errorf("severity %q: got %d, want %d", tc.severity, id, tc.wantID)
		}
	}
}

func float64Ptr(v float64) *float64 { return &v }

func TestOCSFOutputValidity(t *testing.T) {
	// Ensure all mappers produce valid JSON and valid OCSF
	alert := &github.Alert{
		Number: github.Int(1),
		Rule:   &github.Rule{ID: github.String("test"), Severity: github.String("warning")},
	}
	data, _ := MapCodeScanningToOCSF(alert, "org", "repo")
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON from CodeScanning mapper: %v", err)
	}
	if m["class_uid"].(float64) != float64(ocsf.ClassVulnerabilityFind) {
		t.Error("wrong class_uid")
	}
}
