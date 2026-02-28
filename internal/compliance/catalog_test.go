package compliance

import (
	"testing"
)

func TestLoadCatalog(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}
	if len(cat.Frameworks) < 2 {
		t.Fatalf("expected at least 2 frameworks, got %d", len(cat.Frameworks))
	}
}

func TestLoadCatalogFrameworkIDs(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	expectedIDs := map[string]bool{
		"nist-csf-2.0": false,
		"cis-aws-1.4":  false,
	}
	for _, fw := range cat.Frameworks {
		if _, ok := expectedIDs[fw.ID]; ok {
			expectedIDs[fw.ID] = true
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected framework %q not found", id)
		}
	}
}

func TestLoadCatalogNISTStructure(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	nist := cat.GetFramework("nist-csf-2.0")
	if nist == nil {
		t.Fatal("NIST CSF 2.0 framework not found")
	}
	if nist.Name != "NIST Cybersecurity Framework" {
		t.Errorf("name = %q, want %q", nist.Name, "NIST Cybersecurity Framework")
	}
	if nist.Version != "2.0" {
		t.Errorf("version = %q, want %q", nist.Version, "2.0")
	}
	if len(nist.Functions) == 0 {
		t.Fatal("expected NIST functions, got 0")
	}

	// Verify known functions exist
	fnIDs := make(map[string]bool)
	for _, fn := range nist.Functions {
		fnIDs[fn.ID] = true
	}
	for _, expected := range []string{"GV", "ID", "PR", "DE", "RS", "RC"} {
		if !fnIDs[expected] {
			t.Errorf("expected NIST function %q not found", expected)
		}
	}
}

func TestLoadCatalogCISStructure(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	cis := cat.GetFramework("cis-aws-1.4")
	if cis == nil {
		t.Fatal("CIS AWS 1.4 framework not found")
	}
	if cis.Version != "1.4.0" {
		t.Errorf("version = %q, want %q", cis.Version, "1.4.0")
	}
	if len(cis.Functions) == 0 {
		t.Fatal("expected CIS sections, got 0")
	}
}

func TestGetFrameworkFound(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	fw := cat.GetFramework("nist-csf-2.0")
	if fw == nil {
		t.Fatal("GetFramework returned nil for existing framework")
	}
	if fw.ID != "nist-csf-2.0" {
		t.Errorf("ID = %q, want %q", fw.ID, "nist-csf-2.0")
	}
}

func TestGetFrameworkNotFound(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	fw := cat.GetFramework("nonexistent")
	if fw != nil {
		t.Errorf("expected nil for nonexistent framework, got %+v", fw)
	}
}

func TestLookupControlAWS(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	// S3.4 is mapped to PR.DS-01 in NIST CSF
	refs := cat.LookupControl("S3.4")
	if len(refs) == 0 {
		t.Fatal("expected control refs for S3.4, got 0")
	}

	found := false
	for _, ref := range refs {
		if ref.FrameworkID == "nist-csf-2.0" && ref.ControlID == "PR.DS-01" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected S3.4 to map to nist-csf-2.0/PR.DS-01, got %+v", refs)
	}
}

func TestLookupControlCaseInsensitive(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	lower := cat.LookupControl("s3.4")
	upper := cat.LookupControl("S3.4")

	if len(lower) != len(upper) {
		t.Errorf("case mismatch: lower=%d refs, upper=%d refs", len(lower), len(upper))
	}
}

func TestLookupControlNotFound(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	refs := cat.LookupControl("NONEXISTENT.999")
	if len(refs) != 0 {
		t.Errorf("expected 0 refs for nonexistent control, got %d", len(refs))
	}
}

func TestLookupControlCrossFramework(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	// IAM.6 is mapped in both NIST CSF (PR.AA-01) and CIS AWS (1.5, 1.6)
	refs := cat.LookupControl("IAM.6")
	if len(refs) < 2 {
		t.Fatalf("expected IAM.6 to map to at least 2 framework controls, got %d", len(refs))
	}

	frameworks := make(map[string]bool)
	for _, ref := range refs {
		frameworks[ref.FrameworkID] = true
	}
	if !frameworks["nist-csf-2.0"] {
		t.Error("expected IAM.6 to map to nist-csf-2.0")
	}
	if !frameworks["cis-aws-1.4"] {
		t.Error("expected IAM.6 to map to cis-aws-1.4")
	}
}

func TestControlsHaveAWSMappings(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() error: %v", err)
	}

	// Verify that the control index is not empty
	if len(cat.controlIndex) == 0 {
		t.Fatal("control index is empty after loading catalogs")
	}

	// Spot-check a few known AWS control mappings
	checks := []struct {
		awsControl  string
		frameworkID string
	}{
		{"CloudTrail.1", "nist-csf-2.0"},
		{"CloudTrail.1", "cis-aws-1.4"},
		{"EBS.1", "nist-csf-2.0"},
		{"EBS.1", "cis-aws-1.4"},
		{"VPC.1", "nist-csf-2.0"},
		{"VPC.1", "cis-aws-1.4"},
	}
	for _, tc := range checks {
		refs := cat.LookupControl(tc.awsControl)
		found := false
		for _, ref := range refs {
			if ref.FrameworkID == tc.frameworkID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s to map to %s", tc.awsControl, tc.frameworkID)
		}
	}
}
