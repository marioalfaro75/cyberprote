package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNVDClientGetCVE(t *testing.T) {
	fixture, err := os.ReadFile("testdata/nvd_response.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cveID := r.URL.Query().Get("cveId")
		if cveID == "CVE-2021-44228" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(fixture)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()

	client := NewNVDClient()
	client.baseURL = srv.URL

	// Test successful lookup
	detail, err := client.GetCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetCVE() error: %v", err)
	}
	if detail.ID != "CVE-2021-44228" {
		t.Errorf("ID = %q, want CVE-2021-44228", detail.ID)
	}
	if detail.CVSS3Score != 10.0 {
		t.Errorf("CVSS3Score = %f, want 10.0", detail.CVSS3Score)
	}
	if len(detail.CWEs) == 0 || detail.CWEs[0] != "CWE-502" {
		t.Errorf("CWEs = %v, want [CWE-502]", detail.CWEs)
	}
	if len(detail.References) != 2 {
		t.Errorf("len(References) = %d, want 2", len(detail.References))
	}
	if detail.Description == "" {
		t.Error("Description should not be empty")
	}

	// Test cache hit
	detail2, err := client.GetCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("cached GetCVE() error: %v", err)
	}
	if detail2.ID != "CVE-2021-44228" {
		t.Error("cached result should match")
	}

	// Test not found
	_, err = client.GetCVE(context.Background(), "CVE-9999-99999")
	if err == nil {
		t.Error("GetCVE(unknown) should return error")
	}
}
