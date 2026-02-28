package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestShodanClientLookup(t *testing.T) {
	fixture, err := os.ReadFile("testdata/shodan_response.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/93.184.216.34" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(fixture)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewShodanClient()
	client.baseURL = srv.URL

	// Test successful lookup
	result, err := client.Lookup(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}
	if result == nil {
		t.Fatal("Lookup() returned nil result")
	}
	if result.IP != "93.184.216.34" {
		t.Errorf("IP = %q, want 93.184.216.34", result.IP)
	}
	if len(result.Ports) != 3 {
		t.Errorf("len(Ports) = %d, want 3", len(result.Ports))
	}
	if len(result.Vulns) != 2 {
		t.Errorf("len(Vulns) = %d, want 2", len(result.Vulns))
	}

	// Test cache hit
	result2, err := client.Lookup(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("cached Lookup() error: %v", err)
	}
	if result2 == nil {
		t.Fatal("cached Lookup() returned nil")
	}

	// Test not found
	result3, err := client.Lookup(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("Lookup(not found) error: %v", err)
	}
	if result3 != nil {
		t.Error("Lookup(not found) should return nil result")
	}
}
