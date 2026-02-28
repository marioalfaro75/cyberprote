package ocsftransformprocessor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

func TestOCSFProcessorPassthroughValid(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{CSFExtensions: true}
	p, err := newOCSFProcessor(cfg, zap.NewNop(), sink)
	if err != nil {
		t.Fatal(err)
	}

	finding := map[string]interface{}{
		"class_uid":   2001,
		"activity_id": 1,
		"severity_id": 4,
		"metadata":    map[string]interface{}{"product": map[string]interface{}{"name": "test"}},
		"message":     "Test finding",
	}
	body, _ := json.Marshal(finding)

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("csf.source.platform", "aws")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr(string(body))

	err = p.ConsumeLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}

	if sink.LogRecordCount() != 1 {
		t.Errorf("expected 1 log record passed to sink, got %d", sink.LogRecordCount())
	}
}

func TestOCSFProcessorValidationError(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{CSFExtensions: true}
	p, err := newOCSFProcessor(cfg, zap.NewNop(), sink)
	if err != nil {
		t.Fatal(err)
	}

	// Invalid: missing required fields
	finding := map[string]interface{}{
		"class_uid":   2001,
		"severity_id": 999, // invalid severity
	}
	body, _ := json.Marshal(finding)

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr(string(body))

	err = p.ConsumeLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("ConsumeLogs should not return error: %v", err)
	}

	if p.validationErrors.Load() == 0 {
		t.Error("expected validation errors to be counted")
	}
}

func TestDetectPlatform(t *testing.T) {
	rl := plog.NewResourceLogs()
	rl.Resource().Attributes().PutStr("csf.source.platform", "aws")
	if got := detectPlatform(rl); got != "aws" {
		t.Errorf("detectPlatform = %s, want aws", got)
	}

	rl2 := plog.NewResourceLogs()
	rl2.Resource().Attributes().PutStr("cloud.provider", "gcp")
	if got := detectPlatform(rl2); got != "gcp" {
		t.Errorf("detectPlatform = %s, want gcp", got)
	}

	rl3 := plog.NewResourceLogs()
	if got := detectPlatform(rl3); got != "unknown" {
		t.Errorf("detectPlatform = %s, want unknown", got)
	}
}

func TestEPSSClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := epssResponse{
			Status: "OK",
			Data: []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			}{
				{CVE: "CVE-2024-1234", EPSS: "0.95", Percentile: "0.99"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewEPSSClient(ts.URL)
	score, err := client.GetScore(context.Background(), "CVE-2024-1234")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if score != 0.95 {
		t.Errorf("score = %f, want 0.95", score)
	}

	// Second call should hit cache
	score2, err := client.GetScore(context.Background(), "CVE-2024-1234")
	if err != nil {
		t.Fatalf("GetScore cached: %v", err)
	}
	if score2 != 0.95 {
		t.Errorf("cached score = %f, want 0.95", score2)
	}
}

func TestKEVClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := kevCatalog{
			Title: "CISA KEV",
			Vulnerabilities: []struct {
				CVEID string `json:"cveID"`
			}{
				{CVEID: "CVE-2024-1234"},
				{CVEID: "CVE-2024-5678"},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer ts.Close()

	client := NewKEVClient(ts.URL)

	exploited, err := client.IsKnownExploited(context.Background(), "CVE-2024-1234")
	if err != nil {
		t.Fatalf("IsKnownExploited: %v", err)
	}
	if !exploited {
		t.Error("CVE-2024-1234 should be known exploited")
	}

	notExploited, err := client.IsKnownExploited(context.Background(), "CVE-2099-9999")
	if err != nil {
		t.Fatalf("IsKnownExploited: %v", err)
	}
	if notExploited {
		t.Error("CVE-2099-9999 should not be known exploited")
	}
}

func TestProcessorWithEnrichment(t *testing.T) {
	epssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := epssResponse{
			Status: "OK",
			Data: []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			}{
				{CVE: "CVE-2024-1234", EPSS: "0.87", Percentile: "0.95"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer epssServer.Close()

	kevServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := kevCatalog{
			Title: "CISA KEV",
			Vulnerabilities: []struct {
				CVEID string `json:"cveID"`
			}{
				{CVEID: "CVE-2024-1234"},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer kevServer.Close()

	sink := new(consumertest.LogsSink)
	cfg := &Config{
		EnrichEPSS:      true,
		EnrichKEV:       true,
		EPSSAPIEndpoint: epssServer.URL,
		KEVFeedURL:      kevServer.URL,
	}
	p, err := newOCSFProcessor(cfg, zap.NewNop(), sink)
	if err != nil {
		t.Fatal(err)
	}

	finding := map[string]interface{}{
		"class_uid":   2002,
		"activity_id": 1,
		"severity_id": 4,
		"metadata":    map[string]interface{}{"product": map[string]interface{}{"name": "Inspector"}},
		"vulnerabilities": []map[string]interface{}{
			{
				"uid": "CVE-2024-1234",
				"cve": map[string]interface{}{
					"uid": "CVE-2024-1234",
				},
			},
		},
	}
	body, _ := json.Marshal(finding)

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr(string(body))

	err = p.ConsumeLogs(context.Background(), ld)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the body was enriched
	allLogs := sink.AllLogs()
	if len(allLogs) == 0 {
		t.Fatal("no logs passed to sink")
	}
	enrichedBody := allLogs[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString()
	var enriched map[string]interface{}
	if err := json.Unmarshal([]byte(enrichedBody), &enriched); err != nil {
		t.Fatalf("unmarshal enriched: %v", err)
	}

	vulns := enriched["vulnerabilities"].([]interface{})
	vuln := vulns[0].(map[string]interface{})
	cve := vuln["cve"].(map[string]interface{})

	if cve["epss_score"] == nil {
		t.Error("expected epss_score to be set")
	}
	if cve["is_exploited"] == nil {
		t.Error("expected is_exploited to be set")
	}
}
