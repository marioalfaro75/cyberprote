package graph

import (
	"testing"
)

func TestPropsJSON(t *testing.T) {
	props := map[string]interface{}{
		"uid":   "test-123",
		"name":  "test resource",
		"count": 42,
	}
	result := propsJSON(props)
	if result == "{}" {
		t.Fatal("propsJSON returned empty object for non-empty map")
	}
	if len(result) < 10 {
		t.Errorf("propsJSON result too short: %s", result)
	}
}

func TestEscapeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"it's", "it\\'s"},
		{"a'b'c", "a\\'b\\'c"},
		{"", ""},
	}
	for _, tc := range tests {
		got := escapeString(tc.input)
		if got != tc.expected {
			t.Errorf("escapeString(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestToxicCombinationQueriesExist(t *testing.T) {
	expectedQueries := []string{
		"public_facing_critical_vuln",
		"admin_credential_exposure",
		"lateral_movement_path",
		"overprivileged_sensitive_access",
		"unpatched_internet_exposed",
		"cross_account_assumption",
		"multi_critical_findings",
		"data_exposure_public",
		"compliance_gap_critical_infra",
		"cross_account_access",
		"kev_exploitable_vuln",
		"shadow_admin",
	}
	for _, name := range expectedQueries {
		if _, ok := ToxicCombinationQueries[name]; !ok {
			t.Errorf("missing toxic combination query: %s", name)
		}
	}
}

func TestEdgeTypes(t *testing.T) {
	edges := []EdgeType{
		EdgeAFFECTS, EdgeEXPLOITS, EdgeHAS_ACCESS,
		EdgeASSUMES, EdgeEXPOSES, EdgeBELONGS_TO,
		EdgeCONTAINS, EdgeDEPENDS_ON, EdgeHAS_FINDING,
		EdgeHOSTS, EdgeREMEDIATES,
	}
	for _, e := range edges {
		if string(e) == "" {
			t.Error("empty edge type")
		}
	}
}
