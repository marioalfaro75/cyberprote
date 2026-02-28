package threatintel

import (
	"testing"
)

func TestLoadAttackMatrix(t *testing.T) {
	m, err := LoadAttackMatrix()
	if err != nil {
		t.Fatalf("LoadAttackMatrix() error: %v", err)
	}

	if m.Version == "" {
		t.Error("expected non-empty version")
	}
	if m.Domain != "enterprise" {
		t.Errorf("domain = %q, want enterprise", m.Domain)
	}
	if len(m.Tactics) < 10 {
		t.Errorf("expected at least 10 tactics, got %d", len(m.Tactics))
	}
}

func TestGetTactic(t *testing.T) {
	m, err := LoadAttackMatrix()
	if err != nil {
		t.Fatalf("LoadAttackMatrix() error: %v", err)
	}

	tac := m.GetTactic("TA0001")
	if tac == nil {
		t.Fatal("GetTactic(TA0001) returned nil")
	}
	if tac.Name != "Initial Access" {
		t.Errorf("tactic name = %q, want Initial Access", tac.Name)
	}

	if m.GetTactic("TA9999") != nil {
		t.Error("GetTactic(TA9999) should return nil")
	}
}

func TestGetTechnique(t *testing.T) {
	m, err := LoadAttackMatrix()
	if err != nil {
		t.Fatalf("LoadAttackMatrix() error: %v", err)
	}

	tech := m.GetTechnique("T1078")
	if tech == nil {
		t.Fatal("GetTechnique(T1078) returned nil")
	}
	if tech.Name != "Valid Accounts" {
		t.Errorf("technique name = %q, want Valid Accounts", tech.Name)
	}

	if m.GetTechnique("T9999") != nil {
		t.Error("GetTechnique(T9999) should return nil")
	}
}

func TestAllTactics(t *testing.T) {
	m, err := LoadAttackMatrix()
	if err != nil {
		t.Fatalf("LoadAttackMatrix() error: %v", err)
	}

	tactics := m.AllTactics()
	if len(tactics) == 0 {
		t.Fatal("AllTactics() returned empty slice")
	}
	if tactics[0].UID == "" {
		t.Error("first tactic has empty UID")
	}
}

func TestCWEToAttackMapping(t *testing.T) {
	// Spot-check some well-known mappings
	tests := []struct {
		cwe       string
		wantTech  string
	}{
		{"CWE-89", "T1190"},
		{"CWE-78", "T1059"},
		{"CWE-287", "T1078"},
		{"CWE-798", "T1552"},
	}
	for _, tt := range tests {
		techs, ok := CWEToAttackTechniques[tt.cwe]
		if !ok {
			t.Errorf("CWEToAttackTechniques[%s] not found", tt.cwe)
			continue
		}
		found := false
		for _, tech := range techs {
			if tech == tt.wantTech {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CWEToAttackTechniques[%s] = %v, want to contain %s", tt.cwe, techs, tt.wantTech)
		}
	}
}
