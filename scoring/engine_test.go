package scoring

import (
	"testing"
)

func TestDefaultWeightsSum(t *testing.T) {
	w := DefaultWeights()
	sum := w.Severity + w.CVSS + w.EPSS + w.Exposure + w.Privilege + w.AssetValue + w.KEVBonus + w.ToxicCombo
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("weights sum = %f, want ~1.0", sum)
	}
}

func TestComputeScoreCritical(t *testing.T) {
	e := NewDefaultEngine()
	ctx := FindingContext{
		SeverityID:       5, // Critical
		CVSSScore:        9.8,
		EPSSScore:        0.95,
		IsPublicFacing:   true,
		IsAdminAccess:    true,
		IsKEV:            true,
		AssetCriticality: 5,
		ToxicCombos:      2,
	}
	score := e.ComputeScore(ctx)
	if score < 80 {
		t.Errorf("critical finding score = %f, expected >= 80", score)
	}
	if score > 100 {
		t.Errorf("score = %f, should not exceed 100", score)
	}
}

func TestComputeScoreLow(t *testing.T) {
	e := NewDefaultEngine()
	ctx := FindingContext{
		SeverityID:       1, // Informational
		CVSSScore:        2.0,
		EPSSScore:        0.01,
		IsPublicFacing:   false,
		IsAdminAccess:    false,
		IsKEV:            false,
		AssetCriticality: 1,
		ToxicCombos:      0,
	}
	score := e.ComputeScore(ctx)
	if score > 30 {
		t.Errorf("low finding score = %f, expected <= 30", score)
	}
}

func TestComputeScoreZero(t *testing.T) {
	e := NewDefaultEngine()
	ctx := FindingContext{}
	score := e.ComputeScore(ctx)
	if score != 0 {
		t.Errorf("empty context score = %f, want 0", score)
	}
}

func TestComputeScoreBounds(t *testing.T) {
	e := NewDefaultEngine()
	// Max everything
	ctx := FindingContext{
		SeverityID:       6,
		CVSSScore:        10.0,
		EPSSScore:        1.0,
		IsPublicFacing:   true,
		IsAdminAccess:    true,
		IsKEV:            true,
		AssetCriticality: 5,
		ToxicCombos:      10,
	}
	score := e.ComputeScore(ctx)
	if score > 100 {
		t.Errorf("max score = %f, should not exceed 100", score)
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		id    int32
		want  float64
	}{
		{0, 0}, {1, 10}, {2, 30}, {3, 50}, {4, 75}, {5, 95}, {6, 100},
	}
	for _, tc := range tests {
		got := mapSeverityToScore(tc.id)
		if got != tc.want {
			t.Errorf("severity %d: got %f, want %f", tc.id, got, tc.want)
		}
	}
}
