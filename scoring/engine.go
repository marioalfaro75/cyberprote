// Package scoring implements the composite risk scoring engine for the
// Cloud Security Fabric. Scores range from 0-100.
package scoring

import (
	"math"
)

// Weights controls the relative importance of each scoring factor.
type Weights struct {
	Severity      float64 `yaml:"severity"`
	CVSS          float64 `yaml:"cvss"`
	EPSS          float64 `yaml:"epss"`
	Exposure      float64 `yaml:"exposure"`
	Privilege     float64 `yaml:"privilege"`
	AssetValue    float64 `yaml:"asset_value"`
	KEVBonus      float64 `yaml:"kev_bonus"`
	ToxicCombo    float64 `yaml:"toxic_combo"`
}

// DefaultWeights returns the default scoring weights.
func DefaultWeights() Weights {
	return Weights{
		Severity:   0.20,
		CVSS:       0.20,
		EPSS:       0.15,
		Exposure:   0.15,
		Privilege:  0.10,
		AssetValue: 0.10,
		KEVBonus:   0.05,
		ToxicCombo: 0.05,
	}
}

// FindingContext holds all inputs needed to compute a risk score.
type FindingContext struct {
	SeverityID     int32
	CVSSScore      float64
	EPSSScore      float64
	IsPublicFacing bool
	IsAdminAccess  bool
	IsKEV          bool
	AssetCriticality int // 1-5, where 5 is most critical
	ToxicCombos    int  // number of toxic combinations this finding participates in
}

// Engine computes risk scores based on configurable weights.
type Engine struct {
	weights Weights
}

// NewEngine creates a scoring engine with the given weights.
func NewEngine(weights Weights) *Engine {
	return &Engine{weights: weights}
}

// NewDefaultEngine creates a scoring engine with default weights.
func NewDefaultEngine() *Engine {
	return NewEngine(DefaultWeights())
}

// ComputeScore calculates a composite risk score (0-100) for a finding.
func (e *Engine) ComputeScore(ctx FindingContext) float64 {
	var score float64

	// Severity component (0-100 based on severity_id)
	severityScore := mapSeverityToScore(ctx.SeverityID)
	score += severityScore * e.weights.Severity

	// CVSS component (0-100, normalized from 0-10)
	cvssScore := math.Min(ctx.CVSSScore*10, 100)
	score += cvssScore * e.weights.CVSS

	// EPSS component (0-100, normalized from 0-1)
	epssScore := math.Min(ctx.EPSSScore*100, 100)
	score += epssScore * e.weights.EPSS

	// Exposure component (binary: 0 or 100)
	exposureScore := 0.0
	if ctx.IsPublicFacing {
		exposureScore = 100
	}
	score += exposureScore * e.weights.Exposure

	// Privilege component (binary: 0 or 100)
	privScore := 0.0
	if ctx.IsAdminAccess {
		privScore = 100
	}
	score += privScore * e.weights.Privilege

	// Asset value component (0-100, normalized from 1-5)
	assetScore := float64(ctx.AssetCriticality) * 20
	if assetScore > 100 {
		assetScore = 100
	}
	score += assetScore * e.weights.AssetValue

	// KEV bonus (binary: 0 or 100)
	kevScore := 0.0
	if ctx.IsKEV {
		kevScore = 100
	}
	score += kevScore * e.weights.KEVBonus

	// Toxic combination multiplier
	toxicScore := math.Min(float64(ctx.ToxicCombos)*33, 100)
	score += toxicScore * e.weights.ToxicCombo

	return math.Round(math.Min(score, 100)*10) / 10
}

// mapSeverityToScore converts OCSF severity_id to a 0-100 score.
func mapSeverityToScore(severityID int32) float64 {
	switch severityID {
	case 0: // Unknown
		return 0
	case 1: // Informational
		return 10
	case 2: // Low
		return 30
	case 3: // Medium
		return 50
	case 4: // High
		return 75
	case 5: // Critical
		return 95
	case 6: // Fatal
		return 100
	default:
		return 0
	}
}
