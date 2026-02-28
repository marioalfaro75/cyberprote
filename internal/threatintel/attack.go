// Package threatintel provides threat intelligence data: MITRE ATT&CK catalog,
// CWE-to-ATT&CK mappings, and external OSINT clients (Shodan, NVD).
package threatintel

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed attack_data.yaml
var attackDataFS embed.FS

// attackDataFile is the embedded ATT&CK matrix YAML.
type attackDataFile struct {
	Version string        `yaml:"version"`
	Domain  string        `yaml:"domain"`
	Tactics []TacticEntry `yaml:"tactics"`
}

// TacticEntry is a tactic with its techniques from the YAML file.
type TacticEntry struct {
	UID        string           `yaml:"uid" json:"uid"`
	Name       string           `yaml:"name" json:"name"`
	Techniques []TechniqueEntry `yaml:"techniques" json:"techniques"`
}

// TechniqueEntry is a single ATT&CK technique.
type TechniqueEntry struct {
	UID  string `yaml:"uid" json:"uid"`
	Name string `yaml:"name" json:"name"`
}

// AttackMatrix holds the parsed ATT&CK matrix with indexes for fast lookup.
type AttackMatrix struct {
	Version        string
	Domain         string
	Tactics        []TacticEntry
	tacticIndex    map[string]*TacticEntry
	techniqueIndex map[string]*TechniqueEntry
}

// LoadAttackMatrix loads and indexes the embedded ATT&CK matrix YAML.
func LoadAttackMatrix() (*AttackMatrix, error) {
	data, err := attackDataFS.ReadFile("attack_data.yaml")
	if err != nil {
		return nil, fmt.Errorf("read attack_data.yaml: %w", err)
	}

	var raw attackDataFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse attack_data.yaml: %w", err)
	}

	m := &AttackMatrix{
		Version:        raw.Version,
		Domain:         raw.Domain,
		Tactics:        raw.Tactics,
		tacticIndex:    make(map[string]*TacticEntry),
		techniqueIndex: make(map[string]*TechniqueEntry),
	}

	for i := range m.Tactics {
		t := &m.Tactics[i]
		m.tacticIndex[t.UID] = t
		for j := range t.Techniques {
			tech := &t.Techniques[j]
			m.techniqueIndex[tech.UID] = tech
		}
	}

	return m, nil
}

// GetTactic returns a tactic by UID, or nil if not found.
func (m *AttackMatrix) GetTactic(uid string) *TacticEntry {
	return m.tacticIndex[uid]
}

// GetTechnique returns a technique by UID, or nil if not found.
func (m *AttackMatrix) GetTechnique(uid string) *TechniqueEntry {
	return m.techniqueIndex[uid]
}

// AllTactics returns all tactics in order.
func (m *AttackMatrix) AllTactics() []TacticEntry {
	return m.Tactics
}
