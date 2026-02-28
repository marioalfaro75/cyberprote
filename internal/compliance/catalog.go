// Package compliance provides framework catalog loading and compliance posture
// computation for NIST CSF, CIS Benchmarks, and other security frameworks.
package compliance

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalogs/*.yaml
var catalogFS embed.FS

// Framework represents a compliance framework (e.g., NIST CSF 2.0, CIS AWS 1.4).
type Framework struct {
	ID        string     `yaml:"id" json:"id"`
	Name      string     `yaml:"name" json:"name"`
	Version   string     `yaml:"version" json:"version"`
	Functions []Function `yaml:"functions" json:"functions"`
}

// Function is a top-level grouping in a framework (e.g., NIST "Protect").
type Function struct {
	ID         string     `yaml:"id" json:"id"`
	Name       string     `yaml:"name" json:"name"`
	Categories []Category `yaml:"categories" json:"categories"`
}

// Category is a mid-level grouping (e.g., NIST "PR.DS — Data Security").
type Category struct {
	ID       string    `yaml:"id" json:"id"`
	Name     string    `yaml:"name" json:"name"`
	Controls []Control `yaml:"controls" json:"controls"`
}

// Control is an individual control mapped to cloud provider control IDs.
type Control struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	AWSControls []string `yaml:"aws_controls,omitempty" json:"aws_controls,omitempty"`
	GCPControls []string `yaml:"gcp_controls,omitempty" json:"gcp_controls,omitempty"`
	AzureControls []string `yaml:"azure_controls,omitempty" json:"azure_controls,omitempty"`
}

// Catalog holds all loaded frameworks and indexes for fast lookup.
type Catalog struct {
	Frameworks []Framework
	// controlIndex maps a cloud control ID (e.g., "S3.4") to framework controls.
	controlIndex map[string][]ControlRef
}

// ControlRef is a reference to a specific control within a framework hierarchy.
type ControlRef struct {
	FrameworkID string
	FunctionID  string
	CategoryID  string
	ControlID   string
}

// LoadCatalog loads all embedded YAML framework catalogs.
func LoadCatalog() (*Catalog, error) {
	entries, err := catalogFS.ReadDir("catalogs")
	if err != nil {
		return nil, fmt.Errorf("read catalogs dir: %w", err)
	}

	c := &Catalog{
		controlIndex: make(map[string][]ControlRef),
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := catalogFS.ReadFile("catalogs/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var fw Framework
		if err := yaml.Unmarshal(data, &fw); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		c.Frameworks = append(c.Frameworks, fw)
		c.indexFramework(&fw)
	}

	return c, nil
}

// indexFramework builds the control index for a single framework.
func (c *Catalog) indexFramework(fw *Framework) {
	for _, fn := range fw.Functions {
		for _, cat := range fn.Categories {
			for _, ctrl := range cat.Controls {
				ref := ControlRef{
					FrameworkID: fw.ID,
					FunctionID:  fn.ID,
					CategoryID:  cat.ID,
					ControlID:   ctrl.ID,
				}
				for _, awsCtrl := range ctrl.AWSControls {
					c.controlIndex[strings.ToUpper(awsCtrl)] = append(c.controlIndex[strings.ToUpper(awsCtrl)], ref)
				}
				for _, gcpCtrl := range ctrl.GCPControls {
					c.controlIndex[strings.ToUpper(gcpCtrl)] = append(c.controlIndex[strings.ToUpper(gcpCtrl)], ref)
				}
				for _, azCtrl := range ctrl.AzureControls {
					c.controlIndex[strings.ToUpper(azCtrl)] = append(c.controlIndex[strings.ToUpper(azCtrl)], ref)
				}
			}
		}
	}
}

// GetFramework returns a framework by ID, or nil if not found.
func (c *Catalog) GetFramework(id string) *Framework {
	for i := range c.Frameworks {
		if c.Frameworks[i].ID == id {
			return &c.Frameworks[i]
		}
	}
	return nil
}

// LookupControl returns framework control references for a cloud control ID.
func (c *Catalog) LookupControl(cloudControlID string) []ControlRef {
	return c.controlIndex[strings.ToUpper(cloudControlID)]
}
